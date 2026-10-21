#pragma once

// Transport-agnostic HTTP/2 server protocol engine built on nghttp2.
//
// The engine owns an nghttp2 server session and knows nothing about sockets or
// TLS: bytes go in through consume(), bytes come out through take_output(), and
// the caller decides when to write them. This makes it usable from a blocking
// loop, an event loop or a TLS listener without changes.
//
//   trie::server<api> router;
//   trie::http::h2_connection<trie::server<api>> connection{router};
//   while (...) {
//     auto out = connection.take_output();
//     write(fd, out.data(), out.size());
//     if (connection.finished()) break;
//     auto n = read(fd, buffer, sizeof(buffer));
//     if (n <= 0) break;
//     if (!connection.consume({buffer, static_cast<std::size_t>(n)})) break;
//   }
//
// The router reference must outlive the connection. The connection is
// single-threaded: it must not be used from more than one thread at a time.
// router.prepare() is not required before use (the first dispatch builds the
// middleware chain, which the single-threaded engine can safely do lazily).
//
// Not implemented by design: server push, trailers, h2c upgrade, prioritization
// trees and HTTP/1.1 fallback. All failures are reported through error() and
// consume(); no exceptions or RTTI are used.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "trie/http.hh"
#include "trie/http/serializer.hh"

namespace trie::http {

template <class Router>
class h2_connection {
public:
  explicit h2_connection(Router& router, std::size_t max_request_body = 1024 * 1024)
      : router_{router}, max_request_body_{max_request_body} {
    init_session();
  }

  ~h2_connection() {
    if (session_ != nullptr) nghttp2_session_del(session_);
  }

  h2_connection(h2_connection const&) = delete;
  h2_connection& operator=(h2_connection const&) = delete;
  h2_connection(h2_connection&&) = delete;
  h2_connection& operator=(h2_connection&&) = delete;

  // Feeds inbound bytes into the session. Returns false on a fatal protocol or
  // session error; the reason is then available through error(). The caller
  // must still drain take_output() to send any pending frames (e.g. a
  // protocol-error GOAWAY).
  bool consume(std::string_view bytes) {
    if (fatal_ || session_ == nullptr) return false;
    if (bytes.empty()) return true;
    nghttp2_ssize const processed =
        nghttp2_session_mem_recv2(session_, reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    if (processed < 0) {
      fail(std::string{"nghttp2_session_mem_recv2: "} + nghttp2_strerror(static_cast<int>(processed)));
      return false;
    }
    if (static_cast<std::size_t>(processed) != bytes.size()) {
      fail("nghttp2_session_mem_recv2 did not consume all input");
      return false;
    }
    return true;
  }

  // Returns all currently pending outbound bytes. Can be called repeatedly;
  // an empty result means nothing is queued right now.
  std::string take_output() {
    std::string out;
    if (session_ == nullptr) return out;
    for (;;) {
      const uint8_t* data = nullptr;
      nghttp2_ssize const produced = nghttp2_session_mem_send2(session_, &data);
      if (produced < 0) {
        fail(std::string{"nghttp2_session_mem_send2: "} + nghttp2_strerror(static_cast<int>(produced)));
        break;
      }
      if (produced == 0) break;
      out.append(reinterpret_cast<const char*>(data), static_cast<std::size_t>(produced));
    }
    return out;
  }

  // True once the session is done: a fatal error happened, or a graceful
  // shutdown() has been submitted and flushed (nghttp2 no longer wants to read
  // or write).
  bool finished() const {
    if (fatal_) return true;
    if (session_ == nullptr) return true;
    return nghttp2_session_want_read(session_) == 0 && nghttp2_session_want_write(session_) == 0;
  }

  // Submits a GOAWAY frame for the last processed stream. Its bytes are handed
  // out by take_output(); call take_output() until finished() reports true.
  void shutdown() {
    if (fatal_ || session_ == nullptr || shutdown_submitted_) return;
    shutdown_submitted_ = true;
    int const rc = nghttp2_submit_goaway(session_, NGHTTP2_FLAG_NONE, nghttp2_session_get_last_proc_stream_id(session_),
                                         NGHTTP2_NO_ERROR, nullptr, 0);
    if (rc != 0) fail(std::string{"nghttp2_submit_goaway: "} + nghttp2_strerror(rc));
  }

  std::string const& error() const { return error_; }
  std::size_t requests_handled() const { return requests_handled_; }

private:
  struct stream_state {
    int32_t stream_id = 0;
    std::string method{};
    std::string target{};
    std::vector<std::pair<std::string, std::string>> headers{};
    std::string body{};
    bool body_too_large = false;
    bool responded = false;
    std::string response_body{};
    std::size_t response_offset = 0;
  };

  // Owns the name/value buffers and the nghttp2_nv array pointing into them.
  // nghttp2_submit_response2 copies the values, so the block only has to live
  // across the submit call.
  struct header_block {
    std::vector<std::string> names{};
    std::vector<std::string> values{};
    std::vector<nghttp2_nv> pairs{};

    void add(std::string name, std::string value) {
      names.push_back(std::move(name));
      values.push_back(std::move(value));
    }

    nghttp2_nv const* build() {
      pairs.clear();
      pairs.reserve(names.size());
      for (std::size_t i = 0; i < names.size(); ++i) {
        nghttp2_nv pair{};
        pair.name = reinterpret_cast<uint8_t*>(names[i].data());
        pair.namelen = names[i].size();
        pair.value = reinterpret_cast<uint8_t*>(values[i].data());
        pair.valuelen = values[i].size();
        pair.flags = NGHTTP2_NV_FLAG_NONE;
        pairs.push_back(pair);
      }
      return pairs.data();
    }

    std::size_t size() const { return pairs.size(); }
  };

  void init_session() {
    nghttp2_session_callbacks* callbacks = nullptr;
    if (nghttp2_session_callbacks_new(&callbacks) != 0) {
      fail("nghttp2_session_callbacks_new failed");
      return;
    }
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &h2_connection::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, &h2_connection::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &h2_connection::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &h2_connection::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &h2_connection::on_stream_close);

    int const rc = nghttp2_session_server_new(&session_, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0) {
      session_ = nullptr;
      fail(std::string{"nghttp2_session_server_new: "} + nghttp2_strerror(rc));
      return;
    }

    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_ENABLE_PUSH, 0}};
    int const settings_rc = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings, 1);
    if (settings_rc != 0) {
      fail(std::string{"nghttp2_submit_settings: "} + nghttp2_strerror(settings_rc));
    }
  }

  void fail(std::string message) {
    fatal_ = true;
    if (error_.empty()) error_ = std::move(message);
  }

  static h2_connection* self(void* user_data) { return static_cast<h2_connection*>(user_data); }

  stream_state* find_stream(int32_t stream_id) {
    auto it = streams_.find(stream_id);
    return it == streams_.end() ? nullptr : &it->second;
  }

  // ---- nghttp2 callbacks -------------------------------------------------

  static int on_begin_headers(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* connection = self(user_data);
    // Only request HEADERS open a new stream. Trailer HEADERS blocks are
    // ignored (no trailer support); their header fields are skipped in
    // on_header.
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    stream_state& state = connection->streams_[frame->hd.stream_id];
    state.stream_id = frame->hd.stream_id;
    return 0;
  }

  static int on_header(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
                       const uint8_t* value, size_t valuelen, uint8_t, void* user_data) {
    auto* connection = self(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    stream_state* state = connection->find_stream(frame->hd.stream_id);
    if (state == nullptr) return 0;

    std::string_view const header_name{reinterpret_cast<const char*>(name), namelen};
    std::string_view const header_value{reinterpret_cast<const char*>(value), valuelen};
    if (!header_name.empty() && header_name.front() == ':') {
      // :scheme, :authority and unknown pseudo-header fields are validated by
      // nghttp2's HTTP messaging layer; the engine only needs the routing
      // inputs.
      if (header_name == ":method") {
        state->method.assign(header_value.data(), header_value.size());
      } else if (header_name == ":path") {
        state->target.assign(header_value.data(), header_value.size());
      }
      return 0;
    }
    state->headers.emplace_back(std::string{header_name}, std::string{header_value});
    return 0;
  }

  static int on_data_chunk_recv(nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t* data, size_t len,
                                void* user_data) {
    auto* connection = self(user_data);
    stream_state* state = connection->find_stream(stream_id);
    if (state == nullptr || state->body_too_large) return 0;
    // Keep at most max_request_body bytes. Once the limit is crossed the
    // remaining DATA is drained (nghttp2 keeps sending WINDOW_UPDATEs) so the
    // request can complete and receive a proper 413 response.
    if (len > connection->max_request_body_ - state->body.size()) {
      state->body_too_large = true;
      state->body.clear();
      return 0;
    }
    state->body.append(reinterpret_cast<const char*>(data), len);
    return 0;
  }

  static int on_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* connection = self(user_data);
    bool end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;

    if (frame->hd.type == NGHTTP2_HEADERS) {
      if (end_stream) connection->finish_stream(frame->hd.stream_id);
    } else if (frame->hd.type == NGHTTP2_DATA) {
      if (end_stream) connection->finish_stream(frame->hd.stream_id);
    }
    // SETTINGS/PING/WINDOW_UPDATE/RST_STREAM/GOAWAY are handled by nghttp2.
    return 0;
  }

  static int on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t, void* user_data) {
    auto* connection = self(user_data);
    connection->streams_.erase(stream_id);
    return 0;
  }

  static nghttp2_ssize read_response_body(nghttp2_session*, int32_t, uint8_t* buffer, size_t length,
                                          uint32_t* data_flags, nghttp2_data_source* source, void*) {
    auto* state = static_cast<stream_state*>(source->ptr);
    if (state == nullptr) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      return 0;
    }
    std::size_t const remaining = state->response_body.size() - state->response_offset;
    if (remaining == 0) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      return 0;
    }
    std::size_t const amount = std::min(length, remaining);
    std::memcpy(buffer, state->response_body.data() + state->response_offset, amount);
    state->response_offset += amount;
    if (state->response_offset >= state->response_body.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(amount);
  }

  // ---- request/response plumbing ----------------------------------------

  static std::string lowercase(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) out.push_back(to_lower(c));
    return out;
  }

  static bool forbidden_response_header(std::string_view name) {
    // Connection-specific fields are forbidden in HTTP/2; Content-Length is
    // generated by the engine (as the HTTP/1 serializer does).
    return iequals(name, "connection") || iequals(name, "keep-alive") ||
           iequals(name, "proxy-connection") || iequals(name, "transfer-encoding") ||
           iequals(name, "upgrade") || iequals(name, "content-length");
  }

  static response error_response(status code, std::string body) {
    response result{};
    result.status_code = static_cast<int>(code);
    result.body = std::move(body);
    return result;
  }

  // Builds the router response for a completed request. Validation failures
  // map directly onto the HTTP status they describe.
  response build_response(stream_state const& state) {
    if (state.method.empty()) return error_response(status::bad_request, "missing :method");
    auto const method = method_from_name(state.method);
    if (!method.has_value()) return error_response(status::not_implemented, "unsupported method");
    if (state.target.empty()) return error_response(status::bad_request, "missing :path");
    if (state.body_too_large) return error_response(status::payload_too_large, "request body too large");

    std::vector<header_view> headers;
    headers.reserve(state.headers.size());
    for (auto const& header : state.headers) headers.push_back(header_view{header.first, header.second});
    request_view const view = request_view::from_target(*method, state.target, headers, state.body);
    return router_.dispatch(view);
  }

  void finish_stream(int32_t stream_id) {
    stream_state* state = find_stream(stream_id);
    if (state == nullptr || state->responded) return;
    state->responded = true;
    response result = build_response(*state);
    submit_response(*state, std::move(result));
  }

  void submit_response(stream_state& state, response&& result) {
    int code = result.status_code;
    if (code < 100 || code > 999) code = static_cast<int>(status::ok);
    bool const bodyless_status = code == static_cast<int>(status::no_content) || code == 304;
    bool const head_only = state.method == "HEAD";

    header_block block;
    block.add(":status", std::to_string(code));
    for (auto const& header : result.headers) {
      std::string name = lowercase(header.first);
      if (!valid_header_name(name) || !valid_header_value(header.second)) continue;
      if (forbidden_response_header(name)) continue;
      block.add(std::move(name), header.second);
    }
    if (!bodyless_status) block.add("content-length", std::to_string(result.body.size()));

    bool const send_body = !bodyless_status && !head_only && !result.body.empty();
    state.response_body.clear();
    state.response_offset = 0;
    if (send_body) state.response_body = std::move(result.body);

    nghttp2_nv const* pairs = block.build();
    int rc = 0;
    if (send_body) {
      nghttp2_data_provider2 provider{};
      provider.source.ptr = &state;
      provider.read_callback = &h2_connection::read_response_body;
      rc = nghttp2_submit_response2(session_, state.stream_id, pairs, block.size(), &provider);
    } else {
      rc = nghttp2_submit_response2(session_, state.stream_id, pairs, block.size(), nullptr);
    }
    if (rc != 0) {
      fail(std::string{"nghttp2_submit_response2: "} + nghttp2_strerror(rc));
      return;
    }
    ++requests_handled_;
  }

  Router& router_;
  std::size_t max_request_body_ = 0;
  nghttp2_session* session_ = nullptr;
  std::unordered_map<int32_t, stream_state> streams_{};
  std::string error_{};
  std::size_t requests_handled_ = 0;
  bool fatal_ = false;
  bool shutdown_submitted_ = false;
};

} // namespace trie::http
