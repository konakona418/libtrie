#pragma once

// Minimal nghttp2 HTTP/2 client used by tests/h2_connection_test.cc.
//
// The server engine under test is transport-agnostic, so the tests drive it
// over a socketpair: main() talks HTTP/2 through this client, a std::thread
// runs the server loop (recv -> h2_connection::consume -> take_output -> send).
//
// This helper is deliberately small: it submits requests on one connection,
// records per-stream responses, and exposes blocking wait()/request_and_wait()
// helpers that pump the session until the response completes. It never blocks
// on network reads without a socket receive timeout, so a stalled server turns
// into a test failure instead of a hung test process.

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nghttp2/nghttp2.h>

namespace h2test {

inline bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    char ca = a[i] >= 'A' && a[i] <= 'Z' ? static_cast<char>(a[i] - 'A' + 'a') : a[i];
    char cb = b[i] >= 'A' && b[i] <= 'Z' ? static_cast<char>(b[i] - 'A' + 'a') : b[i];
    if (ca != cb) return false;
  }
  return true;
}

// Writes every byte, retrying on EINTR/short writes. Returns false on error.
inline bool write_all(int fd, std::string_view data) {
  while (!data.empty()) {
    auto const written = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
    if (written < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (written == 0) return false;
    data.remove_prefix(static_cast<std::size_t>(written));
  }
  return true;
}

struct response {
  int status = 0;
  std::vector<std::pair<std::string, std::string>> headers{};
  std::string body{};
  std::size_t data_chunks = 0;
  bool headers_complete = false;
  bool end_stream = false;
  bool closed = false;

  std::string_view header(std::string_view name) const {
    for (auto const& header : headers)
      if (iequals(header.first, name)) return header.second;
    return {};
  }
};

class client {
public:
  explicit client(int fd) : fd_{fd} {
    if (nghttp2_session_callbacks_new(&callbacks_) != 0) {
      error_ = "nghttp2_session_callbacks_new failed";
      return;
    }
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks_, &client::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks_, &client::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks_, &client::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks_, &client::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks_, &client::on_stream_close);

    int const rc = nghttp2_session_client_new(&session_, callbacks_, this);
    nghttp2_session_callbacks_del(callbacks_);
    callbacks_ = nullptr;
    if (rc != 0) {
      session_ = nullptr;
      error_ = std::string{"nghttp2_session_client_new: "} + nghttp2_strerror(rc);
      return;
    }

    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
                                         {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    int const settings_rc = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings, 2);
    if (settings_rc != 0) error_ = std::string{"nghttp2_submit_settings: "} + nghttp2_strerror(settings_rc);
  }

  ~client() {
    if (session_ != nullptr) nghttp2_session_del(session_);
  }

  client(client const&) = delete;
  client& operator=(client const&) = delete;
  client(client&&) = delete;
  client& operator=(client&&) = delete;

  bool valid() const { return session_ != nullptr; }
  std::string const& error() const { return error_; }
  bool failed() const { return failed_; }
  bool peer_closed() const { return peer_closed_; }

  // Submits a request without flushing. Returns the stream id, or -1 on error.
  int32_t submit(std::string_view method, std::string_view path, std::string_view body = {},
                 std::vector<std::pair<std::string, std::string>> extra_headers = {}) {
    if (session_ == nullptr) return -1;

    std::vector<std::string> names;
    std::vector<std::string> values;
    auto add = [&names, &values](std::string name, std::string value) {
      names.push_back(std::move(name));
      values.push_back(std::move(value));
    };
    add(":method", std::string{method});
    add(":scheme", "http");
    add(":authority", "libtrie.test");
    add(":path", std::string{path});
    if (!body.empty()) add("content-length", std::to_string(body.size()));
    for (auto& header : extra_headers) add(std::move(header.first), std::move(header.second));

    std::vector<nghttp2_nv> pairs;
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

    std::unique_ptr<request_body> holder;
    nghttp2_data_provider2 provider{};
    nghttp2_data_provider2 const* provider_ptr = nullptr;
    if (!body.empty()) {
      holder = std::make_unique<request_body>();
      holder->data.assign(body.data(), body.size());
      provider.source.ptr = holder.get();
      provider.read_callback = &client::read_request_body;
      provider_ptr = &provider;
    }

    int32_t const stream_id = nghttp2_submit_request2(session_, nullptr, pairs.data(), pairs.size(), provider_ptr, nullptr);
    if (stream_id < 0) {
      error_ = std::string{"nghttp2_submit_request2: "} + nghttp2_strerror(stream_id);
      return -1;
    }
    if (holder != nullptr) request_bodies_.push_back(std::move(holder));
    return stream_id;
  }

  // Serializes pending frames and writes them to the socket.
  bool flush() {
    if (session_ == nullptr) return false;
    for (;;) {
      const uint8_t* data = nullptr;
      nghttp2_ssize const produced = nghttp2_session_mem_send2(session_, &data);
      if (produced < 0) {
        error_ = std::string{"nghttp2_session_mem_send2: "} + nghttp2_strerror(static_cast<int>(produced));
        failed_ = true;
        return false;
      }
      if (produced == 0) break;
      if (!write_all(fd_, std::string_view{reinterpret_cast<const char*>(data), static_cast<std::size_t>(produced)})) {
        error_ = "send failed";
        failed_ = true;
        return false;
      }
    }
    return true;
  }

  // Reads one chunk from the socket and feeds it to the client session.
  // Returns false at EOF, on error, or after a fatal protocol error.
  bool read_more() {
    if (session_ == nullptr) return false;
    unsigned char buffer[16384];
    nghttp2_ssize received = 0;
    for (;;) {
      auto const rc = ::recv(fd_, buffer, sizeof(buffer), 0);
      if (rc < 0) {
        if (errno == EINTR) continue;
        error_ = errno == EAGAIN || errno == EWOULDBLOCK ? "recv timed out" : "recv failed";
        failed_ = true;
        return false;
      }
      if (rc == 0) {
        peer_closed_ = true;
        return false;
      }
      received = static_cast<nghttp2_ssize>(rc);
      break;
    }
    nghttp2_ssize const processed = nghttp2_session_mem_recv2(session_, buffer, static_cast<std::size_t>(received));
    if (processed < 0) {
      error_ = std::string{"nghttp2_session_mem_recv2: "} + nghttp2_strerror(static_cast<int>(processed));
      failed_ = true;
      return false;
    }
    return true;
  }

  bool complete(int32_t stream_id) const {
    auto it = responses_.find(stream_id);
    if (it == responses_.end()) return false;
    return it->second.headers_complete && (it->second.end_stream || it->second.closed);
  }

  // Pumps the session until stream `stream_id` has a complete response.
  bool wait(int32_t stream_id) {
    for (;;) {
      if (!flush()) return false;
      if (complete(stream_id)) return true;
      if (!read_more()) return false;
    }
  }

  // Convenience: submit, flush, and wait for the response.
  int32_t request_and_wait(std::string_view method, std::string_view path, std::string_view body = {},
                           std::vector<std::pair<std::string, std::string>> extra_headers = {}) {
    int32_t const stream_id = submit(method, path, body, std::move(extra_headers));
    if (stream_id < 0) return -1;
    if (!wait(stream_id)) return -1;
    return stream_id;
  }

  // Never throws (the whole project is built with -fno-exceptions): a missing
  // stream yields an empty response so a failed check reports instead of
  // aborting the test process.
  response const& get(int32_t stream_id) const {
    auto it = responses_.find(stream_id);
    if (it != responses_.end()) return it->second;
    static response const empty{};
    return empty;
  }

  bool has_response(int32_t stream_id) const { return responses_.find(stream_id) != responses_.end(); }

private:
  struct request_body {
    std::string data{};
    std::size_t offset = 0;
  };

  static client* self(void* user_data) { return static_cast<client*>(user_data); }

  static int on_begin_headers(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_RESPONSE) return 0;
    self(user_data)->responses_[frame->hd.stream_id] = response{};
    return 0;
  }

  static int on_header(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
                       const uint8_t* value, size_t valuelen, uint8_t, void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_RESPONSE) return 0;
    auto* connection = self(user_data);
    auto it = connection->responses_.find(frame->hd.stream_id);
    if (it == connection->responses_.end()) return 0;
    std::string_view const header_name{reinterpret_cast<const char*>(name), namelen};
    std::string_view const header_value{reinterpret_cast<const char*>(value), valuelen};
    if (header_name == ":status") {
      int status = 0;
      auto const [ptr, error] = std::from_chars(header_value.data(), header_value.data() + header_value.size(), status);
      if (error == std::errc{} && ptr == header_value.data() + header_value.size()) it->second.status = status;
      return 0;
    }
    if (!header_name.empty() && header_name.front() == ':') return 0;
    it->second.headers.emplace_back(std::string{header_name}, std::string{header_value});
    return 0;
  }

  static int on_data_chunk_recv(nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t* data, size_t len,
                                void* user_data) {
    auto* connection = self(user_data);
    auto it = connection->responses_.find(stream_id);
    if (it == connection->responses_.end()) return 0;
    it->second.body.append(reinterpret_cast<const char*>(data), len);
    ++it->second.data_chunks;
    return 0;
  }

  static int on_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* connection = self(user_data);
    auto it = connection->responses_.find(frame->hd.stream_id);
    if (it == connection->responses_.end()) return 0;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      it->second.headers_complete = true;
    }
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
      it->second.end_stream = true;
    }
    return 0;
  }

  static int on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t, void* user_data) {
    auto* connection = self(user_data);
    auto it = connection->responses_.find(stream_id);
    if (it != connection->responses_.end()) it->second.closed = true;
    return 0;
  }

  static nghttp2_ssize read_request_body(nghttp2_session*, int32_t, uint8_t* buffer, size_t length,
                                         uint32_t* data_flags, nghttp2_data_source* source, void*) {
    auto* body = static_cast<request_body*>(source->ptr);
    if (body == nullptr) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      return 0;
    }
    std::size_t const remaining = body->data.size() - body->offset;
    if (remaining == 0) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      return 0;
    }
    std::size_t const amount = std::min(length, remaining);
    std::memcpy(buffer, body->data.data() + body->offset, amount);
    body->offset += amount;
    if (body->offset >= body->data.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(amount);
  }

  int fd_ = -1;
  nghttp2_session* session_ = nullptr;
  nghttp2_session_callbacks* callbacks_ = nullptr;
  std::unordered_map<int32_t, response> responses_{};
  std::vector<std::unique_ptr<request_body>> request_bodies_{};
  std::string error_{};
  bool failed_ = false;
  bool peer_closed_ = false;
};

} // namespace h2test
