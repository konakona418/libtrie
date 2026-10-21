// End-to-end HTTPS + HTTP/2 test: tls_listener with ALPN "h2" driven by a real
// nghttp2 client over OpenSSL.

#define TRIE_TLS_LISTENER_WITH_HTTP2 1

#include "trie/trie.hh"
#include "trie/http/tls_listener.hh"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "harness.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

using namespace std::chrono_literals;

namespace {

std::string const& test_data_dir() {
  static std::string directory = [] {
    std::vector<std::string> candidates;
#if defined(TRIE_TEST_DATA_DIR)
    candidates.emplace_back(TRIE_TEST_DATA_DIR);
#endif
    std::string source{__FILE__};
    auto slash = source.find_last_of('/');
    std::string source_dir = slash == std::string::npos ? std::string{"."} : source.substr(0, slash);
    candidates.push_back(source_dir + "/data");
    candidates.emplace_back("tests/data");
    candidates.emplace_back("../tests/data");
    candidates.emplace_back("../../tests/data");
    for (auto const& candidate : candidates) {
      std::ifstream stream{(candidate + "/server.crt").c_str()};
      if (stream.good()) return candidate;
    }
    return std::string{"tests/data"};
  }();
  return directory;
}

struct api {
  [[=trie::get("/hello")]] std::string hello() { return "hello over h2"; }
  [[=trie::get("/json")]] trie::json::value json() {
    trie::json::value value;
    value["ok"] = true;
    value["transport"] = "h2";
    return value;
  }
  [[=trie::post("/echo")]] std::string echo([[=trie::body]] std::string_view body) { return std::string(body); }
};

struct h2_response {
  int status = 0;
  std::string body{};
  std::vector<std::pair<std::string, std::string>> headers{};
  bool done = false;
  bool reset = false;

  std::string_view header(std::string_view name) const {
    for (auto const& [key, value] : headers) {
      if (trie::http::iequals(key, name)) return value;
    }
    return {};
  }
};

class tls_h2_client {
public:
  tls_h2_client() = default;
  ~tls_h2_client() {
    if (session_ != nullptr) nghttp2_session_del(session_);
    if (ssl_ != nullptr) {
      (void)SSL_shutdown(ssl_);
      SSL_free(ssl_);
    }
    if (ctx_ != nullptr) SSL_CTX_free(ctx_);
    if (fd_ >= 0) ::close(fd_);
  }

  tls_h2_client(tls_h2_client const&) = delete;
  tls_h2_client& operator=(tls_h2_client const&) = delete;

  bool connect(std::uint16_t port, std::vector<std::string> const& alpn) {
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (ctx_ == nullptr) return false;
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    (void)SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);

    std::string wire;
    for (auto const& protocol : alpn) {
      if (protocol.empty() || protocol.size() > 255) continue;
      wire.push_back(static_cast<char>(protocol.size()));
      wire += protocol;
    }
    if (!wire.empty())
      (void)SSL_CTX_set_alpn_protos(ctx_, reinterpret_cast<unsigned char const*>(wire.data()),
                                    static_cast<unsigned int>(wire.size()));

    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) return false;
    timeval timeout{};
    timeout.tv_sec = 3;
    (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) return false;

    ssl_ = SSL_new(ctx_);
    if (ssl_ == nullptr) return false;
    (void)SSL_set_fd(ssl_, fd_);
    (void)SSL_set_tlsext_host_name(ssl_, "localhost");
    if (SSL_connect(ssl_) != 1) return false;

    unsigned char const* selected = nullptr;
    unsigned int selected_length = 0;
    SSL_get0_alpn_selected(ssl_, &selected, &selected_length);
    selected_alpn_.assign(reinterpret_cast<char const*>(selected), selected_length);

    if (!setup_h2()) return false;
    return true;
  }

  std::string const& selected_alpn() const { return selected_alpn_; }
  std::string const& error() const { return error_; }

  h2_response const& request(std::string_view method, std::string_view path, std::string_view body = {}) {
    h2_response& response = responses_[next_slot_++];
    response = h2_response{};
    if (session_ == nullptr) {
      response.done = true;
      response.status = -1;
      return response;
    }

    std::vector<std::string> names = {":method", ":scheme", ":authority", ":path"};
    std::vector<std::string> values = {std::string{method}, "https", "localhost", std::string{path}};
    if (!body.empty()) {
      names.push_back("content-length");
      values.push_back(std::to_string(body.size()));
    }
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

    nghttp2_data_provider2 provider{};
    nghttp2_data_provider2 const* provider_ptr = nullptr;
    if (!body.empty()) {
      auto holder = std::make_unique<request_body>();
      holder->data.assign(body.data(), body.size());
      provider.source.ptr = holder.get();
      provider.read_callback = &tls_h2_client::read_request_body;
      provider_ptr = &provider;
      request_bodies_.push_back(std::move(holder));
    }

    int32_t const stream_id =
        nghttp2_submit_request2(session_, nullptr, pairs.data(), pairs.size(), provider_ptr, &response);
    if (stream_id < 0) {
      response.done = true;
      response.status = -1;
      error_ = std::string{"nghttp2_submit_request2: "} + nghttp2_strerror(stream_id);
      return response;
    }
    responses_by_stream_[stream_id] = &response;
    if (!flush()) return response;

    while (!response.done && !failed_) {
      if (!pump()) break;
    }
    return response;
  }

  bool pump() {
    unsigned char buffer[16384];
    auto const received = SSL_read(ssl_, buffer, sizeof(buffer));
    if (received <= 0) {
      int const ssl_error = SSL_get_error(ssl_, static_cast<int>(received));
      if (ssl_error == SSL_ERROR_ZERO_RETURN) return false;
      failed_ = true;
      error_ = "SSL_read failed";
      return false;
    }
    nghttp2_ssize const consumed = nghttp2_session_mem_recv2(session_, buffer, static_cast<std::size_t>(received));
    if (consumed < 0) {
      failed_ = true;
      error_ = std::string{"nghttp2_session_mem_recv2: "} + nghttp2_strerror(static_cast<int>(consumed));
      return false;
    }
    return flush();
  }

  bool flush() {
    for (;;) {
      const uint8_t* data = nullptr;
      nghttp2_ssize const produced = nghttp2_session_mem_send2(session_, &data);
      if (produced < 0) {
        failed_ = true;
        error_ = std::string{"nghttp2_session_mem_send2: "} + nghttp2_strerror(static_cast<int>(produced));
        return false;
      }
      if (produced == 0) return true;
      std::string_view outgoing{reinterpret_cast<char const*>(data), static_cast<std::size_t>(produced)};
      while (!outgoing.empty()) {
        int const written = SSL_write(ssl_, outgoing.data(), static_cast<int>(outgoing.size()));
        if (written <= 0) {
          failed_ = true;
          error_ = "SSL_write failed";
          return false;
        }
        outgoing.remove_prefix(static_cast<std::size_t>(written));
      }
    }
  }

private:
  struct request_body {
    std::string data;
    std::size_t offset = 0;
  };

  bool setup_h2() {
    nghttp2_session_callbacks* callbacks = nullptr;
    if (nghttp2_session_callbacks_new(&callbacks) != 0) {
      error_ = "nghttp2_session_callbacks_new failed";
      return false;
    }
    nghttp2_session_callbacks_set_on_header_callback(callbacks, &tls_h2_client::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &tls_h2_client::on_data_chunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &tls_h2_client::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &tls_h2_client::on_stream_close);
    int const rc = nghttp2_session_client_new(&session_, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0) {
      error_ = std::string{"nghttp2_session_client_new: "} + nghttp2_strerror(rc);
      session_ = nullptr;
      return false;
    }
    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_ENABLE_PUSH, 0}};
    (void)nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings, 1);
    return flush();
  }

  static h2_response* response_for(void* user_data, int32_t stream_id) {
    auto* self = static_cast<tls_h2_client*>(user_data);
    if (self == nullptr) return nullptr;
    auto entry = self->responses_by_stream_.find(stream_id);
    return entry == self->responses_by_stream_.end() ? nullptr : entry->second;
  }

  static int on_header(nghttp2_session* /*session*/, nghttp2_frame const* frame, uint8_t const* name,
                       std::size_t namelen, uint8_t const* value, std::size_t valuelen, uint8_t /*flags*/,
                       void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_RESPONSE) return 0;
    h2_response* response = response_for(user_data, frame->hd.stream_id);
    if (response == nullptr) return 0;
    std::string header_name{reinterpret_cast<char const*>(name), namelen};
    std::string header_value{reinterpret_cast<char const*>(value), valuelen};
    if (header_name == ":status") response->status = std::atoi(header_value.c_str());
    else response->headers.emplace_back(std::move(header_name), std::move(header_value));
    return 0;
  }

  static int on_data_chunk(nghttp2_session* /*session*/, uint8_t /*flags*/, int32_t stream_id,
                           uint8_t const* data, std::size_t len, void* user_data) {
    h2_response* response = response_for(user_data, stream_id);
    if (response != nullptr) response->body.append(reinterpret_cast<char const*>(data), len);
    return 0;
  }

  static int on_frame_recv(nghttp2_session* /*session*/, nghttp2_frame const* frame, void* user_data) {
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
      h2_response* response = response_for(user_data, frame->hd.stream_id);
      if (response != nullptr) response->done = true;
    }
    if (frame->hd.type == NGHTTP2_RST_STREAM) {
      h2_response* response = response_for(user_data, frame->hd.stream_id);
      if (response != nullptr) {
        response->reset = true;
        response->done = true;
      }
    }
    return 0;
  }

  static int on_stream_close(nghttp2_session* /*session*/, int32_t stream_id, uint32_t /*error_code*/,
                             void* user_data) {
    h2_response* response = response_for(user_data, stream_id);
    if (response != nullptr) response->done = true;
    return 0;
  }

  static nghttp2_ssize read_request_body(nghttp2_session* /*session*/, int32_t /*stream_id*/,
                                         uint8_t* buffer, std::size_t length, uint32_t* data_flags,
                                         nghttp2_data_source* source, void* /*user_data*/) {
    auto* body = static_cast<request_body*>(source->ptr);
    std::size_t const remaining = body->data.size() - body->offset;
    std::size_t const copied = std::min(length, remaining);
    if (copied > 0) std::memcpy(buffer, body->data.data() + body->offset, copied);
    body->offset += copied;
    if (body->offset == body->data.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(copied);
  }

  int fd_ = -1;
  SSL_CTX* ctx_ = nullptr;
  SSL* ssl_ = nullptr;
  nghttp2_session* session_ = nullptr;
  std::string selected_alpn_{};
  std::string error_{};
  bool failed_ = false;
  std::size_t next_slot_ = 0;
  std::map<std::size_t, h2_response> responses_{};
  std::map<int32_t, h2_response*> responses_by_stream_{};
  std::vector<std::unique_ptr<request_body>> request_bodies_{};
};

} // namespace

int main() {
  std::string const data_dir = test_data_dir();
  std::string const server_cert = data_dir + "/server.crt";
  std::string const server_key = data_dir + "/server.key";

  trie::server<api> router;
  trie::http::tls_serve_options options{};
  options.certificate_chain_file = server_cert;
  options.private_key_file = server_key;
  options.enable_http2 = true;
  options.alpn_protocols = {"h2", "http/1.1"};
  options.http.idle_timeout = 5000ms;
  options.http.drain_timeout = 1000ms;

  trie::http::tls_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0}, options};
  CHECK(server.valid());
  std::thread runner{[&server] { server.run(); }};

  {
    tls_h2_client client;
    CHECK(client.connect(server.port(), {"h2"}));
    CHECK_EQ(client.selected_alpn(), std::string{"h2"});

    auto hello = client.request("GET", "/hello");
    CHECK_EQ(hello.status, 200);
    CHECK_EQ(hello.body, std::string{"hello over h2"});
    // Plain string handlers do not set a default Content-Type in the HTTP/2
    // path (the HTTP/1 serializer does not add one either).
    CHECK(hello.header("content-type").empty());
    CHECK_EQ(hello.header("content-length"), std::string{"13"});

    auto json = client.request("GET", "/json");
    CHECK_EQ(json.status, 200);
    CHECK(json.body.find("\"transport\":\"h2\"") != std::string::npos);
    CHECK(json.body.find("\"ok\":true") != std::string::npos);
    CHECK_EQ(json.header("content-type"), std::string{"application/json"});

    auto echo = client.request("POST", "/echo", "payload");
    CHECK_EQ(echo.status, 200);
    CHECK_EQ(echo.body, std::string{"payload"});

    auto missing = client.request("GET", "/nope");
    CHECK_EQ(missing.status, 404);

    auto head = client.request("HEAD", "/hello");
    CHECK_EQ(head.status, 200);
    CHECK(head.body.empty());
    CHECK_EQ(head.header("content-length"), std::string{"13"});

    auto brew = client.request("BREW", "/hello");
    CHECK_EQ(brew.status, 501);

    // Concurrent streams: submit two requests before reading.
    auto first_id = client.request("GET", "/hello");
    auto second_id = client.request("GET", "/json");
    CHECK_EQ(first_id.status, 200);
    CHECK_EQ(second_id.status, 200);
  }
  {
    // ALPN fallback to HTTP/1.1 on the same listener.
    tls_h2_client client;
    CHECK(client.connect(server.port(), {"http/1.1"}));
    CHECK_EQ(client.selected_alpn(), std::string{"http/1.1"});
  }

  server.stop();
  runner.join();
  return tst::report("tls_http2_test");
}

#endif
