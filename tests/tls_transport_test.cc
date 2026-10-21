#include "trie/trie.hh"

#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <fstream>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "harness.hh"
#include "trie/http/tls_transport.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

namespace {

// tests/data holds the self-signed server certificate used by the TLS test
// server below. Tests run from the build tree, so look in a few plausible
// places, preferring an explicit -DTRIE_TEST_DATA_DIR=... if provided.
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

std::string_view request_target(std::string_view head) {
  auto line_end = head.find("\r\n");
  std::string_view line = head.substr(0, line_end);
  auto first = line.find(' ');
  if (first == std::string_view::npos) return {};
  auto second = line.find(' ', first + 1);
  return second == std::string_view::npos ? line.substr(first + 1)
                                          : line.substr(first + 1, second - first - 1);
}

std::size_t request_content_length(std::string_view head) {
  std::size_t position = head.find("\r\n");
  if (position == std::string_view::npos) return 0;
  position += 2;
  while (position < head.size()) {
    auto end = head.find("\r\n", position);
    if (end == std::string_view::npos) break;
    std::string_view line = head.substr(position, end - position);
    auto colon = line.find(':');
    if (colon != std::string_view::npos && trie::http::iequals(line.substr(0, colon), "content-length")) {
      std::string_view value = line.substr(colon + 1);
      while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
      std::size_t length = 0;
      (void)std::from_chars(value.data(), value.data() + value.size(), length);
      return length;
    }
    position = end + 2;
  }
  return 0;
}

// Minimal blocking TLS HTTP/1.1 server running in its own thread. Every
// connection serves one request and closes; /ping returns a Content-Length
// response, /created returns status 201, /eof returns a body delimited by
// connection close, and /abrupt does the same without sending close_notify.
class tls_test_server {
public:
  tls_test_server() = default;
  ~tls_test_server() { stop(); }

  tls_test_server(tls_test_server const&) = delete;
  tls_test_server& operator=(tls_test_server const&) = delete;

  bool start(std::string const& cert_file, std::string const& key_file, bool require_client_cert = false) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (ctx_ == nullptr) return false;
    if (SSL_CTX_use_certificate_chain_file(ctx_, cert_file.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
      return false;
    }
    require_client_cert_ = require_client_cert;
    if (require_client_cert_) {
      // This server exercises whether the client presents its certificate; the
      // test certificates are trusted implicitly.
      SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, accept_any_certificate);
    }

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) return false;
    int reuse = 1;
    (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
        ::listen(listen_fd_, 16) < 0) {
      ::close(listen_fd_);
      listen_fd_ = -1;
      return false;
    }
    socklen_t length = sizeof(address);
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&address), &length) < 0) return false;
    port_ = ntohs(address.sin_port);
    thread_ = std::thread{[this] { serve(); }};
    return true;
  }

  std::uint16_t port() const { return port_; }

  std::string last_sni() const {
    std::lock_guard lock{mutex_};
    return last_sni_;
  }

  bool peer_cert_seen() const {
    std::lock_guard lock{mutex_};
    return peer_cert_seen_;
  }

  void stop() {
    if (thread_.joinable()) {
      stop_.store(true);
      thread_.join();
    }
    if (listen_fd_ >= 0) {
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

private:
  static int accept_any_certificate(int /*preverify_ok*/, X509_STORE_CTX* /*store*/) { return 1; }

  void serve() {
    while (!stop_.load()) {
      pollfd descriptor{listen_fd_, POLLIN, 0};
      int ready = ::poll(&descriptor, 1, 50);
      if (ready < 0) {
        if (errno == EINTR) continue;
        break;
      }
      if (ready == 0) continue;
      int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
      if (fd < 0) continue;
      timeval timeout{2, 0};
      (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
      handle(fd);
      ::close(fd);
    }
  }

  void handle(int fd) {
    SSL* ssl = SSL_new(ctx_);
    if (ssl == nullptr) return;
    if (SSL_set_fd(ssl, fd) != 1 || SSL_accept(ssl) != 1) {
      SSL_free(ssl);
      return; // e.g. the client aborted the handshake after a verification failure
    }

    if (char const* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name); name != nullptr) {
      std::lock_guard lock{mutex_};
      last_sni_ = name;
    }

    if (require_client_cert_) {
      X509* peer = SSL_get1_peer_certificate(ssl);
      bool const present = peer != nullptr;
      if (peer != nullptr) X509_free(peer);
      std::lock_guard lock{mutex_};
      peer_cert_seen_ = present;
    }

    std::string head;
    std::array<char, 4096> chunk{};
    while (head.find("\r\n\r\n") == std::string::npos) {
      int received = SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size()));
      if (received <= 0) {
        SSL_free(ssl);
        return;
      }
      head.append(chunk.data(), static_cast<std::size_t>(received));
      if (head.size() > 64 * 1024) {
        SSL_free(ssl);
        return;
      }
    }

    std::size_t head_end = head.find("\r\n\r\n") + 4;
    std::size_t wanted = request_content_length(head);
    std::size_t body_have = head.size() - head_end;
    while (body_have < wanted) {
      int received = SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size()));
      if (received <= 0) break;
      body_have += static_cast<std::size_t>(received);
    }

    std::string response = make_response(request_target(head));
    bool const abrupt_close = request_target(head) == "/abrupt";
    std::string_view pending{response};
    while (!pending.empty()) {
      std::size_t amount = pending.size() < 4096 ? pending.size() : 4096;
      int written = SSL_write(ssl, pending.data(), static_cast<int>(amount));
      if (written <= 0) break;
      pending.remove_prefix(static_cast<std::size_t>(written));
    }
    if (!abrupt_close) (void)SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  static std::string make_response(std::string_view target) {
    if (target == "/eof") {
      return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\neof-body";
    }
    if (target == "/abrupt") {
      // Closed below without a close_notify alert.
      return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nabrupt-body";
    }
    if (target == "/created") {
      return "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n"
             "Connection: close\r\n\r\ncreated";
    }
    return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n"
           "Connection: close\r\n\r\npong";
  }

  SSL_CTX* ctx_ = nullptr;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0;
  std::atomic<bool> stop_{false};
  std::thread thread_{};
  bool require_client_cert_ = false;
  mutable std::mutex mutex_{};
  std::string last_sni_{};
  bool peer_cert_seen_ = false;
};

struct api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }
};

// The transport contract expected by trie::client.
template <class Transport>
concept transport_like = requires(Transport const& transport, trie::http::request request) {
  { transport.send(std::move(request)) } -> std::same_as<std::expected<trie::http::response, trie::client_error>>;
};

static_assert(transport_like<trie::http::tls_transport>);

trie::http::request get_request(std::string target) {
  trie::http::request request{};
  request.m = trie::method::get;
  request.target = std::move(target);
  return request;
}

} // namespace

int main() {
  std::string const data_dir = test_data_dir();
  std::string const cert_file = data_dir + "/server.crt";
  std::string const key_file = data_dir + "/server.key";

  tls_test_server server;
  if (!server.start(cert_file, key_file)) {
    std::printf("failed to start TLS test server with %s\n", cert_file.c_str());
    return 1;
  }
  std::uint16_t const port = server.port();
  trie::http::endpoint const address{"127.0.0.1", port};

  tls_test_server mtls_server;
  if (!mtls_server.start(cert_file, key_file, true)) {
    std::printf("failed to start mTLS test server with %s\n", cert_file.c_str());
    return 1;
  }
  trie::http::endpoint const mtls_address{"127.0.0.1", mtls_server.port()};

  {
    // Verification off: the self-signed certificate is accepted.
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->status_code, 200);
      CHECK_EQ(result->body, std::string{"pong"});
      CHECK(!result->header("content-length").empty());
    }
  }
  {
    // Verification on against the certificate as its own CA, with SNI.
    trie::http::tls_transport_options options{};
    options.verify_peer = true;
    options.ca_file = cert_file;
    options.server_name = "localhost";
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->status_code, 200);
      CHECK_EQ(result->body, std::string{"pong"});
    }
    CHECK_EQ(server.last_sni(), std::string{"localhost"});
  }
  {
    // An empty server_name falls back to address.host for SNI and verification.
    trie::http::tls_transport_options options{};
    options.verify_peer = true;
    options.ca_file = cert_file;
    trie::http::tls_transport transport{trie::http::endpoint{"localhost", port}, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->status_code, 200);
      CHECK_EQ(result->body, std::string{"pong"});
    }
  }
  {
    // Verification on without a CA bundle (system roots) rejects self-signed.
    trie::http::tls_transport_options options{};
    options.verify_peer = true;
    options.server_name = "localhost";
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(!result.has_value());
    if (!result) {
      CHECK_EQ(result.error().status, 0);
      CHECK(result.error().message.find("certificate") != std::string::npos);
    }
  }
  {
    // An unreadable CA bundle is reported as a transport error.
    trie::http::tls_transport_options options{};
    options.verify_peer = true;
    options.ca_file = data_dir + "/missing-ca.pem";
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(!result.has_value());
    if (!result) {
      CHECK_EQ(result.error().status, 0);
      CHECK(result.error().message.find("CA file") != std::string::npos);
    }
  }
  {
    // Status code and body are parsed from the response.
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/created"));
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->status_code, 201);
      CHECK_EQ(result->body, std::string{"created"});
    }
  }
  {
    // Body delimited by connection close (no Content-Length).
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/eof"));
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->status_code, 200);
      CHECK_EQ(result->body, std::string{"eof-body"});
      CHECK(result->header("content-length").empty());
    }
  }
  {
    // An abrupt TCP close without close_notify is still read as EOF.
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/abrupt"));
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->status_code, 200);
      CHECK_EQ(result->body, std::string{"abrupt-body"});
    }
  }
  {
    // A response larger than max_response_bytes is rejected.
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    options.max_response_bytes = 2;
    trie::http::tls_transport transport{address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(!result.has_value());
    if (!result) {
      CHECK_EQ(result.error().status, 0);
      CHECK(result.error().message.find("too large") != std::string::npos);
    }
  }
  {
    // Connection failure is reported as a transport error (status 0).
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    options.connect_timeout_ms = 100;
    options.io_timeout_ms = 100;
    trie::http::tls_transport transport{trie::http::endpoint{"127.0.0.1", 1}, options};
    auto result = transport.send(get_request("/"));
    CHECK(!result.has_value());
    if (!result) CHECK_EQ(result.error().status, 0);
  }
  {
    // Client certificate and key are presented when the server asks for them.
    trie::http::tls_transport_options options{};
    options.verify_peer = true;
    options.ca_file = cert_file;
    options.server_name = "localhost";
    options.client_cert_file = data_dir + "/client.crt";
    options.client_key_file = data_dir + "/client.key";
    trie::http::tls_transport transport{mtls_address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->status_code, 200);
      CHECK_EQ(result->body, std::string{"pong"});
    }
    CHECK(mtls_server.peer_cert_seen());
  }
  {
    // A client certificate without its private key is a configuration error.
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    options.client_cert_file = data_dir + "/client.crt";
    trie::http::tls_transport transport{mtls_address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(!result.has_value());
    if (!result) {
      CHECK_EQ(result.error().status, 0);
      CHECK(result.error().message.find("client_cert_file") != std::string::npos);
    }
  }
  {
    // A server that requires a client certificate rejects a client without one.
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    trie::http::tls_transport transport{mtls_address, options};
    auto result = transport.send(get_request("/ping"));
    CHECK(!result.has_value());
    if (!result) CHECK_EQ(result.error().status, 0);
  }
  {
    // End-to-end typed client call over TLS.
    trie::http::tls_transport_options options{};
    options.verify_peer = false;
    trie::client<api, trie::http::tls_transport> client{trie::http::tls_transport{address, options}};
    auto result = client.call<^^api::ping>();
    CHECK(result.has_value());
    if (result) CHECK_EQ(*result, std::string{"pong"});
  }

  server.stop();
  mtls_server.stop();
  return tst::report("tls_transport_test");
}

#endif
