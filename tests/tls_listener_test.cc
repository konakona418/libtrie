#include "trie/trie.hh"

#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "harness.hh"
#include "trie/http/tls_listener.hh"
#include "trie/http/tls_transport.hh"

using namespace std::chrono_literals;

#if !defined(__linux__)
int main() { return 0; }
#else

namespace {

// tests/data holds the test certificates. Tests run from the repo root or from
// a build directory, so look in a few plausible places (an explicit
// -DTRIE_TEST_DATA_DIR=... wins if provided).
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

std::string_view response_body(std::string_view wire) {
  auto head_end = wire.find("\r\n\r\n");
  if (head_end == std::string_view::npos) return {};
  return wire.substr(head_end + 4);
}

bool starts_with_status(std::string_view wire, std::string_view status) {
  return wire.starts_with("HTTP/1.1 ") && wire.substr(9).starts_with(status);
}

std::size_t response_content_length(std::string_view head) {
  std::size_t position = head.find("\r\n");
  if (position == std::string_view::npos) return 0;
  position += 2;
  while (position < head.size()) {
    auto end = head.find("\r\n", position);
    // The final header line is not CRLF-terminated: `head` excludes the blank line.
    std::string_view line =
        end == std::string_view::npos ? head.substr(position) : head.substr(position, end - position);
    auto colon = line.find(':');
    if (colon != std::string_view::npos && trie::http::iequals(line.substr(0, colon), "content-length")) {
      std::string_view value = line.substr(colon + 1);
      while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
      std::size_t length = 0;
      (void)std::from_chars(value.data(), value.data() + value.size(), length);
      return length;
    }
    if (end == std::string_view::npos) break;
    position = end + 2;
  }
  return 0;
}

// Small blocking TLS client used where tls_transport cannot express the test:
// ALPN negotiation, keep-alive on one connection, and holding an idle
// connection open for the drain test.
class raw_tls_client {
public:
  raw_tls_client() = default;
  raw_tls_client(raw_tls_client const&) = delete;
  raw_tls_client& operator=(raw_tls_client const&) = delete;
  ~raw_tls_client() { close(); }

  bool connect(std::uint16_t port, std::vector<std::string> const& alpn) {
    fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) return false;
    timeval timeout{2, 0};
    (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
      close();
      return false;
    }

    ctx_ = SSL_CTX_new(TLS_client_method());
    if (ctx_ == nullptr) {
      close();
      return false;
    }
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    ssl_ = SSL_new(ctx_);
    if (ssl_ == nullptr) {
      close();
      return false;
    }
    (void)SSL_set_fd(ssl_, fd_);
    if (!alpn.empty()) {
      std::string wire;
      for (auto const& protocol : alpn) {
        wire.push_back(static_cast<char>(protocol.size()));
        wire += protocol;
      }
      (void)SSL_set_alpn_protos(ssl_, reinterpret_cast<unsigned char const*>(wire.data()),
                                static_cast<unsigned int>(wire.size()));
    }
    if (SSL_connect(ssl_) != 1) {
      close();
      return false;
    }
    return true;
  }

  std::string selected_alpn() const {
    unsigned char const* data = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(ssl_, &data, &length);
    return std::string(reinterpret_cast<char const*>(data), static_cast<std::size_t>(length));
  }

  bool send_all(std::string_view data) {
    while (!data.empty()) {
      int sent = SSL_write(ssl_, data.data(), static_cast<int>(data.size()));
      if (sent <= 0) return false;
      data.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
  }

  // Reads exactly one Content-Length delimited response (keep-alive tests).
  std::string read_response() {
    while (true) {
      auto head_end = buffer_.find("\r\n\r\n");
      if (head_end != std::string::npos) {
        std::size_t const total =
            head_end + 4 + response_content_length(std::string_view{buffer_}.substr(0, head_end));
        if (buffer_.size() >= total) {
          std::string out = buffer_.substr(0, total);
          buffer_.erase(0, total);
          return out;
        }
      }
      std::array<char, 4096> chunk{};
      int received = SSL_read(ssl_, chunk.data(), static_cast<int>(chunk.size()));
      if (received <= 0) {
        std::string out = std::move(buffer_);
        buffer_.clear();
        return out;
      }
      buffer_.append(chunk.data(), static_cast<std::size_t>(received));
    }
  }

  std::string read_until_eof() {
    std::string out = std::move(buffer_);
    buffer_.clear();
    std::array<char, 4096> chunk{};
    while (true) {
      int received = SSL_read(ssl_, chunk.data(), static_cast<int>(chunk.size()));
      if (received <= 0) break; // ZERO_RETURN/SYSCALL or the 2s socket timeout
      out.append(chunk.data(), static_cast<std::size_t>(received));
    }
    return out;
  }

  void close() {
    if (ssl_ != nullptr) {
      SSL_free(ssl_);
      ssl_ = nullptr;
    }
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

private:
  int fd_ = -1;
  SSL_CTX* ctx_ = nullptr;
  SSL* ssl_ = nullptr;
  std::string buffer_;
};

struct person {
  std::string name;
  int age = 0;
};

struct slow_state {
  std::atomic<bool> started{false};
};

struct api {
  slow_state* slow = nullptr;

  [[=trie::get("/ping")]] std::string ping() { return "pong"; }

  [[=trie::get("/json")]] person get_person() { return person{"alice", 30}; }

  [[=trie::post("/person")]] person bump_age([[=trie::body]] person value) {
    value.age += 1;
    return value;
  }

  [[=trie::get("/slow")]] std::string slow_request() {
    if (slow != nullptr) slow->started.store(true);
    std::this_thread::sleep_for(100ms);
    return "slow";
  }
};

trie::http::tls_transport_options client_options(bool verify_peer, std::string const& ca_file) {
  trie::http::tls_transport_options options{};
  options.verify_peer = verify_peer;
  if (verify_peer) {
    options.ca_file = ca_file;
    options.server_name = "localhost";
  }
  return options;
}

trie::http::request get_request(std::string target) {
  trie::http::request request{};
  request.m = trie::method::get;
  request.target = std::move(target);
  return request;
}

} // namespace

int main() {
  std::string const data_dir = test_data_dir();
  std::string const server_cert = data_dir + "/server.crt";
  std::string const server_key = data_dir + "/server.key";
  std::string const client_cert = data_dir + "/client.crt";
  std::string const client_key = data_dir + "/client.key";

  trie::server<api> router;
  slow_state slow{};
  router.controller<api>().slow = &slow;

  trie::http::tls_serve_options server_options{};
  server_options.certificate_chain_file = server_cert;
  server_options.private_key_file = server_key;
  // "h2" is listed but enable_http2 is false, so the ALPN gate must not pick it.
  server_options.alpn_protocols = {"h2", "http/1.1"};

  trie::http::tls_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                     server_options};
  CHECK(server.valid());
  CHECK_EQ(server.error_code(), 0);
  CHECK(server.port() != 0);
  CHECK(!server.stopping());
  std::thread server_thread{[&server] { server.run(); }};

  auto address = [&server] { return trie::http::endpoint{"127.0.0.1", server.port()}; };

  {
    // Typed GET through trie::client over TLS (no ALPN offered by the client).
    trie::client<api, trie::http::tls_transport> client{
        trie::http::tls_transport{address(), client_options(false, server_cert)}};
    auto result = client.call<^^api::ping>();
    CHECK(result.has_value());
    if (result) CHECK_EQ(*result, std::string{"pong"});
  }
  {
    // Typed JSON response.
    trie::client<api, trie::http::tls_transport> client{
        trie::http::tls_transport{address(), client_options(false, server_cert)}};
    auto result = client.call<^^api::get_person>();
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->name, std::string{"alice"});
      CHECK_EQ(result->age, 30);
    }
  }
  {
    // Typed JSON POST/response round-trip.
    trie::client<api, trie::http::tls_transport> client{
        trie::http::tls_transport{address(), client_options(false, server_cert)}};
    auto result = client.call<^^api::bump_age>(person{"bob", 20});
    CHECK(result.has_value());
    if (result) {
      CHECK_EQ(result->name, std::string{"bob"});
      CHECK_EQ(result->age, 21);
    }
  }
  {
    // verify_peer=true against the test certificate (used as its own CA).
    trie::http::tls_transport transport{address(), client_options(true, server_cert)};
    auto response = transport.send(get_request("/ping"));
    CHECK(response.has_value());
    if (response) {
      CHECK_EQ(response->status_code, 200);
      CHECK_EQ(response->body, std::string{"pong"});
    }
  }
  {
    // Unknown route -> 404.
    trie::http::tls_transport transport{address(), client_options(false, server_cert)};
    auto response = transport.send(get_request("/missing"));
    CHECK(response.has_value());
    if (response) CHECK_EQ(response->status_code, 404);
  }
  {
    // Wrong method -> 405 with an Allow header.
    trie::http::tls_transport transport{address(), client_options(false, server_cert)};
    auto request = get_request("/ping");
    request.m = trie::method::post;
    auto response = transport.send(std::move(request));
    CHECK(response.has_value());
    if (response) {
      CHECK_EQ(response->status_code, 405);
      CHECK(response->header("allow").find("GET") != std::string_view::npos);
    }
  }
  {
    // HEAD carries Content-Length but no body.
    trie::http::tls_transport transport{address(), client_options(false, server_cert)};
    auto request = get_request("/ping");
    request.m = trie::method::head;
    auto response = transport.send(std::move(request));
    CHECK(response.has_value());
    if (response) {
      CHECK_EQ(response->status_code, 200);
      CHECK_EQ(response->header("content-length"), std::string_view{"4"});
      CHECK(response->body.empty());
    }
  }
  {
    // ALPN gate + server preference + keep-alive on one TLS connection: the
    // client offers h2 first, but enable_http2 is false, so http/1.1 wins.
    raw_tls_client client;
    CHECK(client.connect(server.port(), {"h2", "http/1.1"}));
    CHECK_EQ(client.selected_alpn(), std::string{"http/1.1"});

    CHECK(client.send_all("GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto first = client.read_response();
    CHECK(starts_with_status(first, "200"));
    CHECK_EQ(response_body(first), std::string_view{"pong"});

    CHECK(client.send_all("GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto second = client.read_response();
    CHECK(starts_with_status(second, "200"));
    CHECK_EQ(response_body(second), std::string_view{"pong"});
  }
  CHECK(server.accepted_connections() >= 8);

  // --- mTLS listener -------------------------------------------------------
  trie::server<api> mtls_router;
  trie::http::tls_serve_options mtls_options{};
  mtls_options.certificate_chain_file = server_cert;
  mtls_options.private_key_file = server_key;
  mtls_options.ca_file = client_cert;
  mtls_options.verify_client = true;
  trie::http::tls_listener<trie::server<api>> mtls_server{mtls_router, trie::http::endpoint{"127.0.0.1", 0},
                                                          mtls_options};
  CHECK(mtls_server.valid());
  CHECK(mtls_server.port() != 0);
  std::thread mtls_thread{[&mtls_server] { mtls_server.run(); }};
  {
    // mTLS positive: the server verifies the client certificate against
    // client.crt (self-signed, so it is its own CA).
    trie::http::tls_transport_options options = client_options(true, server_cert);
    options.client_cert_file = client_cert;
    options.client_key_file = client_key;
    trie::http::tls_transport transport{trie::http::endpoint{"127.0.0.1", mtls_server.port()}, options};
    auto response = transport.send(get_request("/ping"));
    CHECK(response.has_value());
    if (response) {
      CHECK_EQ(response->status_code, 200);
      CHECK_EQ(response->body, std::string{"pong"});
    }
  }
  {
    // mTLS negative: a client without a certificate is rejected.
    trie::http::tls_transport transport{trie::http::endpoint{"127.0.0.1", mtls_server.port()},
                                        client_options(false, server_cert)};
    auto response = transport.send(get_request("/ping"));
    CHECK(!response.has_value());
    if (!response) CHECK_EQ(response.error().status, 0);
  }
  CHECK(mtls_server.accepted_connections() >= 2);
  mtls_server.stop();
  mtls_thread.join();
  CHECK(mtls_server.stopping());

  // --- HTTP/2 opt-in gate + idle drain ------------------------------------
  {
    // HTTP/2 is opt-in via TRIE_TLS_LISTENER_WITH_HTTP2; without the macro an
    // enable_http2 listener must be invalid (ENOTSUP) rather than silently
    // speaking HTTP/1.1 to an h2 client. End-to-end HTTP/2 is covered by
    // tests/tls_http2_test.cc.
    trie::server<api> h2_router;
    trie::http::tls_serve_options h2_options{};
    h2_options.certificate_chain_file = server_cert;
    h2_options.private_key_file = server_key;
    h2_options.enable_http2 = true;
    trie::http::tls_listener<trie::server<api>> h2_server{h2_router, trie::http::endpoint{"127.0.0.1", 0},
                                                          h2_options};
#if defined(TRIE_TLS_LISTENER_WITH_HTTP2)
    CHECK(h2_server.valid());
#else
    CHECK(!h2_server.valid());
    CHECK_EQ(h2_server.error_code(), ENOTSUP);
#endif
  }
  {
    // An idle TLS keep-alive connection is cancelled promptly by stop()/drain.
    trie::server<api> drain_router;
    trie::http::tls_serve_options drain_options{};
    drain_options.certificate_chain_file = server_cert;
    drain_options.private_key_file = server_key;
    trie::http::tls_listener<trie::server<api>> drain_server{
        drain_router, trie::http::endpoint{"127.0.0.1", 0}, drain_options};
    CHECK(drain_server.valid());
    std::thread drain_thread{[&drain_server] { drain_server.run(); }};

    raw_tls_client idle;
    CHECK(idle.connect(drain_server.port(), {}));
    auto const started = std::chrono::steady_clock::now();
    drain_server.stop();
    drain_thread.join();
    auto const elapsed = std::chrono::steady_clock::now() - started;
    CHECK(drain_server.stopping());
    CHECK(elapsed < 2s);
    CHECK(drain_server.accepted_connections() >= 1);
    CHECK(idle.read_until_eof().empty()); // server closed the idle connection
  }

  // --- invalid configuration ----------------------------------------------
  {
    trie::server<api> bad_router;
    trie::http::tls_serve_options bad{};
    bad.private_key_file = server_key;
    trie::http::tls_listener<trie::server<api>> listener{bad_router, trie::http::endpoint{"127.0.0.1", 0},
                                                         bad};
    CHECK(!listener.valid());
    CHECK(listener.error_code() != 0);
    CHECK_EQ(listener.port(), 0);
    CHECK(!trie::http::serve_tls(bad_router, trie::http::endpoint{"127.0.0.1", 0}, bad));
  }
  {
    // A private key that does not match the certificate is also rejected.
    trie::server<api> bad_router;
    trie::http::tls_serve_options bad{};
    bad.certificate_chain_file = server_cert;
    bad.private_key_file = client_key;
    trie::http::tls_listener<trie::server<api>> listener{bad_router, trie::http::endpoint{"127.0.0.1", 0},
                                                         bad};
    CHECK(!listener.valid());
    CHECK(listener.error_code() != 0);
  }

  {
    // An unreadable client-CA bundle is a configuration error too.
    trie::server<api> bad_router;
    trie::http::tls_serve_options bad{};
    bad.certificate_chain_file = server_cert;
    bad.private_key_file = server_key;
    bad.ca_file = data_dir + "/missing-ca.pem";
    bad.verify_client = true;
    trie::http::tls_listener<trie::server<api>> listener{bad_router, trie::http::endpoint{"127.0.0.1", 0},
                                                         bad};
    CHECK(!listener.valid());
    CHECK(listener.error_code() != 0);
  }

  // --- handshake timeout ---------------------------------------------------
  {
    trie::server<api> timed_router;
    trie::http::tls_serve_options timed_options{};
    timed_options.certificate_chain_file = server_cert;
    timed_options.private_key_file = server_key;
    timed_options.handshake_timeout = 100ms;
    trie::http::tls_listener<trie::server<api>> timed{timed_router, trie::http::endpoint{"127.0.0.1", 0},
                                                      timed_options};
    CHECK(timed.valid());
    std::thread timed_thread{[&timed] { timed.run(); }};

    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    timeval timeout{1, 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(timed.port());
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);

    std::this_thread::sleep_for(300ms);
    std::size_t total = 0;
    ssize_t received = 0;
    char buffer[32];
    while ((received = ::recv(fd, buffer, sizeof(buffer), 0)) > 0) total += static_cast<std::size_t>(received);
    CHECK_EQ(received, ssize_t{0}); // the server closed the stalled handshake
    CHECK_EQ(total, std::size_t{0});
    ::close(fd);

    timed.stop();
    timed_thread.join();
    CHECK_EQ(timed.accepted_connections(), std::size_t{1});
  }

  // --- connection limit ----------------------------------------------------
  {
    trie::server<api> limit_router;
    trie::http::tls_serve_options limit_options{};
    limit_options.certificate_chain_file = server_cert;
    limit_options.private_key_file = server_key;
    limit_options.http.max_connections = 1;
    trie::http::tls_listener<trie::server<api>> limited{limit_router, trie::http::endpoint{"127.0.0.1", 0},
                                                        limit_options};
    CHECK(limited.valid());
    std::thread limited_thread{[&limited] { limited.run(); }};

    raw_tls_client holder;
    CHECK(holder.connect(limited.port(), {}));
    {
      // Over the limit: the extra connection is closed before the handshake.
      raw_tls_client rejected;
      CHECK(!rejected.connect(limited.port(), {}));
    }
    limited.stop();
    limited_thread.join();
    CHECK(limited.stopping());
    CHECK_EQ(limited.accepted_connections(), std::size_t{1});
    holder.close();
  }

  // --- in-flight request drain + final stop -------------------------------
  {
    trie::http::tls_transport transport{address(), client_options(false, server_cert)};
    std::string body{"unset"};
    std::thread client_thread{[&transport, &body] {
      auto response = transport.send(get_request("/slow"));
      if (response) body = std::move(response->body);
    }};

    auto const wait_deadline = std::chrono::steady_clock::now() + 2s;
    while (!slow.started.load(std::memory_order_relaxed) && std::chrono::steady_clock::now() < wait_deadline)
      std::this_thread::sleep_for(1ms);
    CHECK(slow.started.load(std::memory_order_relaxed));

    auto const started = std::chrono::steady_clock::now();
    server.stop();
    server_thread.join();
    client_thread.join();
    auto const elapsed = std::chrono::steady_clock::now() - started;

    CHECK(server.stopping());
    CHECK(elapsed < 5s);
    CHECK_EQ(body, std::string{"slow"});
    CHECK(server.accepted_connections() >= 9);
  }

  return tst::report("tls_listener_test");
}

#endif
