// End-to-end test for the HTTP/2 client transport: a real tls_listener with
// ALPN "h2" serves a trie::client<Api, h2_transport> instance.

#define TRIE_TLS_LISTENER_WITH_HTTP2 1

#include "trie/trie.hh"

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "harness.hh"
#include "trie/http/h2_transport.hh"
#include "trie/http/tls_listener.hh"

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

struct person {
  std::string name;
  int age = 0;
};

struct api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }

  [[=trie::get("/person")]] person get_person() { return person{"alice", 30}; }

  [[=trie::post("/person/echo")]] person echo_person([[=trie::body]] person value) { return value; }

  [[=trie::get("/large")]] std::string large() { return std::string(128 * 1024, 'x'); }

  [[=trie::get("/header")]] std::string header_echo([[=trie::header("x-test")]] std::string value) {
    return value;
  }
};

trie::http::request get_request(std::string target) {
  trie::http::request request{};
  request.m = trie::method::get;
  request.target = std::move(target);
  return request;
}

trie::http::h2_transport_options transport_options(bool verify_peer, std::string ca_file = {}) {
  trie::http::h2_transport_options options{};
  options.verify_peer = verify_peer;
  options.server_name = "localhost";
  options.ca_file = std::move(ca_file);
  options.connect_timeout_ms = 3000;
  options.io_timeout_ms = 5000;
  return options;
}

trie::http::tls_serve_options listener_options(std::string certificate, std::string key, bool http2) {
  trie::http::tls_serve_options options{};
  options.certificate_chain_file = std::move(certificate);
  options.private_key_file = std::move(key);
  options.enable_http2 = http2;
  options.alpn_protocols = {"h2", "http/1.1"};
  options.http.idle_timeout = 5000ms;
  options.http.drain_timeout = 1000ms;
  return options;
}

// Binds an ephemeral loopback port and releases it, giving a port nobody is
// listening on (used for the connection-refused path).
std::uint16_t unused_port() {
  int const fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return 0;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = 0;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    ::close(fd);
    return 0;
  }
  socklen_t length = sizeof(address);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    ::close(fd);
    return 0;
  }
  std::uint16_t const port = ntohs(address.sin_port);
  ::close(fd);
  return port;
}

} // namespace

int main() {
  std::string const data_dir = test_data_dir();
  std::string const server_cert = data_dir + "/server.crt";
  std::string const server_key = data_dir + "/server.key";
  std::string const client_cert = data_dir + "/client.crt";
  std::string const client_key = data_dir + "/client.key";

  // --- HTTP/2 server ------------------------------------------------------
  trie::server<api> router;
  trie::http::tls_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                     listener_options(server_cert, server_key, true)};
  CHECK(server.valid());
  CHECK_EQ(server.error_code(), 0);
  CHECK(server.port() != 0);
  std::thread runner{[&server] { server.run(); }};
  trie::http::endpoint const address{"127.0.0.1", server.port()};

  {
    // Typed client over HTTP/2: GET, typed JSON GET, typed JSON POST echo, and a
    // response large enough to need multiple DATA frames.
    trie::client<api, trie::http::h2_transport> client{
        trie::http::h2_transport{address, transport_options(false)}};

    auto ping = client.call<^^api::ping>();
    CHECK(ping.has_value());
    if (ping) CHECK_EQ(*ping, std::string{"pong"});

    auto person_result = client.call<^^api::get_person>();
    CHECK(person_result.has_value());
    if (person_result) {
      CHECK_EQ(person_result->name, std::string{"alice"});
      CHECK_EQ(person_result->age, 30);
    }

    auto echoed = client.call<^^api::echo_person>(person{"bob", 20});
    CHECK(echoed.has_value());
    if (echoed) {
      CHECK_EQ(echoed->name, std::string{"bob"});
      CHECK_EQ(echoed->age, 20);
    }

    auto large = client.call<^^api::large>();
    CHECK(large.has_value());
    if (large) {
      CHECK_EQ(large->size(), std::size_t{128} * 1024);
      if (!large->empty()) {
        CHECK_EQ(large->front(), 'x');
        CHECK_EQ(large->back(), 'x');
      }
    }
  }

  {
    // Raw transport checks that need headers/status without typed decoding.
    trie::http::h2_transport transport{address, transport_options(false)};

    auto missing = transport.send(get_request("/missing"));
    CHECK(missing.has_value());
    if (missing) {
      CHECK_EQ(missing->status_code, 404);
      CHECK_EQ(missing->body, std::string{"not found"});
    }

    auto wrong_method_request = get_request("/ping");
    wrong_method_request.m = trie::method::post;
    auto wrong_method = transport.send(std::move(wrong_method_request));
    CHECK(wrong_method.has_value());
    if (wrong_method) {
      CHECK_EQ(wrong_method->status_code, 405);
      auto const allow = wrong_method->header("allow");
      CHECK(allow.find("GET") != std::string_view::npos);
      CHECK(allow.find("HEAD") != std::string_view::npos);
    }

    auto head_request = get_request("/ping");
    head_request.m = trie::method::head;
    auto head = transport.send(std::move(head_request));
    CHECK(head.has_value());
    if (head) {
      CHECK_EQ(head->status_code, 200);
      CHECK_EQ(head->header("content-length"), std::string_view{"4"});
      CHECK(head->body.empty());
    }

    // Request headers are forwarded (lowercased) as regular HTTP/2 fields.
    auto header_request = get_request("/header");
    header_request.headers.emplace_back("X-Test", "forwarded");
    auto header_response = transport.send(std::move(header_request));
    CHECK(header_response.has_value());
    if (header_response) {
      CHECK_EQ(header_response->status_code, 200);
      CHECK_EQ(header_response->body, std::string{"forwarded"});
    }

    auto person_response = transport.send(get_request("/person"));
    CHECK(person_response.has_value());
    if (person_response) {
      CHECK_EQ(person_response->status_code, 200);
      CHECK_EQ(person_response->header("content-type"), std::string_view{"application/json"});
    }
  }

  {
    // Peer verification against the test certificate used as its own CA.
    trie::http::h2_transport transport{address, transport_options(true, server_cert)};
    auto response = transport.send(get_request("/ping"));
    CHECK(response.has_value());
    if (response) {
      CHECK_EQ(response->status_code, 200);
      CHECK_EQ(response->body, std::string{"pong"});
    }
  }

  {
    // Connection refused: nobody listens on this port.
    trie::http::h2_transport transport{trie::http::endpoint{"127.0.0.1", unused_port()},
                                       transport_options(false)};
    auto response = transport.send(get_request("/ping"));
    CHECK(!response.has_value());
    if (!response) {
      CHECK_EQ(response.error().status, 0);
      CHECK(!response.error().message.empty());
    }
  }

  {
    // verify_peer=true with the wrong CA (the self-signed client cert).
    trie::http::h2_transport transport{address, transport_options(true, client_cert)};
    auto response = transport.send(get_request("/ping"));
    CHECK(!response.has_value());
    if (!response) CHECK_EQ(response.error().status, 0);
  }

  {
    // verify_peer=true with no CA file: the system store does not trust the
    // self-signed test certificate.
    trie::http::h2_transport transport{address, transport_options(true)};
    auto response = transport.send(get_request("/ping"));
    CHECK(!response.has_value());
  }

  {
    // max_response_bytes is enforced while DATA frames arrive.
    trie::http::h2_transport_options options = transport_options(false);
    options.max_response_bytes = 1024;
    trie::http::h2_transport transport{address, options};
    auto response = transport.send(get_request("/large"));
    CHECK(!response.has_value());
    if (!response) CHECK(response.error().message.find("max_response_bytes") != std::string::npos);
  }

  {
    // mTLS: the transport presents the test client certificate when asked.
    trie::server<api> mtls_router;
    trie::http::tls_serve_options mtls_options = listener_options(server_cert, server_key, true);
    mtls_options.ca_file = client_cert;
    mtls_options.verify_client = true;
    trie::http::tls_listener<trie::server<api>> mtls_server{
        mtls_router, trie::http::endpoint{"127.0.0.1", 0}, mtls_options};
    CHECK(mtls_server.valid());
    std::thread mtls_runner{[&mtls_server] { mtls_server.run(); }};
    trie::http::endpoint const mtls_address{"127.0.0.1", mtls_server.port()};

    {
      trie::http::h2_transport_options options = transport_options(true, server_cert);
      options.client_certificate_file = client_cert;
      options.client_key_file = client_key;
      trie::http::h2_transport transport{mtls_address, options};
      auto response = transport.send(get_request("/ping"));
      CHECK(response.has_value());
      if (response) {
        CHECK_EQ(response->status_code, 200);
        CHECK_EQ(response->body, std::string{"pong"});
      }
    }
    {
      // Without a client certificate the TLS handshake is rejected.
      trie::http::h2_transport transport{mtls_address, transport_options(false)};
      auto response = transport.send(get_request("/ping"));
      CHECK(!response.has_value());
    }

    mtls_server.stop();
    mtls_runner.join();
    CHECK(mtls_server.stopping());
  }

  {
    // ALPN safety: an HTTP/1.1-only TLS listener must never be spoken to as
    // HTTP/2, and there is no silent HTTP/1.1 fallback.
    trie::server<api> http1_router;
    trie::http::tls_listener<trie::server<api>> http1_server{
        http1_router, trie::http::endpoint{"127.0.0.1", 0},
        listener_options(server_cert, server_key, false)};
    CHECK(http1_server.valid());
    std::thread http1_runner{[&http1_server] { http1_server.run(); }};
    trie::http::endpoint const http1_address{"127.0.0.1", http1_server.port()};

    {
      // Default offer: "h2" only, which the server filters out -> no ALPN.
      trie::http::h2_transport transport{http1_address, transport_options(false)};
      auto response = transport.send(get_request("/ping"));
      CHECK(!response.has_value());
      if (!response) CHECK(response.error().message.find("ALPN") != std::string::npos);
    }
    {
      // Offering http/1.1 as well: the server selects it, and the transport
      // still refuses to downgrade.
      trie::http::h2_transport_options options = transport_options(false);
      options.alpn_protocols = {"h2", "http/1.1"};
      trie::http::h2_transport transport{http1_address, options};
      auto response = transport.send(get_request("/ping"));
      CHECK(!response.has_value());
      if (!response) {
        CHECK(response.error().message.find("ALPN") != std::string::npos);
        CHECK(response.error().message.find("http/1.1") != std::string::npos);
      }
    }

    http1_server.stop();
    http1_runner.join();
    CHECK(http1_server.stopping());
  }

  server.stop();
  runner.join();
  CHECK(server.stopping());
  CHECK(server.accepted_connections() >= 8);

  return tst::report("h2_transport_test");
}

#endif
