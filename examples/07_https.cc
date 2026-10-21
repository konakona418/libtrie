// HTTPS server (HTTP/1.1 over TLS). Generate/obtain a certificate first, e.g.
// the test certificates in tests/data can be used for local experiments:
//
//   ./build/dev/examples/trie_07_https 8443 tests/data/server.crt tests/data/server.key
//
// For HTTP/2 over TLS, define TRIE_TLS_LISTENER_WITH_HTTP2 before including
// tls_listener.hh, set options.enable_http2 = true, and link nghttp2.

#include "trie/trie.hh"
#include "trie/http/tls_listener.hh"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

struct api {
  [[=trie::get("/hello")]] std::string hello() { return "hello over HTTPS"; }
};

int main(int argc, char** argv) {
  const std::uint16_t port = argc > 1 ? static_cast<std::uint16_t>(std::atoi(argv[1])) : 8443;
  if (argc < 4) {
    std::printf("usage: %s <port> <cert.pem> <key.pem>\n", argv[0]);
    return 1;
  }

  trie::http::tls_serve_options options{};
  options.certificate_chain_file = argv[2];
  options.private_key_file = argv[3];
  options.alpn_protocols = {"http/1.1"};

  trie::server<api> router;
  trie::http::tls_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", port}, options};
  if (!server.valid()) {
    std::printf("failed to start HTTPS listener (error %d)\n", server.error_code());
    return 1;
  }
  std::printf("listening on https://127.0.0.1:%u\n", static_cast<unsigned>(server.port()));
  server.run();
  return 0;
}
