// 05 — Type-safe client over a real TCP connection.
//
// The client is instantiated with the same api type the server routes: the HTTP
// method, path template, parameter kinds and return type all come from the
// handler's reflection. socket_transport performs one blocking HTTP/1.1
// request per call (no pooling, no TLS).
#include "trie/trie.hh"

#include <cstdio>
#include <string>
#include <thread>

struct client_api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }

  [[=trie::get("/users/{id}")]] int double_id(int id) { return id * 2; }
};

int main() {
  trie::server<client_api> router;

  // Port 0: the kernel picks a free port; port() gives the real one to the client.
  trie::http::listener<trie::server<client_api>> server{router, trie::http::endpoint{"127.0.0.1", 0}};
  if (!server.valid()) {
    std::puts("error: could not bind 127.0.0.1:0");
    return 1;
  }
  std::printf("listening on http://127.0.0.1:%u\n", static_cast<unsigned>(server.port()));

  // The listener's event loop blocks, so run it on its own thread.
  std::thread server_thread{[&server] { server.run(); }};

  trie::client<client_api, trie::http::socket_transport> client{
      trie::http::socket_transport{trie::http::endpoint{"127.0.0.1", server.port()}}};

  // Each call returns std::expected<T, trie::client_error>: non-2xx responses,
  // transport failures and body-conversion failures are values, not exceptions.
  auto pong = client.call<^^client_api::ping>();
  if (pong) {
    std::printf("client.call<^^ping>()       -> %s\n", pong->c_str());
  } else {
    std::printf("client.call<^^ping>()       -> error %d %s\n", pong.error().status,
                pong.error().message.c_str());
  }

  auto doubled = client.call<^^client_api::double_id>(21);
  if (doubled) {
    std::printf("client.call<^^double_id>(21) -> %d\n", *doubled);
  } else {
    std::printf("client.call<^^double_id>(21) -> error %d %s\n", doubled.error().status,
                doubled.error().message.c_str());
  }

  server.stop();
  server_thread.join();
  return 0;
}
