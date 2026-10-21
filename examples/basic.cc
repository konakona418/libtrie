#include "trie/trie.hh"

#include <cstdio>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct demo_api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }

  [[=trie::get("/users/{id}")]] int user(int id) { return id * 2; }

  [[=trie::get("/search")]] std::string search([[=trie::query("q")]] std::string_view q) {
    return "searching for: " + std::string(q);
  }
};

struct loopback_transport {
  trie::server<demo_api>* server = nullptr;

  std::expected<trie::http::response, trie::client_error> send(trie::http::request request) {
    std::vector<trie::http::header_view> scratch;
    for (auto const& header : request.headers) scratch.push_back({header.first, header.second});
    return server->dispatch(
        trie::http::request_view::from_target(request.m, request.target, scratch, request.body));
  }
};

int main() {
  trie::server<demo_api> server;

  auto response = server.dispatch(trie::method::get, "/ping");
  std::printf("GET /ping            -> %d %s\n", response.status_code, response.body.c_str());

  response = server.dispatch(trie::method::get, "/users/21");
  std::printf("GET /users/21        -> %d %s\n", response.status_code, response.body.c_str());

  response = server.dispatch(trie::method::get, "/search?q=hello%20world");
  std::printf("GET /search?q=...    -> %d %s\n", response.status_code, response.body.c_str());

  response = server.dispatch(trie::method::post, "/users/21");
  std::printf("POST /users/21       -> %d Allow: %s\n", response.status_code,
              std::string{response.header("Allow")}.c_str());

  response = server.dispatch(trie::method::get, "/missing");
  std::printf("GET /missing         -> %d %s\n", response.status_code, response.body.c_str());

  trie::client<demo_api, loopback_transport> client{loopback_transport{&server}};
  auto doubled = client.call<^^demo_api::user>(21);
  if (doubled) std::printf("client.user(21)      -> %d\n", *doubled);

  auto found = client.call<^^demo_api::search>(std::string_view{"hello world"});
  if (found) std::printf("client.search(..)    -> %s\n", found->c_str());
  return 0;
}
