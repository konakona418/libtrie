#include "trie/trie.hh"

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include "harness.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

struct person {
  std::string name;
  int age = 0;
};

struct api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }

  [[=trie::get("/users/{id}")]] int user(int id) { return id * 2; }

  [[=trie::get("/search")]] std::string search([[=trie::query("q")]] std::string_view q,
                                                [[=trie::query("limit")]] std::optional<int> limit) {
    std::string out(q);
    if (limit.has_value()) {
      out += ':';
      out += std::to_string(*limit);
    }
    return out;
  }

  [[=trie::get("/secure")]] std::string secure([[=trie::header("X-Token")]] std::string_view token) {
    return std::string(token);
  }

  [[=trie::post("/person")]] person bump_age([[=trie::body]] person value) {
    value.age += 1;
    return value;
  }

  [[=trie::get("/fail")]] trie::http::status fail() { return trie::http::status::bad_request; }
};

int main() {
  trie::server<api> router;
  trie::http::listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0}};
  CHECK(server.valid());

  std::thread server_thread{[&server] { server.run(); }};
  trie::client<api, trie::http::socket_transport> client{
      trie::http::socket_transport{trie::http::endpoint{"127.0.0.1", server.port()}}};

  {
    auto result = client.call<^^api::ping>();
    CHECK(result.has_value());
    CHECK_EQ(*result, std::string{"pong"});
  }
  {
    auto result = client.call<^^api::user>(42);
    CHECK(result.has_value());
    CHECK_EQ(*result, 84);
  }
  {
    auto result = client.call<^^api::search>(std::string_view{"hello world"}, std::optional<int>{3});
    CHECK(result.has_value());
    CHECK_EQ(*result, std::string{"hello world:3"});
  }
  {
    auto result = client.call<^^api::secure>(std::string_view{"token"});
    CHECK(result.has_value());
    CHECK_EQ(*result, std::string{"token"});
  }
  {
    auto result = client.call<^^api::bump_age>(person{"bob", 20});
    CHECK(result.has_value());
    CHECK_EQ(result->name, std::string{"bob"});
    CHECK_EQ(result->age, 21);
  }
  {
    auto result = client.call<^^api::fail>();
    CHECK(!result.has_value());
    CHECK_EQ(result.error().status, 400);
  }
  {
    // Unknown route: the server returns 404 and the client maps it to an error.
    trie::http::request request{};
    request.m = trie::method::get;
    request.target = "/missing";
    trie::http::socket_transport transport{trie::http::endpoint{"127.0.0.1", server.port()}};
    auto response = transport.send(std::move(request));
    CHECK(response.has_value());
    CHECK_EQ(response->status_code, 404);
  }
  {
    // Connection failure is reported as a transport error (status 0).
    trie::http::socket_transport unreachable{trie::http::endpoint{"127.0.0.1", 1},
                                             trie::http::socket_transport_options{100, 100}};
    trie::http::request request{};
    request.target = "/";
    auto response = unreachable.send(std::move(request));
    CHECK(!response.has_value());
    CHECK_EQ(response.error().status, 0);
  }

  server.stop();
  server_thread.join();
  return tst::report("socket_transport_test");
}

#endif
