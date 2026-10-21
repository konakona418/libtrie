#include "trie/trie.hh"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

struct person {
  std::string name;
  int age = 0;
};

enum class color { red, green, blue };

struct demo_api {
  [[=trie::get("/hello")]] std::string hello() { return "hello, world"; }

  [[=trie::get("/users/{id}")]] int user(int id) { return id; }

  [[=trie::get("/color/{c}")]] std::string color_name(color value) {
    return std::string(trie::enum_name(value));
  }

  [[=trie::get("/person/schema")]] trie::json::value person_schema() {
    return trie::json::schema<person>();
  }

  // Typed JSON: the request body is deserialized into `person`, and the response
  // is serialized with Content-Type: application/json.
  [[=trie::post("/person")]] person bump_age([[=trie::body]] person value) {
    value.age += 1;
    return value;
  }

  [[=trie::get("/info")]] trie::json::value info() {
    auto parsed = trie::json::parse(R"({"name":"libtrie","reflection":true})");
    return parsed.value_or(trie::json::value{});
  }
};

int main(int argc, char** argv) {
  const std::uint16_t port = argc > 1 ? static_cast<std::uint16_t>(std::atoi(argv[1])) : 8080;
  trie::server<demo_api> router;
  trie::http::listener<trie::server<demo_api>> server{router, trie::http::endpoint{"127.0.0.1", port}};
  if (!server.valid()) {
    std::printf("failed to bind 127.0.0.1:%u\n", static_cast<unsigned>(port));
    return 1;
  }
  std::printf("listening on http://127.0.0.1:%u\n", static_cast<unsigned>(server.port()));
  std::printf("  curl http://127.0.0.1:%u/hello\n", static_cast<unsigned>(server.port()));
  std::printf("  curl -X POST -H 'Content-Type: application/json' "
              "-d '{\"name\":\"a\",\"age\":1}' http://127.0.0.1:%u/person\n",
              static_cast<unsigned>(server.port()));
  std::printf("  curl http://127.0.0.1:%u/color/green\n", static_cast<unsigned>(server.port()));
  std::printf("  curl http://127.0.0.1:%u/person/schema\n", static_cast<unsigned>(server.port()));
  server.run();
  return 0;
}
