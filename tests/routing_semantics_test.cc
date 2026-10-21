#include "trie/trie.hh"

#include <array>
#include <string>
#include <string_view>

#include "harness.hh"

// Wildcard route declared before the static one: static must still win.
struct wildcard_first {
  [[=trie::get("/users/{id}")]] std::string by_id(std::string_view id) { return "wild:" + std::string(id); }
  [[=trie::get("/users/me")]] std::string me() { return "static"; }
};

// Static route declared before the wildcard one: same result.
struct static_first {
  [[=trie::get("/users/me")]] std::string me() { return "static"; }
  [[=trie::get("/users/{id}")]] std::string by_id(std::string_view id) { return "wild:" + std::string(id); }
};

struct nested_api {
  [[=trie::get("/api/{id}")]] std::string wild(std::string_view id) { return "wild:" + std::string(id); }
  [[=trie::get("/api/me/details")]] std::string details() { return "details"; }
};

struct decode_api {
  [[=trie::get("/files/{name}")]] std::string file(std::string_view name) { return std::string(name); }
  [[=trie::get("/search")]] std::string search([[=trie::query("q")]] std::string_view q) { return std::string(q); }
  [[=trie::get("/header")]] std::string header([[=trie::header("X-Value")]] std::string_view value) {
    return std::string(value);
  }
};

int main() {
  {
    trie::server<wildcard_first> server;
    CHECK_EQ(server.dispatch(trie::method::get, "/users/me").body, std::string{"static"});
    CHECK_EQ(server.dispatch(trie::method::get, "/users/42").body, std::string{"wild:42"});
  }
  {
    trie::server<static_first> server;
    CHECK_EQ(server.dispatch(trie::method::get, "/users/me").body, std::string{"static"});
    CHECK_EQ(server.dispatch(trie::method::get, "/users/42").body, std::string{"wild:42"});
  }
  {
    trie::server<nested_api> server;
    CHECK_EQ(server.dispatch(trie::method::get, "/api/me/details").body, std::string{"details"});
    CHECK_EQ(server.dispatch(trie::method::get, "/api/me").body, std::string{"wild:me"});
  }
  {
    trie::server<decode_api> server;

    // Path segments: '+' is a literal plus; %XX is decoded.
    CHECK_EQ(server.dispatch(trie::method::get, "/files/a+b").body, std::string{"a+b"});
    CHECK_EQ(server.dispatch(trie::method::get, "/files/a%2Bb").body, std::string{"a+b"});
    CHECK_EQ(server.dispatch(trie::method::get, "/files/a%20b").body, std::string{"a b"});

    // Query values use form semantics: '+' means space.
    CHECK_EQ(server.dispatch(trie::method::get, "/search?q=a+b").body, std::string{"a b"});
    CHECK_EQ(server.dispatch(trie::method::get, "/search?q=a%2Bb").body, std::string{"a+b"});

    // Header values: '+' stays literal.
    const std::array<trie::http::header_view, 1> headers{{{"X-Value", "a+b"}}};
    auto response = server.dispatch(
        trie::http::request_view::from_target(trie::method::get, "/header", headers));
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"a+b"});

    const std::array<trie::http::header_view, 1> encoded{{{"X-Value", "a%2Bb"}}};
    response = server.dispatch(trie::http::request_view::from_target(trie::method::get, "/header", encoded));
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"a+b"});
  }
  return tst::report("routing_semantics_test");
}
