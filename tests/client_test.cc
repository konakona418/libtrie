#include "trie/trie.hh"

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "harness.hh"

struct api {
  [[=trie::get("/users/{id}")]] int get_user(int id) { return id * 2; }

  [[=trie::post("/users")]] void create_user([[=trie::body]] std::string_view body,
                                              trie::http::response& response) {
    response.set_status(trie::http::status::created);
    response.body.assign(body.data(), body.size());
  }

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
};

struct recording_transport {
  trie::http::request last{};
  trie::http::response reply{};

  std::expected<trie::http::response, trie::client_error> send(trie::http::request request) {
    last = std::move(request);
    return reply;
  }
};

struct loopback_transport {
  trie::server<api>* server = nullptr;

  std::expected<trie::http::response, trie::client_error> send(trie::http::request request) {
    std::vector<trie::http::header_view> scratch;
    scratch.reserve(request.headers.size());
    for (auto const& h : request.headers) scratch.push_back({h.first, h.second});
    return server->dispatch(trie::http::request_view::from_target(request.m, request.target, scratch,
                                                                 request.body));
  }
};

int main() {
  {
    trie::client<api, recording_transport> client{recording_transport{}};
    client.transport().reply.body = "84";

    auto result = client.call<^^api::get_user>(42);
    CHECK(result.has_value());
    CHECK_EQ(*result, 84);
    CHECK_EQ(client.transport().last.m, trie::method::get);
    CHECK_EQ(client.transport().last.target, std::string{"/users/42"});
    CHECK(client.transport().last.headers.empty());
    CHECK(client.transport().last.body.empty());
  }
  {
    trie::client<api, recording_transport> client{recording_transport{}};
    auto result = client.call<^^api::create_user>(std::string_view{"hello"});
    CHECK(result.has_value());
    CHECK_EQ(client.transport().last.m, trie::method::post);
    CHECK_EQ(client.transport().last.target, std::string{"/users"});
    CHECK_EQ(client.transport().last.body, std::string{"hello"});
  }
  {
    trie::client<api, recording_transport> client{recording_transport{}};
    client.transport().reply.body = "found";

    auto result = client.call<^^api::search>(std::string_view{"hello world"}, std::optional<int>{5});
    CHECK(result.has_value());
    CHECK_EQ(*result, std::string{"found"});
    CHECK_EQ(client.transport().last.target, std::string{"/search?q=hello%20world&limit=5"});
  }
  {
    trie::client<api, recording_transport> client{recording_transport{}};
    client.transport().reply.body = "x";

    auto result = client.call<^^api::search>(std::string_view{"x"}, std::optional<int>{});
    CHECK(result.has_value());
    CHECK_EQ(client.transport().last.target, std::string{"/search?q=x"});
  }
  {
    trie::client<api, recording_transport> client{recording_transport{}};
    client.transport().reply.body = "abc";

    auto result = client.call<^^api::secure>(std::string_view{"token-value"});
    CHECK(result.has_value());
    CHECK_EQ(client.transport().last.headers.size(), std::size_t{1});
    CHECK_EQ(client.transport().last.headers[0].first, std::string{"X-Token"});
    CHECK_EQ(client.transport().last.headers[0].second, std::string{"token-value"});
  }
  {
    trie::client<api, recording_transport> client{recording_transport{}};
    client.transport().reply.status_code = 404;
    client.transport().reply.body = "missing";

    auto result = client.call<^^api::get_user>(1);
    CHECK(!result.has_value());
    CHECK_EQ(result.error().status, 404);
    CHECK_EQ(result.error().message, std::string{"missing"});
  }
  {
    trie::client<api, recording_transport> client{recording_transport{}};
    client.transport().reply.status_code = 200;
    client.transport().reply.body = "not-an-int";

    auto result = client.call<^^api::get_user>(1);
    CHECK(!result.has_value());
    CHECK_EQ(result.error().status, 0);
  }
  {
    // End-to-end: the client talks to a real server through the mock transport.
    trie::server<api> server;
    trie::client<api, loopback_transport> client{loopback_transport{&server}};

    auto user = client.call<^^api::get_user>(7);
    CHECK(user.has_value());
    CHECK_EQ(*user, 14);

    auto search = client.call<^^api::search>(std::string_view{"hello world"}, std::optional<int>{3});
    CHECK(search.has_value());
    CHECK_EQ(*search, std::string{"hello world:3"});

    auto partial = client.call<^^api::search>(std::string_view{"x"}, std::optional<int>{});
    CHECK(partial.has_value());
    CHECK_EQ(*partial, std::string{"x"});

    auto secure = client.call<^^api::secure>(std::string_view{"abc"});
    CHECK(secure.has_value());
    CHECK_EQ(*secure, std::string{"abc"});

    auto created = client.call<^^api::create_user>(std::string_view{"data"});
    CHECK(created.has_value());
  }
  {
    using client_t = trie::client<api, recording_transport>;
    static_assert(std::is_same_v<decltype(std::declval<client_t&>().call<^^api::get_user>(1)),
                                 std::expected<int, trie::client_error>>);
    static_assert(
        std::is_same_v<decltype(std::declval<client_t&>().call<^^api::create_user>(std::string_view{})),
                       std::expected<void, trie::client_error>>);
    static_assert(std::is_same_v<
                  decltype(std::declval<client_t&>().call<^^api::search>(std::string_view{},
                                                                         std::optional<int>{})),
                  std::expected<std::string, trie::client_error>>);
  }
  return tst::report("client_test");
}
