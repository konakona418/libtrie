#include "trie/trie.hh"

#include <array>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "harness.hh"

enum class color { red, green, blue };
enum class flag : unsigned { none = 0, a = 1, b = 2 };

struct enum_api {
  [[=trie::get("/colors/{c}")]] std::string color_path(color value) {
    return std::string(trie::enum_name(value));
  }

  [[=trie::get("/colors")]] std::string color_query([[=trie::query("c")]] color value,
                                                     [[=trie::query("f")]] std::optional<flag> extra) {
    std::string out(trie::enum_name(value));
    if (extra.has_value()) {
      out += ':';
      out += trie::enum_name(*extra);
    }
    return out;
  }

  [[=trie::get("/header")]] std::string color_header([[=trie::header("X-Color")]] color value) {
    return std::string(trie::enum_name(value));
  }

  [[=trie::get("/numeric/{c}")]] int color_number(color value) { return static_cast<int>(value); }
};

struct loopback_transport {
  trie::server<enum_api>* server = nullptr;

  std::expected<trie::http::response, trie::client_error> send(trie::http::request request) {
    std::vector<trie::http::header_view> scratch;
    scratch.reserve(request.headers.size());
    for (auto const& header : request.headers) scratch.push_back({header.first, header.second});
    return server->dispatch(
        trie::http::request_view::from_target(request.m, request.target, scratch, request.body));
  }
};

static_assert(trie::enum_name(color::green) == std::string_view{"green"});
static_assert(trie::enum_from_name<color>("blue") == color::blue);
static_assert(!trie::enum_from_name<color>("purple").has_value());
static_assert(trie::enum_name(static_cast<color>(42)).empty());

int main() {
  trie::server<enum_api> server;

  {
    auto response = server.dispatch(trie::method::get, "/colors/green");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"green"});
  }
  {
    auto response = server.dispatch(trie::method::get, "/colors/2");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"blue"});
  }
  {
    auto response = server.dispatch(trie::method::get, "/colors/purple");
    CHECK_EQ(response.status_code, 400);
  }
  {
    auto response = server.dispatch(trie::method::get, "/colors?c=red");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"red"});
  }
  {
    auto response = server.dispatch(trie::method::get, "/colors?c=red&f=b");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"red:b"});
  }
  {
    auto response = server.dispatch(trie::method::get, "/colors?c=red&f=nope");
    CHECK_EQ(response.status_code, 400);
  }
  {
    auto response = server.dispatch(trie::method::get, "/colors");
    CHECK_EQ(response.status_code, 400);
  }
  {
    const std::array<trie::http::header_view, 1> headers{{{"X-Color", "blue"}}};
    auto request = trie::http::request_view::from_target(trie::method::get, "/header", headers);
    auto response = server.dispatch(request);
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"blue"});
  }
  {
    auto response = server.dispatch(trie::method::get, "/numeric/1");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"1"});
  }
  {
    trie::client<enum_api, loopback_transport> client{loopback_transport{&server}};

    auto path = client.call<^^enum_api::color_path>(color::green);
    CHECK(path.has_value());
    CHECK_EQ(*path, std::string{"green"});

    auto query = client.call<^^enum_api::color_query>(color::red, flag::b);
    CHECK(query.has_value());
    CHECK_EQ(*query, std::string{"red:b"});

    auto header = client.call<^^enum_api::color_header>(color::blue);
    CHECK(header.has_value());
    CHECK_EQ(*header, std::string{"blue"});

    auto number = client.call<^^enum_api::color_number>(color::blue);
    CHECK(number.has_value());
    CHECK_EQ(*number, 2);
  }
  return tst::report("enum_param_test");
}
