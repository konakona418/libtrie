#include "trie/trie.hh"

#include <expected>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "harness.hh"

struct person {
  std::string name;
  int age = 0;
};

struct json_api {
  [[=trie::post("/echo")]] trie::json::value echo([[=trie::body]] trie::json::value body) {
    return body;
  }

  [[=trie::post("/person")]] person echo_person([[=trie::body]] person value) { return value; }

  [[=trie::get("/person")]] person get_person() { return person{"alice", 30}; }

  [[=trie::post("/person/text")]] std::string describe([[=trie::body]] person value) {
    return value.name + ":" + std::to_string(value.age);
  }
};

struct loopback_transport {
  trie::server<json_api>* server = nullptr;

  std::expected<trie::http::response, trie::client_error> send(trie::http::request request) {
    std::vector<trie::http::header_view> scratch;
    scratch.reserve(request.headers.size());
    for (auto const& header : request.headers) scratch.push_back({header.first, header.second});
    return server->dispatch(
        trie::http::request_view::from_target(request.m, request.target, scratch, request.body));
  }
};

int main() {
  trie::server<json_api> server;

  {
    auto response = server.dispatch(trie::method::post, "/person"); // no body -> invalid JSON
    CHECK_EQ(response.status_code, 400);
  }
  {
    trie::http::request_view request = trie::http::request_view::from_target(
        trie::method::post, "/person", {}, R"({"name":"bob","age":41})");
    auto response = server.dispatch(request);
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.header("content-type"), std::string_view{"application/json"});
    auto parsed = trie::json::parse_as<person>(response.body);
    CHECK(parsed.has_value());
    CHECK_EQ(parsed->name, std::string{"bob"});
    CHECK_EQ(parsed->age, 41);
  }
  {
    trie::http::request_view request =
        trie::http::request_view::from_target(trie::method::post, "/person", {}, R"({"name":1,"age":"x"})");
    auto response = server.dispatch(request);
    CHECK_EQ(response.status_code, 400);
  }
  {
    trie::http::request_view request =
        trie::http::request_view::from_target(trie::method::post, "/person", {}, "{not json");
    auto response = server.dispatch(request);
    CHECK_EQ(response.status_code, 400);
  }
  {
    auto response = server.dispatch(trie::method::get, "/person");
    CHECK_EQ(response.status_code, 200);
    auto parsed = trie::json::parse_as<person>(response.body);
    CHECK(parsed.has_value());
    CHECK_EQ(parsed->name, std::string{"alice"});
    CHECK_EQ(parsed->age, 30);
  }
  {
    trie::http::request_view request = trie::http::request_view::from_target(
        trie::method::post, "/person/text", {}, R"({"name":"carol","age":22})");
    auto response = server.dispatch(request);
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"carol:22"});
    CHECK(response.header("content-type").empty());
  }
  {
    trie::http::request_view request =
        trie::http::request_view::from_target(trie::method::post, "/echo", {}, R"({"a":[1,true,"x"]})");
    auto response = server.dispatch(request);
    CHECK_EQ(response.status_code, 200);
    auto parsed = trie::json::parse(response.body);
    CHECK(parsed.has_value());
    CHECK_EQ((*parsed)["a"][0].get<int>(), 1);
    CHECK_EQ((*parsed)["a"][2].get<std::string>(), std::string{"x"});
  }
  {
    trie::client<json_api, loopback_transport> client{loopback_transport{&server}};

    auto echoed = client.call<^^json_api::echo_person>(person{"dave", 55});
    CHECK(echoed.has_value());
    CHECK_EQ(echoed->name, std::string{"dave"});
    CHECK_EQ(echoed->age, 55);

    auto fetched = client.call<^^json_api::get_person>();
    CHECK(fetched.has_value());
    CHECK_EQ(fetched->name, std::string{"alice"});
    CHECK_EQ(fetched->age, 30);

    auto text = client.call<^^json_api::describe>(person{"erin", 18});
    CHECK(text.has_value());
    CHECK_EQ(*text, std::string{"erin:18"});

    auto value = client.call<^^json_api::echo>(trie::json::parse(R"({"n":7})").value());
    CHECK(value.has_value());
    CHECK_EQ((*value)["n"].get<int>(), 7);
  }
  {
    using client_t = trie::client<json_api, loopback_transport>;
    static_assert(std::is_same_v<decltype(std::declval<client_t&>().call<^^json_api::get_person>()),
                                 std::expected<person, trie::client_error>>);
    static_assert(std::is_same_v<decltype(std::declval<client_t&>().call<^^json_api::echo>(trie::json::value{})),
                                 std::expected<trie::json::value, trie::client_error>>);
  }
  return tst::report("json_route_test");
}
