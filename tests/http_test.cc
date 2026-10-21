#include "trie/http.hh"

#include <array>
#include <string_view>
#include <vector>

#include "harness.hh"

int main() {
  {
    auto view = trie::http::request_view::from_target(trie::method::get, "/users/42?q=hello%20world&limit=5");
    CHECK_EQ(view.m, trie::method::get);
    CHECK_EQ(view.path, std::string_view{"/users/42"});
    CHECK_EQ(view.query, std::string_view{"q=hello%20world&limit=5"});
    CHECK_EQ(view.query_param("q"), std::string_view{"hello%20world"});
    CHECK_EQ(view.query_param("limit"), std::string_view{"5"});
    CHECK(!view.has_query_param("nope"));
    CHECK(view.has_query_param("limit"));
  }
  {
    auto view = trie::http::request_view::from_target(trie::method::post, "/plain");
    CHECK_EQ(view.path, std::string_view{"/plain"});
    CHECK(view.query.empty());
  }
  {
    const std::array<trie::http::header_view, 2> headers{{{"Content-Type", "application/json"},
                                                          {"X-Token", "secret"}}};
    auto view = trie::http::request_view::from_target(trie::method::get, "/", headers, "body");
    CHECK_EQ(view.header("content-type"), std::string_view{"application/json"});
    CHECK_EQ(view.header("X-TOKEN"), std::string_view{"secret"});
    CHECK(view.has_header("x-token"));
    CHECK(!view.has_header("x-missing"));
    CHECK_EQ(view.body, std::string_view{"body"});
  }
  {
    trie::http::request request{};
    request.m = trie::method::put;
    request.target = "/items/7?verbose=1";
    request.headers.emplace_back("Accept", "text/plain");
    request.body = "payload";
    std::vector<trie::http::header_view> scratch;
    auto view = request.view(scratch);
    CHECK_EQ(view.m, trie::method::put);
    CHECK_EQ(view.path, std::string_view{"/items/7"});
    CHECK_EQ(view.query_param("verbose"), std::string_view{"1"});
    CHECK_EQ(view.header("accept"), std::string_view{"text/plain"});
    CHECK_EQ(view.body, std::string_view{"payload"});
  }
  {
    trie::http::response response{};
    response.set_status(trie::http::status::created);
    response.set_header("X-Test", "yes");
    response.body = "done";
    CHECK_EQ(response.status_code, 201);
    CHECK_EQ(response.header("x-test"), std::string_view{"yes"});
    CHECK_EQ(trie::http::iequals("AbC", "aBc"), true);
  }
  return tst::report("http_test");
}
