#include "trie/trie.hh"

#include <array>
#include <optional>
#include <string>
#include <string_view>

#include "harness.hh"

struct users_api {
  [[=trie::get("/users/{id}")]] int get_user(int id, trie::http::response& response) {
    response.set_header("X-User", std::to_string(id));
    return id;
  }

  [[=trie::post("/users")]] void create_user([[=trie::body]] std::string_view body,
                                              trie::http::response& response) {
    response.set_status(trie::http::status::created);
    response.body.assign(body.data(), body.size());
  }

  [[=trie::get("/users/{id}/posts/{post}")]] std::string get_post(int id, std::string_view post) {
    return std::to_string(id) + ":" + std::string(post);
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

  [[=trie::get("/files/{name}")]] std::string file(std::string_view name) { return std::string(name); }

  [[=trie::get("/secure")]] std::string secure([[=trie::header("X-Token")]] std::string_view token) {
    return std::string(token);
  }

  [[=trie::get("/status")]] trie::http::status status_only() { return trie::http::status::no_content; }
};

struct admin_api {
  [[=trie::get("/admin/ping")]] std::string ping() { return "pong"; }

  [[=trie::del("/admin/users/{id}")]] int delete_user(int id) { return id; }
};

int main() {
  trie::server<users_api, admin_api> srv;

  {
    auto response = srv.dispatch(trie::method::get, "/users/42");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"42"});
    CHECK_EQ(response.header("x-user"), std::string_view{"42"});
  }
  {
    trie::http::request_view request =
        trie::http::request_view::from_target(trie::method::post, "/users", {}, "hello");
    auto response = srv.dispatch(request);
    CHECK_EQ(response.status_code, 201);
    CHECK_EQ(response.body, std::string{"hello"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/users/1/posts/2");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"1:2"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/search?q=hello%20world&limit=5");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"hello world:5"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/search?q=x");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"x"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/search");
    CHECK_EQ(response.status_code, 400);
  }
  {
    const std::array<trie::http::header_view, 1> headers{{{"X-Token", "secret"}}};
    auto request = trie::http::request_view::from_target(trie::method::get, "/secure", headers);
    auto response = srv.dispatch(request);
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"secret"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/secure");
    CHECK_EQ(response.status_code, 400);
  }
  {
    auto response = srv.dispatch(trie::method::get, "/files/a%2Fb%20c");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"a/b c"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/files/%zz");
    CHECK_EQ(response.status_code, 400);
  }
  {
    auto response = srv.dispatch(trie::method::get, "/users/not-a-number");
    CHECK_EQ(response.status_code, 400);
  }
  {
    auto response = srv.dispatch(trie::method::get, "/status");
    CHECK_EQ(response.status_code, 204);
  }
  {
    auto response = srv.dispatch(trie::method::get, "/admin/ping");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"pong"});
  }
  {
    auto response = srv.dispatch(trie::method::del, "/admin/users/7");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"7"});
  }
  {
    auto response = srv.dispatch(trie::method::post, "/users/42");
    CHECK_EQ(response.status_code, 405);
    CHECK_EQ(response.header("allow"), std::string_view{"GET"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/does/not/exist");
    CHECK_EQ(response.status_code, 404);
    CHECK_EQ(response.body, std::string{"not found"});
  }
  {
    auto response = srv.dispatch(trie::method::get, "/users/42/extra");
    CHECK_EQ(response.status_code, 404);
  }
  {
    // The controller instance is reachable, which is what allows stateful APIs.
    srv.controller<users_api>();
  }
  return tst::report("router_test");
}
