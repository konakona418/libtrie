#include "trie/trie.hh"

#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "harness.hh"

struct request_state {
  int value = 0;
  std::string user{};
};

struct api {
  [[=trie::get("/value")]] std::string value([[=trie::inject]] request_state& state) {
    return std::to_string(state.value);
  }

  [[=trie::get("/user")]] std::string user([[=trie::inject]] request_state const& state) {
    return state.user;
  }

  [[=trie::get("/counting")]] std::string counting([[=trie::inject]] request_state& state) {
    ++state.value;
    ++hits;
    return std::to_string(state.value);
  }

  int hits = 0;
};

struct state_middleware {
  int value = 7;

  trie::http::response operator()(trie::http::context& context, const trie::http::request_view& request,
                                  const trie::http::next& next) const {
    request_state state{};
    state.value = value;
    state.user = "alice";
    context.set<request_state>(std::move(state));
    auto response = next(context, request);
    response.set_header("X-Middleware", "state");
    return response;
  }
};

struct ref_middleware {
  request_state* state = nullptr;

  trie::http::response operator()(trie::http::context& context, const trie::http::request_view& request,
                                  const trie::http::next& next) const {
    context.set_ref(*state);
    return next(context, request);
  }
};

struct trace_middleware {
  std::vector<std::string>* order = nullptr;
  std::string name{};

  trie::http::response operator()(trie::http::context& context, const trie::http::request_view& request,
                                  const trie::http::next& next) const {
    order->push_back(name + ":before");
    auto response = next(context, request);
    order->push_back(name + ":after");
    return response;
  }
};

struct auth_middleware {
  std::string token{};

  trie::http::response operator()(trie::http::context& context, const trie::http::request_view& request,
                                  const trie::http::next& next) const {
    if (request.header("X-Token") != token) {
      trie::http::response response{};
      response.status_code = static_cast<int>(trie::http::status::unauthorized);
      response.body = "unauthorized";
      return response;
    }
    return next(context, request);
  }
};

int main() {
  {
    // No middleware: injecting a request context fails with 500.
    trie::server<api> server;
    auto response = server.dispatch(trie::method::get, "/value");
    CHECK_EQ(response.status_code, 500);
    CHECK_EQ(response.body, std::string{"missing request context"});
  }
  {
    trie::server<api> server;
    server.use(state_middleware{7});

    auto response = server.dispatch(trie::method::get, "/value");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"7"});
    CHECK_EQ(response.header("x-middleware"), std::string_view{"state"});

    response = server.dispatch(trie::method::get, "/user");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"alice"});
  }
  {
    // Middleware order: first installed is outermost.
    trie::server<api> server;
    std::vector<std::string> order;
    server.use(trace_middleware{&order, "outer"});
    server.use(trace_middleware{&order, "inner"});
    server.use(state_middleware{3});

    auto response = server.dispatch(trie::method::get, "/value");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"3"});
    CHECK_EQ(order.size(), std::size_t{4});
    CHECK_EQ(order[0], std::string{"outer:before"});
    CHECK_EQ(order[1], std::string{"inner:before"});
    CHECK_EQ(order[2], std::string{"inner:after"});
    CHECK_EQ(order[3], std::string{"outer:after"});
  }
  {
    // Short-circuit: a rejected request never reaches the handler or inner middleware.
    trie::server<api> server;
    std::vector<std::string> order;
    server.use(auth_middleware{"secret"});
    server.use(trace_middleware{&order, "inner"});
    server.use(state_middleware{1});

    auto response = server.dispatch(trie::method::get, "/counting");
    CHECK_EQ(response.status_code, 401);
    CHECK_EQ(response.body, std::string{"unauthorized"});
    CHECK(order.empty());
    CHECK_EQ(server.controller<api>().hits, 0);

    const std::array<trie::http::header_view, 1> headers{{{"X-Token", "secret"}}};
    response = server.dispatch(trie::http::request_view::from_target(trie::method::get, "/counting", headers));
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"2"});
    CHECK_EQ(server.controller<api>().hits, 1);
    CHECK_EQ(order.size(), std::size_t{2});
  }
  {
    // Borrowed context values via set_ref.
    trie::server<api> server;
    request_state external{};
    external.value = 99;
    server.use(ref_middleware{&external});

    auto response = server.dispatch(trie::method::get, "/value");
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"99"});
  }
  {
    // Adding middleware after a dispatch invalidates the cached chain.
    trie::server<api> server;
    server.use(state_middleware{5});
    CHECK_EQ(server.dispatch(trie::method::get, "/value").body, std::string{"5"});

    std::vector<std::string> order;
    server.use(trace_middleware{&order, "late"});
    CHECK_EQ(server.dispatch(trie::method::get, "/value").body, std::string{"5"});
    CHECK_EQ(order.size(), std::size_t{2});
  }
  {
    // 404/405 flow through middleware normally.
    trie::server<api> server;
    server.use(state_middleware{1});
    CHECK_EQ(server.dispatch(trie::method::get, "/missing").status_code, 404);
    CHECK_EQ(server.dispatch(trie::method::post, "/value").status_code, 405);
  }
  return tst::report("middleware_test");
}
