// 04 — Middleware: request-scoped context, auth short-circuit, ordering.
// Middleware = (context&, request_view const&, next const&) -> response; first use() outermost.
#include "trie/trie.hh"

#include <array>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

// Request-scoped state shared with handlers through [[=trie::inject]] T& params.
struct request_info {
  int number = 0;
  std::string user = "alice";
};

// Innermost middleware: stores a context value, adds a header after the handler.
struct counting_middleware {
  int count = 0;

  trie::http::response operator()(trie::http::context& context, trie::http::request_view const& request,
                                  trie::http::next const& next) {
    context.set<request_info>(request_info{++count, "alice"});
    auto response = next(context, request);
    response.set_header("X-Request-Number", std::to_string(count));
    return response;
  }
};

// Auth middleware: rejects without calling next(); inner middleware/handler skip.
struct auth_middleware {
  std::string_view token{};

  trie::http::response operator()(trie::http::context& context, trie::http::request_view const& request,
                                  trie::http::next const& next) const {
    if (request.header("X-Token") != token) {
      trie::http::response response{};
      response.status_code = static_cast<int>(trie::http::status::unauthorized);
      response.body = "unauthorized";
      return response;
    }
    return next(context, request);
  }
};

// Records the before/after traversal so middleware order is visible.
struct trace_middleware {
  std::vector<std::string>* order = nullptr;
  std::string name{};

  trie::http::response operator()(trie::http::context& context, trie::http::request_view const& request,
                                  trie::http::next const& next) const {
    order->push_back(name + ":before");
    auto response = next(context, request);
    order->push_back(name + ":after");
    return response;
  }
};

struct middleware_api {
  [[=trie::get("/whoami")]] std::string whoami([[=trie::inject]] request_info const& info) {
    ++hits;
    return "user=" + info.user + " request=" + std::to_string(info.number);
  }

  [[=trie::get("/number/{n}")]] int number(int n) {
    ++hits;
    return n * 2;
  }

  int hits = 0;
};

void show(std::string_view label, trie::http::response const& response) {
  std::printf("%-30.*s -> %d  %s", static_cast<int>(label.size()), label.data(), response.status_code,
              response.body.c_str());
  if (auto number = response.header("X-Request-Number"); !number.empty())
    std::printf("  X-Request-Number: %.*s", static_cast<int>(number.size()), number.data());
  std::printf("\n");
}

void show_order(std::vector<std::string> const& order) {
  std::printf("  order:");
  for (auto const& step : order) std::printf(" %s", step.c_str());
  std::printf("\n");
}

int main() {
  trie::server<middleware_api> server;
  std::vector<std::string> order;
  server.use(trace_middleware{&order, "outer"}); // first use = outermost
  server.use(auth_middleware{"secret"});
  server.use(trace_middleware{&order, "inner"});
  server.use(counting_middleware{}); // innermost: injects the context value

  const std::array<trie::http::header_view, 1> token{{{"X-Token", "secret"}}};

  // Authorized: outer -> auth -> inner -> counting -> handler, then unwind.
  show("GET /whoami (valid token)",
       server.dispatch(trie::http::request_view::from_target(trie::method::get, "/whoami", token)));
  show_order(order);

  // Rejected: auth short-circuits, so "inner" and the handler never run (hits
  // stays 1) while the response still passes back through "outer".
  order.clear();
  show("GET /whoami (no token)", server.dispatch(trie::method::get, "/whoami"));
  show_order(order);
  std::printf("handler hits: %d\n", server.controller<middleware_api>().hits);

  // A server-level error hook customizes any validation/conversion failure.
  trie::server<middleware_api> hooked;
  hooked.on_validation_error([](trie::validation_failure const& failure, trie::http::context&) {
    trie::http::response response{};
    response.status_code = static_cast<int>(trie::http::status::bad_request);
    response.body = "invalid request: " + failure.message;
    return response;
  });
  show("GET /number/oops", hooked.dispatch(trie::method::get, "/number/oops"));
  return 0;
}
