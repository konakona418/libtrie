#include "trie/trie.hh"

#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "harness.hh"

struct person {
  std::string name;
  int age = 0;
};

struct request_info {
  bool validated = false;
};

struct hook_api {
  [[=trie::post("/person")]] person echo([[=trie::body]] person value) { return value; }
};

struct tagging_middleware {
  trie::http::response operator()(trie::http::context& context, const trie::http::request_view& request,
                                  const trie::http::next& next) const {
    context.set<request_info>(request_info{});
    return next(context, request);
  }
};

trie::http::request_view person_request(std::string_view body) {
  return trie::http::request_view::from_target(trie::method::post, "/person", {}, body);
}

int main() {
  {
    // Custom body validator runs after schema validation and can use middleware context.
    trie::server<hook_api> server;
    server.use(tagging_middleware{});
    server.on_body_validation([](const trie::http::request_view&, std::string_view type_name,
                                 const trie::json::value& body, trie::http::context& context)
                                  -> std::expected<void, std::string> {
      auto* info = context.get<request_info>();
      if (info == nullptr) return std::unexpected("missing middleware context");
      info->validated = true;
      if (type_name.find("person") == std::string_view::npos) return std::unexpected("unexpected body type");
      if (body.contains("age") && body["age"].get<int>() > 150) return std::unexpected("age must be <= 150");
      return {};
    });

    auto response = server.dispatch(person_request(R"({"name":"old","age":200})"));
    CHECK_EQ(response.status_code, 400);
    CHECK_EQ(response.body, std::string{"age must be <= 150"});

    response = server.dispatch(person_request(R"({"name":"ok","age":20})"));
    CHECK_EQ(response.status_code, 200);
    CHECK_EQ(response.body, std::string{"{\"age\":20,\"name\":\"ok\"}"});
  }
  {
    // Validation error hook customizes the failure response (status, body, headers).
    trie::server<hook_api> server;
    server.on_validation_error([](const trie::validation_failure& failure, trie::http::context&) {
      trie::http::response response{};
      response.status_code = 422;
      response.set_header("Content-Type", "application/json");
      response.body = "{\"error\":\"" + failure.message + "\",\"type\":\"" + std::string(failure.type_name) + "\"}";
      return response;
    });

    auto response = server.dispatch(person_request(R"({"age":1})"));
    CHECK_EQ(response.status_code, 422);
    CHECK_EQ(response.header("content-type"), std::string_view{"application/json"});
    CHECK(response.body.find("missing required field") != std::string::npos);
    CHECK(response.body.find("person") != std::string::npos);

    response = server.dispatch(person_request("{bad json"));
    CHECK_EQ(response.status_code, 422);
    CHECK(response.body.find("\"error\":\"") != std::string::npos);

    // A hook returning a 200 response is coerced to 400.
    server.on_validation_error([](const trie::validation_failure&, trie::http::context&) {
      return trie::http::response{};
    });
    response = server.dispatch(person_request(R"({"age":1})"));
    CHECK_EQ(response.status_code, 400);
  }
  {
    // Schema strictness is configurable per server.
    trie::server<hook_api> server;
    server.set_validation_options(trie::json::validate_options{.reject_unknown = false, .require_all = false});

    auto response = server.dispatch(person_request(R"({"name":"x","extra":true})"));
    CHECK_EQ(response.status_code, 200);

    server.set_validation_options(trie::json::validate_options{.reject_unknown = true, .require_all = true});
    response = server.dispatch(person_request(R"({"name":"x"})"));
    CHECK_EQ(response.status_code, 400);
    CHECK(response.body.find("age") != std::string::npos);
  }
  {
    // Error hook also applies to plain parameter conversion failures.
    struct api2 {
      [[=trie::get("/value/{n}")]] int value(int n) { return n; }
    };
    trie::server<api2> server;
    server.on_validation_error([](const trie::validation_failure& failure, trie::http::context&) {
      trie::http::response response{};
      response.status_code = 400;
      response.body = "custom: " + failure.message;
      return response;
    });
    auto response = server.dispatch(trie::method::get, "/value/not-a-number");
    CHECK_EQ(response.status_code, 400);
    CHECK_EQ(response.body, std::string{"custom: bad request"});
  }
  return tst::report("schema_hook_test");
}
