// 03 — Typed JSON bodies, generated schema and validation hooks.
//
// [[=trie::body]] T deserializes the request body into T after validating it
// against a schema derived from T's reflected members; returning an aggregate
// serializes it back as application/json. Validation is configurable per server.
#include "trie/trie.hh"

#include <cstdio>
#include <expected>
#include <string>
#include <string_view>

// name has no default initializer -> required in JSON; age defaults -> optional.
struct person {
  std::string name;
  int age = 0;
};

struct json_api {
  [[=trie::post("/person")]] person bump_age([[=trie::body]] person value) {
    value.age += 1;
    return value;
  }
};

trie::http::request_view post(std::string_view body) {
  return trie::http::request_view::from_target(trie::method::post, "/person", {}, body);
}

void show(std::string_view label, trie::http::response const& response) {
  std::printf("%-42.*s -> %d  %s\n", static_cast<int>(label.size()), label.data(), response.status_code,
              response.body.c_str());
}

int main() {
  trie::server<json_api> server;

  // schema<T>() turns the same reflection metadata into JSON-Schema-like JSON.
  std::printf("schema<person>():\n%s\n", trie::json::dump(trie::json::schema<person>()).c_str());

  // Validation error hook: customize the response for any parse/schema/parameter
  // failure. Returning 200 is coerced to 400.
  server.on_validation_error([](trie::validation_failure const& failure, trie::http::context&) {
    trie::json::value error{};
    error["error"] = failure.message;
    error["type"] = std::string{failure.type_name};
    trie::http::response response{};
    response.status_code = 422;
    response.set_header("Content-Type", "application/json");
    response.body = trie::json::dump(error);
    return response;
  });

  // Extra body validator: runs after built-in schema validation, before the
  // JSON document is converted to person. Returning a message rejects with 400.
  server.on_body_validation([](trie::http::request_view const&, std::string_view,
                               trie::json::value const& body,
                               trie::http::context&) -> std::expected<void, std::string> {
    if (body.contains("age") && body["age"].get<int>() > 150) return std::unexpected("age must be <= 150");
    return {};
  });

  // Valid aggregate in, aggregate out; age defaulted, unknown fields rejected.
  show("valid body", server.dispatch(post(R"({"name":"bob","age":41})")));
  show("defaulted age (optional member)", server.dispatch(post(R"({"name":"carol"})")));
  show("missing required field 'name'", server.dispatch(post(R"({"age":1})")));
  show("malformed JSON", server.dispatch(post("{not json")));
  show("unknown field (strict by default)", server.dispatch(post(R"({"name":"x","extra":true})")));
  show("custom validator: age 200", server.dispatch(post(R"({"name":"old","age":200})")));

  // Schema strictness is a server-wide setting. Disable unknown-field rejection,
  // then require every member (including defaulted ones) to be present.
  server.set_validation_options(trie::json::validate_options{.reject_unknown = false});
  show("unknown field (reject_unknown = false)", server.dispatch(post(R"({"name":"x","extra":true})")));
  server.set_validation_options(trie::json::validate_options{.require_all = true});
  show("missing age (require_all = true)", server.dispatch(post(R"({"name":"x"})")));
  return 0;
}
