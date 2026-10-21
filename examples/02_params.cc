// 02 — Parameter binding: path, enum, query and header parameters.
//
// A pure router demo: dispatch() takes request views directly, so no socket is
// involved. Path parameters are inferred positionally, query/header parameters
// are named by their annotation, and all conversion failures become HTTP 400.
#include "trie/trie.hh"

#include <array>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

enum class color { red, green, blue };

struct params_api {
  // "42" is parsed into int; a non-numeric segment yields 400.
  [[=trie::get("/users/{id}")]] std::string user(int id) {
    return "user #" + std::to_string(id);
  }

  // Enums are matched against enumerator names ("green"); enum_name() maps a
  // value back to its reflected identifier.
  [[=trie::get("/colors/{c}")]] std::string color_path(color c) {
    return std::string(trie::enum_name(c));
  }

  // std::optional<T> makes a query parameter optional; without it a missing
  // parameter is a 400. Query values are percent-decoded before conversion.
  [[=trie::get("/search")]] std::string search([[=trie::query("q")]] std::string_view q,
                                               [[=trie::query("limit")]] std::optional<int> limit) {
    std::string out{q};
    if (limit) out += " (limit " + std::to_string(*limit) + ")";
    return out;
  }

  // Header lookup is case-insensitive; a missing header is a 400.
  [[=trie::get("/secure")]] std::string secure([[=trie::header("X-Token")]] std::string_view token) {
    return "token accepted: " + std::string(token);
  }
};

void show(std::string_view label, trie::http::response const& response) {
  std::printf("%-38.*s -> %d", static_cast<int>(label.size()), label.data(), response.status_code);
  if (!response.body.empty()) std::printf("  %s", response.body.c_str());
  if (auto allow = response.header("Allow"); !allow.empty())
    std::printf("  Allow: %.*s", static_cast<int>(allow.size()), allow.data());
  std::printf("\n");
}

int main() {
  trie::server<params_api> server;

  // Typed path parameter.
  show("GET /users/42", server.dispatch(trie::method::get, "/users/42"));

  // Enum path parameter, then the reflected name.
  show("GET /colors/green", server.dispatch(trie::method::get, "/colors/green"));

  // Optional query parameter present / absent, and a required one missing.
  show("GET /search?q=reflection&limit=5",
       server.dispatch(trie::method::get, "/search?q=reflection&limit=5"));
  show("GET /search?q=reflection", server.dispatch(trie::method::get, "/search?q=reflection"));
  show("GET /search (missing q)", server.dispatch(trie::method::get, "/search"));

  // Header parameter.
  const std::array<trie::http::header_view, 1> headers{{{"X-Token", "s3cret"}}};
  show("GET /secure (X-Token: s3cret)",
       server.dispatch(trie::http::request_view::from_target(trie::method::get, "/secure", headers)));
  show("GET /secure (no header)", server.dispatch(trie::method::get, "/secure"));

  // Router errors: 400 for a bad enum value, 405 + Allow for a wrong method,
  // and 404 for a path that does not exist.
  show("GET /colors/purple", server.dispatch(trie::method::get, "/colors/purple"));
  show("POST /users/42", server.dispatch(trie::method::post, "/users/42"));
  show("GET /does-not-exist", server.dispatch(trie::method::get, "/does-not-exist"));
  return 0;
}
