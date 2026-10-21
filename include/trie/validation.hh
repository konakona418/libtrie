#pragma once

#include <expected>
#include <functional>
#include <string>
#include <string_view>

#include "trie/error.hh"
#include "trie/http/context.hh"
#include "trie/http.hh"
#include "trie/json.hh"

namespace trie {

// Information about a failed request-body validation. `type_name` is the
// reflected C++ type of the body parameter (for schema/conversion failures) and
// may be empty for plain request errors such as malformed path parameters.
struct validation_failure {
  std::string message{};
  std::string_view type_name{};
  const http::request_view* request = nullptr;
};

// Customizes the response produced when request validation fails. Returning a
// response with status 200 is coerced to 400.
using validation_error_handler = std::function<http::response(const validation_failure&, http::context&)>;

// Extra body validation running after the built-in schema validation, before
// the JSON value is converted to the C++ type. Return an error message to
// reject the request with 400.
using body_validation_handler =
    std::function<std::expected<void, std::string>(const http::request_view&, std::string_view type_name,
                                                   const json::value&, http::context&)>;

struct validation_hooks {
  json::validate_options schema_options{};
  body_validation_handler body{};
  validation_error_handler error{};
};

} // namespace trie
