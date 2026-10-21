#pragma once

#include <array>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include "trie/detail/reflect.hh"
#include "trie/http.hh"

namespace trie {

struct client_error {
  int status = 0;
  std::string message{};
};

namespace detail {

struct serialized_arg {
  std::string text{};
  bool present = true;
};

template <class T>
consteval bool is_text_body() {
  using U = std::remove_cvref_t<T>;
  if constexpr (is_optional_v<U>) {
    return is_text_body<typename is_optional<U>::value_type>();
  } else {
    return is_string_like<U>();
  }
}

template <std::meta::info Fn, std::size_t J, class Arg>
serialized_arg serialize_one(Arg&& arg) {
  constexpr std::size_t param = param_index_for_arg<Fn, J>();
  using P = param_type_t<Fn, param>;
  using U = std::remove_cvref_t<P>;
  static_assert(!std::is_reference_v<P>, "client-callable handler parameters must be values");
  P value = static_cast<P>(std::forward<Arg>(arg));

  if constexpr (kind_of<Fn, param>() == param_kind::body) {
    if constexpr (is_text_body<U>()) {
      if constexpr (is_optional_v<U>) {
        if (!value.has_value()) return serialized_arg{"", false};
        return serialized_arg{value_to_text<typename is_optional<U>::value_type>(*value), true};
      } else {
        return serialized_arg{value_to_text<U>(value), true};
      }
    } else if constexpr (json::serializable<U>()) {
      if constexpr (is_optional_v<U>) {
        if (!value.has_value()) return serialized_arg{"", false};
        return serialized_arg{json::dump(json::to_json(*value)), true};
      } else {
        return serialized_arg{json::dump(json::to_json(value)), true};
      }
    } else {
      static_assert(always_false_v<U>, "unsupported JSON body argument type");
    }
  } else if constexpr (is_optional_v<U>) {
    if (!value.has_value()) return serialized_arg{"", false};
    return serialized_arg{value_to_text<typename is_optional<U>::value_type>(*value), true};
  } else {
    return serialized_arg{value_to_text<U>(value), true};
  }
}

template <std::meta::info Fn, class... Args, std::size_t... Js>
auto serialize_args_impl(std::index_sequence<Js...>, Args&&... args) {
  return std::array<serialized_arg, sizeof...(Js)>{serialize_one<Fn, Js>(std::forward<Args>(args))...};
}

template <std::meta::info Fn, std::size_t J, class Arg>
consteval bool one_arg_ok() {
  constexpr std::size_t param = param_index_for_arg<Fn, J>();
  using P = param_type_t<Fn, param>;
  return !std::is_reference_v<P> && std::is_convertible_v<Arg&&, P>;
}

template <std::meta::info Fn, class... Args, std::size_t... Js>
consteval bool call_args_ok_impl(std::index_sequence<Js...>, std::type_identity<std::tuple<Args...>>) {
  return (one_arg_ok<Fn, Js, Args>() && ... && true);
}

template <std::meta::info Fn, class... Args>
consteval bool call_args_ok() {
  return call_args_ok_impl<Fn>(std::index_sequence_for<Args...>{}, std::type_identity<std::tuple<Args...>>{});
}

template <std::meta::info Fn>
void append_path(std::string& target, std::span<const serialized_arg> values) {
  static constexpr auto annotation = route_annotation<Fn>();
  static constexpr auto path_arguments = path_args<Fn>();
  std::string_view pattern{annotation.path.data()};
  std::size_t placeholder = 0;
  for (std::size_t i = 0; i < pattern.size(); ++i) {
    if (pattern[i] != '{') {
      target.push_back(pattern[i]);
      continue;
    }
    auto end = pattern.find('}', i);
    if (end == std::string_view::npos) break;
    std::size_t argument = path_arguments[placeholder++];
    target += url_encode(values[argument].text);
    i = end;
  }
}

template <std::meta::info Fn, std::size_t I>
void append_parameter(http::request& request, std::string& query, std::span<const serialized_arg> values) {
  constexpr param_kind kind = kind_of<Fn, I>();
  if constexpr (kind == param_kind::query || kind == param_kind::header) {
    constexpr std::size_t argument = arg_index_for_param<Fn, I>();
    constexpr auto name = param_name<Fn, I>();
    if (!values[argument].present) return;
    std::string_view key{name.data()};
    if constexpr (kind == param_kind::query) {
      if (!query.empty()) query += '&';
      query += key;
      query += '=';
      query += url_encode(values[argument].text);
    } else {
      request.headers.emplace_back(std::string(key), values[argument].text);
    }
  } else if constexpr (kind == param_kind::body) {
    constexpr std::size_t argument = arg_index_for_param<Fn, I>();
    request.body = values[argument].text;
  }
}

template <std::meta::info Fn, std::size_t... Is>
void append_parameters_impl(http::request& request, std::string& query,
                            [[maybe_unused]] std::span<const serialized_arg> values,
                            std::index_sequence<Is...>) {
  (append_parameter<Fn, Is>(request, query, values), ...);
}

template <std::meta::info Fn>
void append_parameters(http::request& request, std::string& query, std::span<const serialized_arg> values) {
  append_parameters_impl<Fn>(request, query, values, std::make_index_sequence<param_count<Fn>()>{});
}

template <class R>
using client_value_t = std::conditional_t<
    std::is_void_v<R>, void,
    std::conditional_t<std::is_same_v<std::remove_cvref_t<R>, std::string_view> ||
                           std::is_same_v<std::remove_cvref_t<R>, const char*>,
                       std::string, std::remove_cvref_t<R>>>;

template <class R>
using client_result_t = std::expected<client_value_t<R>, client_error>;

template <class R>
client_result_t<R> make_client_result(std::expected<http::response, client_error> sent) {
  if (!sent) return std::unexpected(std::move(sent.error()));
  http::response& response = *sent;
  if (response.status_code < 200 || response.status_code >= 300)
    return std::unexpected(client_error{response.status_code, response.body});

  using V = client_value_t<R>;
  if constexpr (std::is_void_v<V>) {
    return {};
  } else if constexpr (std::is_same_v<V, std::string>) {
    return std::move(response.body);
  } else if constexpr (std::is_same_v<V, http::status>) {
    return static_cast<http::status>(response.status_code);
  } else if constexpr (std::is_integral_v<V> || std::is_floating_point_v<V>) {
    bool ok = true;
    V value = parse_value<V>(response.body, ok);
    if (!ok) return std::unexpected(client_error{0, "invalid response body"});
    return value;
  } else if constexpr (std::is_same_v<V, json::value>) {
    auto parsed = json::parse(response.body);
    if (!parsed) return std::unexpected(client_error{0, parsed.error().message});
    return *std::move(parsed);
  } else if constexpr (json::serializable<V>()) {
    auto parsed = json::parse_as<V>(response.body);
    if (!parsed) return std::unexpected(client_error{0, parsed.error().message});
    return *std::move(parsed);
  } else {
    static_assert(always_false_v<V>, "unsupported client return type");
  }
}

} // namespace detail

// Type-safe client: the route, its method and its path template come from the
// handler's reflection, and the argument/return types come from its signature.
//
//   struct api { [[=trie::get("/users/{id}")]] int user(int id); };
//   trie::client<api, mock_transport> client{transport};
//   auto result = client.call<^^api::user>(42);  // expected<int, client_error>
template <class Api, class Transport>
class client {
  static_assert(std::is_class_v<Api>, "trie::client needs the reflected controller type as its first argument");

public:
  explicit client(Transport transport = {}) : transport_(std::move(transport)) {}

  template <std::meta::info Fn, class... Args>
  auto call(Args&&... args) -> detail::client_result_t<detail::return_type_t<Fn>> {
    static_assert(std::meta::is_function(Fn), "trie::client::call expects a member function reflection");
    static_assert(std::meta::parent_of(Fn) == ^^Api, "handler does not belong to the client's Api type");
    static_assert(detail::route_ok<Fn>(), "handler signature is not usable as a route");
    static_assert(sizeof...(Args) == detail::explicit_param_count<Fn>(),
                  "trie::client::call needs exactly the handler's non-context parameters");
    static_assert(detail::call_args_ok<Fn, Args...>(),
                  "trie::client::call argument types do not match the handler parameters");

    static constexpr auto annotation = detail::route_annotation<Fn>();

    http::request request{};
    request.m = annotation.m; // NOLINT(bugprone-unused-local-non-trivial-variable)

    auto values = detail::serialize_args_impl<Fn>(std::index_sequence_for<Args...>{}, std::forward<Args>(args)...);
    std::string target;
    detail::append_path<Fn>(target, values);

    std::string query;
    detail::append_parameters<Fn>(request, query, values);
    if (!query.empty()) {
      target += '?';
      target += query;
    }
    request.target = std::move(target);

    return detail::make_client_result<detail::return_type_t<Fn>>(transport_.send(std::move(request)));
  }

  Transport& transport() { return transport_; }
  Transport const& transport() const { return transport_; }

private:
  Transport transport_{};
};

} // namespace trie
