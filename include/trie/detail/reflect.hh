#pragma once

#include <array>
#include <cstddef>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <meta>

#include "trie/annotations.hh"
#include "trie/detail/enum.hh"
#include "trie/http.hh"
#include "trie/json.hh"

namespace trie::detail {

template <class>
inline constexpr bool always_false_v = false;

inline constexpr std::size_t max_handler_params = 12;

// ---------------------------------------------------------------------------
// Reflection entry points
// ---------------------------------------------------------------------------

// Declared members of a controller. Note that `members_of` also reports the
// implicit special member functions, so everything below filters those out.
template <class C>
inline constexpr auto member_list = std::define_static_array(
    std::meta::members_of(^^C, std::meta::access_context::unprivileged()));

consteval bool is_special_or_non_function(std::meta::info m) {
  return !std::meta::is_function(m) || std::meta::is_special_member_function(m);
}

consteval bool is_route_annotation(std::meta::info a) {
  return std::meta::remove_const(std::meta::type_of(a)) == ^^route;
}

consteval bool is_route_member(std::meta::info m) {
  if (is_special_or_non_function(m)) return false;
  for (auto a : std::meta::annotations_of(m))
    if (is_route_annotation(a)) return true;
  return false;
}

template <class C>
consteval std::size_t route_count() {
  std::size_t n = 0;
  for (auto m : member_list<C>) {
    if (is_special_or_non_function(m)) continue;
    for (auto a : std::meta::annotations_of(m))
      if (is_route_annotation(a)) ++n;
  }
  return n;
}

// ---------------------------------------------------------------------------
// Route collection
// ---------------------------------------------------------------------------

struct route_entry {
  method m;
  bool valid;
  int ctrl;
  int fn;
  std::array<char, route_path_capacity> path;
};

template <class C, std::size_t Ctrl>
consteval auto collect_controller() {
  std::array<route_entry, route_count<C>()> out{};
  std::size_t i = 0;
  std::size_t fn = 0;
  template for (constexpr auto mem : member_list<C>) {
    if constexpr (!is_special_or_non_function(mem)) {
      template for (constexpr auto a : std::define_static_array(std::meta::annotations_of(mem))) {
        if constexpr (is_route_annotation(a)) {
          constexpr auto rt = std::meta::extract<route>(a);
          out[i++] = route_entry{rt.m, rt.valid, static_cast<int>(Ctrl), static_cast<int>(fn), rt.path};
        }
      }
      ++fn;
    }
  }
  return out;
}

template <class C, std::size_t Ctrl, class Alloc>
consteval void append_routes(Alloc& out, std::size_t& idx) {
  constexpr auto local = collect_controller<C, Ctrl>();
  for (std::size_t i = 0; i < local.size(); ++i) out[idx++] = local[i];
}

template <class... Cs, std::size_t... Is>
consteval auto collect_all_impl(std::index_sequence<Is...>) {
  constexpr std::size_t total = (route_count<Cs>() + ... + std::size_t{0});
  std::array<route_entry, total> out{};
  std::size_t idx = 0;
  (append_routes<Cs, Is>(out, idx), ...);
  return out;
}

template <class... Cs>
consteval auto collect_all() {
  return collect_all_impl<Cs...>(std::make_index_sequence<sizeof...(Cs)>{});
}

// Reflection of the FnIdx-th (non-special) member function of C. Kept as a
// consteval function because arrays of `std::meta::info` cannot be used as
// template arguments in GCC 16.
template <class C, std::size_t FnIdx>
consteval std::meta::info handler_info() {
  std::meta::info out = ^^void;
  std::size_t i = 0;
  template for (constexpr auto mem : member_list<C>) {
    if constexpr (!is_special_or_non_function(mem)) {
      if (i == FnIdx) out = mem;
      ++i;
    }
  }
  return out;
}

struct route_target {
  int ctrl;
  int fn;
};

template <class C, std::size_t FnIdx>
inline constexpr std::meta::info handler_info_v = handler_info<C, FnIdx>();

// The `route` annotation of a handler, as a plain compile-time value.
template <std::meta::info Fn>
consteval route route_annotation() {
  route out = trie::get("/");
  template for (constexpr auto a : std::define_static_array(std::meta::annotations_of(Fn))) {
    if constexpr (is_route_annotation(a)) out = std::meta::extract<route>(a);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Handler parameter classification
// ---------------------------------------------------------------------------

enum class param_kind : unsigned char { request, response, context, path, query, header, body };

template <class>
struct is_optional : std::false_type {};
template <class T>
struct is_optional<std::optional<T>> : std::true_type {
  using value_type = T;
};

template <class T>
inline constexpr bool is_optional_v = is_optional<std::remove_cvref_t<T>>::value;

template <class T>
consteval bool is_parseable() {
  using U = std::remove_cvref_t<T>;
  if constexpr (is_optional_v<U>) {
    return is_parseable<typename is_optional<U>::value_type>();
  } else if constexpr (std::is_same_v<U, std::string> || std::is_same_v<U, std::string_view>) {
    return true;
  } else if constexpr (std::is_same_v<U, bool>) {
    return true;
  } else if constexpr (std::is_integral_v<U> || std::is_floating_point_v<U>) {
    return true;
  } else if constexpr (std::is_enum_v<U>) {
    return true;
  } else {
    return false;
  }
}

template <class T>
consteval bool is_string_like() {
  using U = std::remove_cvref_t<T>;
  return std::is_same_v<U, std::string> || std::is_same_v<U, std::string_view> ||
         std::is_same_v<U, const char*>;
}

template <std::meta::info Fn, std::size_t I>
using param_type_t = typename [:std::meta::type_of(std::meta::parameters_of(Fn)[I]):];

template <std::meta::info Fn>
using return_type_t = typename [:std::meta::return_type_of(Fn):];

struct param_desc {
  param_kind kind = param_kind::path;
  std::array<char, annotation_name_capacity> name{};
  bool valid = true;
};

template <std::meta::info Fn, std::size_t I>
consteval param_desc describe_param() {
  using T = param_type_t<Fn, I>;
  using U = std::remove_cvref_t<T>;
  param_desc d{};
  if constexpr (std::is_same_v<U, http::request_view>) {
    d.kind = param_kind::request;
  } else if constexpr (std::is_same_v<U, http::response>) {
    d.kind = param_kind::response;
  } else {
    template for (constexpr auto a :
                  std::define_static_array(std::meta::annotations_of(std::meta::parameters_of(Fn)[I]))) {
      constexpr auto ty = std::meta::remove_const(std::meta::type_of(a));
      if constexpr (ty == ^^query_t) {
        constexpr auto q = std::meta::extract<query_t>(a);
        d.kind = param_kind::query;
        d.name = q.name;
        d.valid = q.valid;
      } else if constexpr (ty == ^^header_t) {
        constexpr auto h = std::meta::extract<header_t>(a);
        d.kind = param_kind::header;
        d.name = h.name;
        d.valid = h.valid;
      } else if constexpr (ty == ^^body_t) {
        d.kind = param_kind::body;
      } else if constexpr (ty == ^^inject_t) {
        d.kind = param_kind::context;
      } else if constexpr (ty == ^^from_path_t) {
        d.kind = param_kind::path;
      }
    }
  }
  return d;
}

template <std::meta::info Fn, std::size_t I>
consteval param_kind kind_of() {
  return describe_param<Fn, I>().kind;
}

template <std::meta::info Fn, std::size_t I>
consteval std::array<char, annotation_name_capacity> param_name() {
  return describe_param<Fn, I>().name;
}

template <std::meta::info Fn>
consteval std::size_t param_count() {
  return std::meta::parameters_of(Fn).size();
}

template <std::meta::info Fn, std::size_t... Is>
consteval std::size_t count_kind_impl([[maybe_unused]] param_kind k, std::index_sequence<Is...>) {
  return (std::size_t{0} + ... + (kind_of<Fn, Is>() == k ? std::size_t{1} : std::size_t{0}));
}

template <std::meta::info Fn>
consteval std::size_t count_kind(param_kind k) {
  return count_kind_impl<Fn>(k, std::make_index_sequence<param_count<Fn>()>{});
}

template <std::meta::info Fn, std::size_t I>
consteval bool is_context_param() {
  constexpr auto k = kind_of<Fn, I>();
  return k == param_kind::request || k == param_kind::response || k == param_kind::context;
}

template <std::meta::info Fn, std::size_t... Js>
consteval std::size_t count_context_before(std::index_sequence<Js...>) {
  return (std::size_t{0} + ... + (is_context_param<Fn, Js>() ? std::size_t{0} : std::size_t{1}));
}

// Position of parameter I among the parameters a client passes explicitly.
template <std::meta::info Fn, std::size_t I>
consteval std::size_t arg_index_for_param() {
  return count_context_before<Fn>(std::make_index_sequence<I>{});
}

template <std::meta::info Fn, std::size_t J, std::size_t... Is>
consteval std::size_t param_index_for_arg_impl(std::index_sequence<Is...>) {
  std::size_t found = max_handler_params;
  ((arg_index_for_param<Fn, Is>() == J ? found = Is : found), ...);
  return found;
}

template <std::meta::info Fn, std::size_t J>
consteval std::size_t param_index_for_arg() {
  return param_index_for_arg_impl<Fn, J>(std::make_index_sequence<param_count<Fn>()>{});
}

template <std::meta::info Fn>
consteval std::size_t explicit_param_count() {
  return param_count<Fn>() - count_kind<Fn>(param_kind::request) - count_kind<Fn>(param_kind::response);
}

// Argument ordinals (among explicit client arguments) of the path parameters,
// in path order.
template <std::meta::info Fn, std::size_t... Is>
consteval void append_path_args(std::array<std::size_t, max_handler_params>& out, std::size_t& n,
                                std::index_sequence<Is...>) {
  ((kind_of<Fn, Is>() == param_kind::path ? (out[n++] = arg_index_for_param<Fn, Is>()) : std::size_t{0}), ...);
}

template <std::meta::info Fn>
consteval std::array<std::size_t, max_handler_params> path_args() {
  std::array<std::size_t, max_handler_params> out{};
  std::size_t n = 0;
  append_path_args<Fn>(out, n, std::make_index_sequence<param_count<Fn>()>{});
  return out;
}

// ---------------------------------------------------------------------------
// Static validation
// ---------------------------------------------------------------------------

consteval bool is_wildcard_segment(std::string_view s) {
  return s.size() >= 3 && s.front() == '{' && s.back() == '}';
}

consteval std::size_t count_placeholders(std::string_view path) {
  std::size_t n = 0;
  while (!path.empty()) {
    while (!path.empty() && path.front() == '/') path.remove_prefix(1);
    if (path.empty()) break;
    auto slash = path.find('/');
    std::string_view seg = path.substr(0, slash);
    if (is_wildcard_segment(seg)) ++n;
    path = slash == std::string_view::npos ? std::string_view{} : path.substr(slash + 1);
  }
  return n;
}

template <std::meta::info Fn, std::size_t I>
consteval bool param_ok() {
  using T = param_type_t<Fn, I>;
  using U = std::remove_cvref_t<T>;
  constexpr auto d = describe_param<Fn, I>();
  if constexpr (d.kind == param_kind::request || d.kind == param_kind::response) {
    return true;
  } else if constexpr (d.kind == param_kind::context) {
    return std::is_lvalue_reference_v<T>;
  } else if constexpr (std::is_reference_v<T>) {
    return false;
  } else {
    if (!d.valid) return false;
    if constexpr (d.kind == param_kind::body) {
      return is_string_like<U>() ||
             (json::serializable<U>() && !json::borrows_parsed_storage<U>());
    } else {
      return is_parseable<U>();
    }
  }
}

template <std::meta::info Fn, std::size_t... Is>
consteval bool params_ok_impl(std::index_sequence<Is...>) {
  return (param_ok<Fn, Is>() && ... && true);
}

template <std::meta::info Fn>
consteval bool params_ok() {
  return params_ok_impl<Fn>(std::make_index_sequence<param_count<Fn>()>{});
}

template <std::meta::info Fn>
consteval bool return_ok() {
  using R = std::remove_cvref_t<return_type_t<Fn>>;
  if constexpr (std::is_void_v<R>) return true;
  else if constexpr (std::is_same_v<R, http::status>) return true;
  else if constexpr (is_string_like<R>()) return true;
  else if constexpr (std::is_integral_v<R> || std::is_floating_point_v<R>) return true;
  else if constexpr (std::is_same_v<R, json::value>) return true;
  else if constexpr (json::serializable<R>() && !json::borrows_parsed_storage<R>()) return true;
  else return false;
}

template <std::meta::info Fn>
consteval bool route_annotation_ok() {
  constexpr auto rt = route_annotation<Fn>();
  if (!rt.valid) return false;
  std::string_view path{rt.path.data()};
  if (path.empty() || path.front() != '/') return false;
  return count_placeholders(path) == count_kind<Fn>(param_kind::path);
}

template <std::meta::info Fn>
consteval bool handler_signature_ok() {
  if (count_kind<Fn>(param_kind::body) > 1) return false;
  if (!params_ok<Fn>()) return false;
  return return_ok<Fn>();
}

template <std::meta::info Fn>
consteval bool route_ok() {
  return route_annotation_ok<Fn>() && handler_signature_ok<Fn>();
}

template <class C>
consteval bool controller_annotations_ok() {
  bool ok = true;
  template for (constexpr auto mem : member_list<C>) {
    if constexpr (!is_special_or_non_function(mem)) {
      if constexpr (is_route_member(mem)) {
        if (!route_annotation_ok<mem>()) ok = false;
      }
    }
  }
  return ok;
}

template <class C>
consteval bool controller_signatures_ok() {
  bool ok = true;
  template for (constexpr auto mem : member_list<C>) {
    if constexpr (!is_special_or_non_function(mem)) {
      if constexpr (is_route_member(mem)) {
        if (!handler_signature_ok<mem>()) ok = false;
      }
    }
  }
  return ok;
}

template <class... Cs>
consteval bool routes_unique() {
  constexpr auto routes = collect_all<Cs...>();
  for (std::size_t i = 0; i < routes.size(); ++i)
    for (std::size_t j = i + 1; j < routes.size(); ++j)
      if (routes[i].m == routes[j].m &&
          std::string_view{routes[i].path.data()} == std::string_view{routes[j].path.data()})
        return false;
  return true;
}



template <class... Cs>
consteval bool routes_have_arity() {
  constexpr auto routes = collect_all<Cs...>();
  for (auto const& r : routes)
    if (!r.valid) return false;
  return true;
}

template <class T>
std::string value_to_text(T const& value) {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, std::string>) {
    return value;
  } else if constexpr (std::is_same_v<U, std::string_view>) {
    return std::string(value);
  } else if constexpr (std::is_same_v<U, const char*>) {
    return value != nullptr ? std::string(value) : std::string{};
  } else if constexpr (std::is_same_v<U, bool>) {
    return value ? "true" : "false";
  } else if constexpr (std::is_integral_v<U> || std::is_floating_point_v<U>) {
    std::array<char, 64> buffer{};
    auto [ptr, ec] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    if (ec != std::errc{}) return {};
    return std::string(buffer.data(), static_cast<std::size_t>(ptr - buffer.data()));
  } else if constexpr (std::is_enum_v<U>) {
    if (auto name = trie::enum_name(value); !name.empty()) return std::string(name);
    using underlying = std::underlying_type_t<U>;
    std::array<char, 64> buffer{};
    auto [ptr, ec] = std::to_chars(buffer.data(), buffer.data() + buffer.size(),
                                  static_cast<underlying>(value));
    if (ec != std::errc{}) return {};
    return std::string(buffer.data(), static_cast<std::size_t>(ptr - buffer.data()));
  } else {
    static_assert(always_false_v<U>, "unsupported value type");
  }
}

template <class T>
constexpr T parse_value(std::string_view s, bool& ok) {
  using U = std::remove_cvref_t<T>;
  ok = true;
  if constexpr (std::is_same_v<U, std::string>) {
    return std::string(s);
  } else if constexpr (std::is_same_v<U, std::string_view>) {
    return s;
  } else if constexpr (std::is_same_v<U, bool>) {
    if (s == "1" || s == "true") return true;
    if (s == "0" || s == "false") return false;
    ok = false;
    return false;
  } else if constexpr (std::is_integral_v<U>) {
    U value{};
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    ok = ec == std::errc{} && ptr == s.data() + s.size();
    return value;
  } else if constexpr (std::is_floating_point_v<U>) {
    U value{};
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    ok = ec == std::errc{} && ptr == s.data() + s.size();
    return value;
  } else if constexpr (std::is_enum_v<U>) {
    if (auto named = trie::enum_from_name<U>(s)) return *named;
    using underlying = std::underlying_type_t<U>;
    underlying raw{};
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), raw);
    ok = ec == std::errc{} && ptr == s.data() + s.size();
    return static_cast<U>(raw);
  } else {
    static_assert(always_false_v<U>, "unsupported handler parameter type");
  }
}


template <class Controllers>
struct controller_set;

template <class... Cs>
struct controller_set<std::tuple<Cs...>> {
  static consteval auto routes() { return collect_all<Cs...>(); }
  static consteval bool valid() {
    return (controller_annotations_ok<Cs>() && ... && true) && (controller_signatures_ok<Cs>() && ... && true) &&
           routes_unique<Cs...>();
  }
  static consteval bool annotations_ok() { return (controller_annotations_ok<Cs>() && ... && true); }
  static consteval bool signatures_ok() { return (controller_signatures_ok<Cs>() && ... && true); }
  static consteval bool unique() { return routes_unique<Cs...>(); }
  static consteval bool arity_ok() { return routes_have_arity<Cs...>(); }
};

template <class Controllers>
inline constexpr auto route_table_v = controller_set<Controllers>::routes();

template <class Controllers, method M>
consteval bool method_present() {
  constexpr auto const& routes = route_table_v<Controllers>;
  for (auto const& route : routes)
    if (route.m == M) return true;
  return false;
}

template <class Controllers, std::size_t RouteId>
consteval route_target target_of() {
  constexpr auto const& routes = route_table_v<Controllers>;
  return route_target{routes[RouteId].ctrl, routes[RouteId].fn};
}

} // namespace trie::detail
