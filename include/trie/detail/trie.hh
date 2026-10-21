#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "trie/detail/reflect.hh"

namespace trie::detail {

// ---------------------------------------------------------------------------
// Compile-time routing trie
// ---------------------------------------------------------------------------

inline constexpr std::size_t segment_capacity = 24;

struct node {
  int parent = -2; // -2 marks an unused slot
  int self = -1;
  bool wildcard = false;
  unsigned char method_mask = 0;
  std::array<char, segment_capacity> segment{};
  std::array<int, method_count> handlers{};

  constexpr node() { handlers.fill(-1); }
};

consteval node make_node(int parent, int self, bool wildcard, std::string_view segment) {
  node n{};
  n.parent = parent;
  n.self = self;
  n.wildcard = wildcard;
  for (std::size_t i = 0; i < segment.size() && i + 1 < n.segment.size(); ++i)
    n.segment[i] = segment[i];
  return n;
}

consteval std::size_t count_segments(std::string_view path) {
  std::size_t n = 0;
  while (!path.empty()) {
    while (!path.empty() && path.front() == '/') path.remove_prefix(1);
    if (path.empty()) break;
    auto slash = path.find('/');
    path = slash == std::string_view::npos ? std::string_view{} : path.substr(slash + 1);
    ++n;
  }
  return n;
}

template <class... Cs>
consteval std::size_t tree_capacity() {
  constexpr auto routes = collect_all<Cs...>();
  std::size_t total = 1;
  for (auto const& r : routes) total += count_segments(std::string_view{r.path.data()});
  return total;
}

consteval bool is_wildcard(std::string_view segment) {
  return segment.size() >= 3 && segment.front() == '{' && segment.back() == '}';
}

template <class... Cs>
consteval auto build_tree() {
  constexpr auto routes = collect_all<Cs...>();
  constexpr std::size_t capacity = tree_capacity<Cs...>();
  std::array<node, capacity> nodes{};
  nodes[0] = make_node(-1, 0, false, std::string_view{});
  std::size_t used = 1;

  for (std::size_t ri = 0; ri < routes.size(); ++ri) {
    std::string_view path{routes[ri].path.data()};
    int parent = 0;
    while (true) {
      while (!path.empty() && path.front() == '/') path.remove_prefix(1);
      if (path.empty()) break;
      auto slash = path.find('/');
      std::string_view segment = path.substr(0, slash);
      path = slash == std::string_view::npos ? std::string_view{} : path.substr(slash + 1);

      bool wildcard = is_wildcard(segment);
      if (wildcard) segment = segment.substr(1, segment.size() - 2);

      int found = -1;
      for (std::size_t j = 0; j < used; ++j) {
        if (nodes[j].parent != parent || nodes[j].wildcard != wildcard) continue;
        if (wildcard || std::string_view{nodes[j].segment.data()} == segment) {
          found = static_cast<int>(j);
          break;
        }
      }
      if (found < 0) {
        found = static_cast<int>(used);
        nodes[used] = make_node(parent, static_cast<int>(used), wildcard, segment);
        ++used;
      }
      parent = found;
    }
    nodes[parent].handlers[static_cast<std::size_t>(routes[ri].m)] = static_cast<int>(ri);
  }

  // Propagate "which methods are reachable in this subtree" towards the root so
  // dispatch can skip whole subtrees at compile time for other methods.
  for (std::size_t i = used; i-- > 0;) {
    for (std::size_t m = 0; m < method_count; ++m)
      if (nodes[i].handlers[m] >= 0) nodes[i].method_mask |= static_cast<unsigned char>(1u << m);
    if (nodes[i].parent >= 0)
      nodes[nodes[i].parent].method_mask |= nodes[i].method_mask;
  }
  return nodes;
}

template <class Controllers>
struct tree_builder;

template <class... Cs>
struct tree_builder<std::tuple<Cs...>> {
  static consteval auto build() { return build_tree<Cs...>(); }
};

template <class Controllers>
inline constexpr auto tree_v = tree_builder<Controllers>::build();

template <method M, const auto& Tree, int Idx>
consteval int handler_at() {
  for (auto const& n : Tree)
    if (n.self == Idx) return n.handlers[static_cast<std::size_t>(M)];
  return -1;
}

template <const auto& Tree, int Idx>
consteval bool has_children() {
  for (auto const& n : Tree)
    if (n.parent == Idx) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Dispatch state
// ---------------------------------------------------------------------------

struct dispatch_ctx {
  const http::request_view& req;
  http::response& res;
  std::span<const std::string_view> segments;
  std::array<std::string_view, 8> captures{};
  std::size_t capture_count = 0;
  std::array<char, 4096> arena{};
  std::size_t arena_used = 0;
  bool bad_request = false;

  std::span<char> allocate(std::size_t n) {
    if (arena_used + n > arena.size()) {
      bad_request = true;
      return {};
    }
    auto out = std::span<char>{arena}.subspan(arena_used, n);
    arena_used += n;
    return out;
  }

  // Percent-decodes into the request arena so the returned view stays valid for
  // the duration of the handler call.
  std::string_view decode(std::string_view input) {
    auto buffer = allocate(input.size());
    if (buffer.size() != input.size()) return {};
    auto written = url_decode(input, buffer);
    if (written == std::string_view::npos) {
      bad_request = true;
      return {};
    }
    return std::string_view{buffer.data(), written};
  }

  void reset_route_search() {
    capture_count = 0;
    bad_request = false;
  }
};

// ---------------------------------------------------------------------------
// Parameter conversion
// ---------------------------------------------------------------------------

template <std::meta::info Fn, std::size_t... Js>
consteval std::size_t count_path_before(std::index_sequence<Js...>) {
  return (std::size_t{0} + ... + (kind_of<Fn, Js>() == param_kind::path ? std::size_t{1} : std::size_t{0}));
}

template <std::meta::info Fn, std::size_t I>
consteval std::size_t path_ordinal() {
  return count_path_before<Fn>(std::make_index_sequence<I>{});
}

template <class T>
constexpr T make_value(std::string_view s, dispatch_ctx& c) {
  using U = std::remove_cvref_t<T>;
  bool ok = true;
  if constexpr (is_optional_v<U>) {
    using V = typename is_optional<U>::value_type;
    auto value = parse_value<V>(s, ok);
    if (!ok) c.bad_request = true;
    return U{std::move(value)};
  } else {
    auto value = parse_value<U>(s, ok);
    if (!ok) c.bad_request = true;
    return value;
  }
}

template <std::meta::info Fn, std::size_t I>
constexpr auto make_arg(dispatch_ctx& c) -> param_type_t<Fn, I> {
  using T = param_type_t<Fn, I>;
  using U = std::remove_cvref_t<T>;
  constexpr param_kind kind = kind_of<Fn, I>();
  if constexpr (kind == param_kind::request) {
    return c.req;
  } else if constexpr (kind == param_kind::response) {
    return c.res;
  } else if constexpr (kind == param_kind::path) {
    constexpr std::size_t ordinal = path_ordinal<Fn, I>();
    return make_value<T>(c.captures[ordinal], c);
  } else if constexpr (kind == param_kind::body) {
    if constexpr (is_string_like<U>()) {
      return make_value<T>(c.req.body, c);
    } else if constexpr (std::is_same_v<U, json::value>) {
      auto parsed = json::parse(c.req.body);
      if (!parsed) {
        c.bad_request = true;
        return T{};
      }
      return *std::move(parsed);
    } else {
      auto parsed = json::parse_as<U>(c.req.body);
      if (!parsed) {
        c.bad_request = true;
        return T{};
      }
      return *std::move(parsed);
    }
  } else {
    constexpr auto name = param_name<Fn, I>();
    std::string_view key{name.data()};
    bool present = kind == param_kind::query ? c.req.has_query_param(key) : c.req.has_header(key);
    if constexpr (is_optional_v<U>) {
      if (!present) return U{};
    } else if (!present) {
      c.bad_request = true;
      return T{};
    }
    std::string_view raw =
        kind == param_kind::query ? c.req.query_param(key) : c.req.header(key);
    return make_value<T>(c.decode(raw), c);
  }
}

// ---------------------------------------------------------------------------
// Handler invocation
// ---------------------------------------------------------------------------

template <class R>
void store_result(http::response& res, R&& value) {
  using U = std::remove_cvref_t<R>;
  if constexpr (std::is_same_v<U, http::status>) {
    res.set_status(value);
  } else if constexpr (std::is_same_v<U, std::string>) {
    res.body = std::forward<R>(value);
  } else if constexpr (std::is_same_v<U, std::string_view>) {
    res.body.assign(value.data(), value.size());
  } else if constexpr (std::is_same_v<U, const char*>) {
    res.body = value != nullptr ? value : "";
  } else if constexpr (std::is_same_v<U, bool>) {
    res.body = value ? "true" : "false";
  } else if constexpr (std::is_integral_v<U> || std::is_floating_point_v<U>) {
    res.body = value_to_text<U>(value);
  } else if constexpr (std::is_same_v<U, json::value>) {
    res.body = json::dump(value);
    res.set_header("Content-Type", "application/json");
  } else if constexpr (json::serializable<U>()) {
    res.body = json::dump(json::to_json(value));
    res.set_header("Content-Type", "application/json");
  } else {
    static_assert(always_false_v<U>, "unsupported handler return type");
  }
}

template <std::meta::info Fn, class Self, std::size_t... Is>
void invoke_args(Self& self, dispatch_ctx& c, std::index_sequence<Is...>) {
  using R = return_type_t<Fn>;
  std::tuple<param_type_t<Fn, Is>...> args{make_arg<Fn, Is>(c)...};
  if (c.bad_request) {
    c.res.status_code = static_cast<int>(http::status::bad_request);
    c.res.body = "bad request";
    return;
  }
  std::apply(
      [&](auto&&... values) {
        if constexpr (std::is_void_v<R>) {
          self.[:Fn:](static_cast<decltype(values)>(values)...);
        } else {
          store_result(c.res, self.[:Fn:](static_cast<decltype(values)>(values)...));
        }
      },
      args);
}

template <std::meta::info Fn, class Self>
void invoke(Self& self, dispatch_ctx& c) {
  invoke_args<Fn>(self, c, std::make_index_sequence<param_count<Fn>()>{});
}

template <class Controllers, std::size_t RouteId>
void invoke_route(Controllers& controllers, dispatch_ctx& c) {
  constexpr auto target = target_of<Controllers, RouteId>();
  constexpr std::size_t ctrl = static_cast<std::size_t>(target.ctrl);
  constexpr std::size_t fn = static_cast<std::size_t>(target.fn);
  using controller_t = std::tuple_element_t<ctrl, Controllers>;
  invoke<handler_info_v<controller_t, fn>>(std::get<ctrl>(controllers), c);
}

consteval unsigned char method_bit(method m) {
  return static_cast<unsigned char>(1u << static_cast<unsigned>(m));
}

// ---------------------------------------------------------------------------
// Static dispatch: every trie node becomes its own template instantiation, and
// `template for` expands the children into nested calls.
// ---------------------------------------------------------------------------

template <method M, class Controllers, const auto& Tree, int Idx>
bool dispatch(Controllers& controllers, dispatch_ctx& c, std::size_t depth) {
  constexpr int handler = handler_at<M, Tree, Idx>();
  if constexpr (handler >= 0) {
    if (depth == c.segments.size()) {
      invoke_route<Controllers, static_cast<std::size_t>(handler)>(controllers, c);
      return true;
    }
  }
  if constexpr (has_children<Tree, Idx>()) {
    template for (constexpr auto n : Tree) {
      if constexpr (n.parent == Idx && (n.method_mask & method_bit(M)) != 0) {
        if (depth >= c.segments.size()) continue;
        if constexpr (n.wildcard) {
          auto saved = c.capture_count;
          c.captures[c.capture_count++] = c.decode(c.segments[depth]);
          if (c.bad_request) return false;
          if (dispatch<M, Controllers, Tree, n.self>(controllers, c, depth + 1)) return true;
          c.capture_count = saved;
        } else {
          if (std::string_view{n.segment.data()} != c.segments[depth]) continue;
          if (dispatch<M, Controllers, Tree, n.self>(controllers, c, depth + 1)) return true;
        }
      }
    }
  }
  return false;
}

// Path-only probe used to answer 405 Method Not Allowed without invoking any
// handler.
template <method M, const auto& Tree, int Idx>
bool method_matches(dispatch_ctx& c, std::size_t depth) {
  constexpr int handler = handler_at<M, Tree, Idx>();
  if constexpr (handler >= 0) {
    if (depth == c.segments.size()) return true;
  }
  if constexpr (has_children<Tree, Idx>()) {
    template for (constexpr auto n : Tree) {
      if constexpr (n.parent == Idx && (n.method_mask & method_bit(M)) != 0) {
        if (depth >= c.segments.size()) continue;
        if constexpr (n.wildcard) {
          if (method_matches<M, Tree, n.self>(c, depth + 1)) return true;
        } else {
          if (std::string_view{n.segment.data()} != c.segments[depth]) continue;
          if (method_matches<M, Tree, n.self>(c, depth + 1)) return true;
        }
      }
    }
  }
  return false;
}

} // namespace trie::detail
