#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <tuple>

#include "trie/detail/trie.hh"

namespace trie {

// A router over one or more controller classes. The complete routing table is
// a compile-time trie: every path segment becomes a template instantiation, so
// matching never walks a runtime table.
//
//   struct api { [[=trie::get("/users/{id}")]] int user(int id); };
//   trie::server<api> srv;
//   auto res = srv.dispatch(trie::method::get, "/users/42");
template <class... Cs>
class server {
public:
  using controllers_t = std::tuple<Cs...>;

  static_assert(sizeof...(Cs) > 0, "trie::server requires at least one controller class");
  static_assert(detail::controller_set<controllers_t>::annotations_ok(),
                "invalid route annotation: paths must start with '/' and {placeholders} must match path parameters");
  static_assert(detail::controller_set<controllers_t>::signatures_ok(),
                "invalid handler signature: unsupported parameter/return type, or more than one body parameter");
  static_assert(detail::controller_set<controllers_t>::unique(), "duplicate (method, path) route");
  static_assert(detail::controller_set<controllers_t>::arity_ok(), "route path is too long (max 95 characters)");

  http::response dispatch(const http::request_view& request) {
    http::response response{};
    std::array<std::string_view, max_path_segments> segments{};
    std::size_t segment_count = 0;
    if (!split_path(request.path, segments, segment_count)) {
      response.status_code = static_cast<int>(http::status::bad_request);
      response.body = "bad request";
      return response;
    }

    detail::dispatch_ctx ctx{request,
                             response,
                             std::span<const std::string_view>{segments}.first(segment_count),
                             {},
                             0,
                             {},
                             0,
                             false};

    bool matched = dispatch_method(request.m, ctx);
    if (matched) return response;
    if (ctx.bad_request) {
      response.status_code = static_cast<int>(http::status::bad_request);
      response.body = "bad request";
      return response;
    }

    detail::dispatch_ctx probe{request,
                               response,
                               ctx.segments,
                               {},
                               0,
                               {},
                               0,
                               false};
    std::string allow;
    bool path_exists = false;
    static constexpr std::array<method, method_count> all_methods{
        method::get, method::post, method::put, method::patch, method::del, method::head, method::options};
    for (method m : all_methods) {
      if (!probe_method(m, probe)) continue;
      path_exists = true;
      if (!allow.empty()) allow += ", ";
      allow += http::method_name(m);
    }

    if (path_exists) {
      response.status_code = static_cast<int>(http::status::method_not_allowed);
      response.set_header("Allow", std::move(allow));
    } else {
      response.status_code = static_cast<int>(http::status::not_found);
      response.body = "not found";
    }
    return response;
  }

  http::response dispatch(method m, std::string_view target) {
    return dispatch(http::request_view::from_target(m, target));
  }

  template <class C>
  C& controller() {
    return std::get<C>(controllers_);
  }

  template <class C>
  C const& controller() const {
    return std::get<C>(controllers_);
  }

private:
  static constexpr std::size_t max_path_segments = 32;

  static bool split_path(std::string_view path, std::array<std::string_view, max_path_segments>& out,
                         std::size_t& count) {
    count = 0;
    if (!path.empty() && path.front() != '/') return false;
    while (!path.empty()) {
      while (!path.empty() && path.front() == '/') path.remove_prefix(1);
      if (path.empty()) break;
      if (count == out.size()) return false;
      auto slash = path.find('/');
      out[count++] = path.substr(0, slash);
      path = slash == std::string_view::npos ? std::string_view{} : path.substr(slash + 1);
    }
    return true;
  }

  bool dispatch_method(method m, detail::dispatch_ctx& ctx) {
    switch (m) {
      case method::get: return dispatch_as<method::get>(ctx);
      case method::post: return dispatch_as<method::post>(ctx);
      case method::put: return dispatch_as<method::put>(ctx);
      case method::patch: return dispatch_as<method::patch>(ctx);
      case method::del: return dispatch_as<method::del>(ctx);
      case method::head: return dispatch_as<method::head>(ctx);
      case method::options: return dispatch_as<method::options>(ctx);
    }
    return false;
  }

  template <method M>
  bool dispatch_as(detail::dispatch_ctx& ctx) {
    if constexpr (detail::method_present<controllers_t, M>())
      return detail::dispatch<M, controllers_t, detail::tree_v<controllers_t>, 0>(controllers_, ctx, 0);
    else
      return false;
  }

  bool probe_method(method m, detail::dispatch_ctx& ctx) {
    switch (m) {
      case method::get: return probe_as<method::get>(ctx);
      case method::post: return probe_as<method::post>(ctx);
      case method::put: return probe_as<method::put>(ctx);
      case method::patch: return probe_as<method::patch>(ctx);
      case method::del: return probe_as<method::del>(ctx);
      case method::head: return probe_as<method::head>(ctx);
      case method::options: return probe_as<method::options>(ctx);
    }
    return false;
  }

  template <method M>
  bool probe_as(detail::dispatch_ctx& ctx) {
    if constexpr (detail::method_present<controllers_t, M>())
      return detail::method_matches<M, detail::tree_v<controllers_t>, 0>(ctx, 0);
    else
      return false;
  }

  std::tuple<Cs...> controllers_{};
};

} // namespace trie
