#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "trie/detail/trie.hh"
#include "trie/http/context.hh"
#include "trie/validation.hh"

namespace trie {

// A router over one or more controller classes, plus a Spring-like middleware
// chain. The complete routing table is a compile-time trie: every path segment
// becomes a template instantiation, so matching never walks a runtime table.
//
//   struct api { [[=trie::get("/users/{id}")]] int user(int id); };
//   trie::server<api> srv;
//   srv.use(auth_middleware{"secret"});
//   auto res = srv.dispatch(trie::method::get, "/users/42");
template <class... Cs>
class server {
public:
  using next_t = http::next;
  using middleware_function =
      std::function<http::response(http::context&, const http::request_view&, const next_t&)>;

  server() = default;
  server(server const&) = delete;
  server& operator=(server const&) = delete;
  server(server&&) = delete;
  server& operator=(server&&) = delete;

  using controllers_t = std::tuple<Cs...>;

  static_assert(sizeof...(Cs) > 0, "trie::server requires at least one controller class");
  static_assert(detail::controller_set<controllers_t>::annotations_ok(),
                "invalid route annotation: paths must start with '/' and {placeholders} must match path parameters");
  static_assert(detail::controller_set<controllers_t>::signatures_ok(),
                "invalid handler signature: unsupported parameter/return type, or more than one body parameter");
  static_assert(detail::controller_set<controllers_t>::unique(), "duplicate (method, path) route");
  static_assert(detail::controller_set<controllers_t>::arity_ok(), "route path is too long (max 95 characters)");

  // Appends a middleware; the first `use` call is the outermost middleware.
  // A middleware is any callable `(http::context&, const http::request_view&,
  // const http::next&) -> http::response`.
  template <class M>
  server& use(M middleware) {
    middlewares_.push_back(
        [mw = std::move(middleware)](http::context& context, const http::request_view& request,
                                     const next_t& next) mutable -> http::response {
          return mw(context, request, next);
        });
    chain_valid_ = false;
    return *this;
  }

  // Overrides the schema strictness used for typed JSON bodies.
  server& set_validation_options(json::validate_options options) {
    hooks_.schema_options = options;
    return *this;
  }

  // Additional body validation after the built-in schema checks.
  server& on_body_validation(body_validation_handler handler) {
    hooks_.body = std::move(handler);
    return *this;
  }

  // Customizes the response for parse/schema/validation failures.
  server& on_validation_error(validation_error_handler handler) {
    hooks_.error = std::move(handler);
    return *this;
  }

  http::response dispatch(const http::request_view& request) {
    http::context context{};
    if (middlewares_.empty()) return dispatch_impl(request, context);
    ensure_chain();
    return chain_(context, request);
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

  // Canonical order used both for probing and for building `Allow` values.
  // HEAD follows GET because a HEAD route is implied by its GET route.
  static constexpr std::array<method, method_count> allow_order{
      method::get, method::head, method::post, method::put, method::patch, method::del, method::options};

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

  http::response dispatch_impl(const http::request_view& request, http::context& context) {
    http::response response{};
    std::array<std::string_view, max_path_segments> segments{};
    std::size_t segment_count = 0;
    if (!split_path(request.path, segments, segment_count)) {
      response.status_code = static_cast<int>(http::status::bad_request);
      response.body = "bad request";
      return response;
    }

    // HEAD is GET without the response body. When no explicit HEAD route
    // matches, route through the GET handler instead; the listener's serializer
    // knows to suppress the body (and to keep the GET Content-Length). Handlers
    // therefore observe the request as a GET.
    http::request_view routed = request;
    detail::dispatch_ctx ctx{routed,
                             response,
                             std::span<const std::string_view>{segments}.first(segment_count),
                             {},
                             0,
                             {},
                             0,
                             false,
                             {},
                             {},
                             &context,
                             &hooks_};

    bool matched = dispatch_method(routed.m, ctx);
    if (!matched && routed.m == method::head && !ctx.bad_request) {
      ctx.reset_route_search();
      routed.m = method::get;
      matched = dispatch_as<method::get>(ctx);
    }
    if (matched) return response;
    if (ctx.bad_request) {
      if (hooks_.error) {
        validation_failure failure{ctx.bad_request_reason.empty() ? "bad request" : ctx.bad_request_reason,
                                   ctx.bad_request_type, &routed};
        response = hooks_.error(failure, context);
        if (response.status_code == static_cast<int>(http::status::ok))
          response.status_code = static_cast<int>(http::status::bad_request);
        return response;
      }
      response.status_code = static_cast<int>(http::status::bad_request);
      response.body = ctx.bad_request_reason.empty() ? "bad request" : ctx.bad_request_reason;
      return response;
    }

    detail::dispatch_ctx probe{routed,
                               response,
                               ctx.segments,
                               {},
                               0,
                               {},
                               0,
                               false,
                               {},
                               {},
                               nullptr,
                               nullptr};
    std::array<bool, method_count> available{};
    for (method m : allow_order)
      if (probe_method(m, probe)) available[static_cast<std::size_t>(m)] = true;

    // A GET route can always answer HEAD, so advertise HEAD whenever GET is
    // registered (and never list it twice).
    if (available[static_cast<std::size_t>(method::get)])
      available[static_cast<std::size_t>(method::head)] = true;

    bool path_exists = false;
    for (bool present : available) path_exists = path_exists || present;

    if (!path_exists) {
      response.status_code = static_cast<int>(http::status::not_found);
      response.body = "not found";
      return response;
    }

    std::string allow;
    for (method m : allow_order) {
      if (!available[static_cast<std::size_t>(m)]) continue;
      if (!allow.empty()) allow += ", ";
      allow += http::method_name(m);
    }

    // No OPTIONS route matched but the path exists: answer the capability query
    // automatically. Explicit OPTIONS routes take priority (handled above).
    if (routed.m == method::options) {
      response.status_code = static_cast<int>(http::status::no_content);
      response.set_header("Allow", std::move(allow));
      return response;
    }

    response.status_code = static_cast<int>(http::status::method_not_allowed);
    response.set_header("Allow", std::move(allow));
    return response;
  }

  void ensure_chain() {
    if (chain_valid_) return;
    next_t next = [this](http::context& context, const http::request_view& request) {
      return dispatch_impl(request, context);
    };
    for (auto iterator = middlewares_.rbegin(); iterator != middlewares_.rend(); ++iterator) {
      middleware_function current = *iterator;
      next_t previous = std::move(next);
      next = [current = std::move(current), previous = std::move(previous)](
                 http::context& context, const http::request_view& request) -> http::response {
        return current(context, request, previous);
      };
    }
    chain_ = std::move(next);
    chain_valid_ = true;
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
  validation_hooks hooks_{};
  std::vector<middleware_function> middlewares_{};
  next_t chain_{};
  bool chain_valid_ = false;
};

} // namespace trie
