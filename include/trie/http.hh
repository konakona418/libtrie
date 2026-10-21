#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trie/annotations.hh"
#include "trie/detail/url.hh"

namespace trie::http {

enum class status : int {
  ok = 200,
  created = 201,
  accepted = 202,
  no_content = 204,
  bad_request = 400,
  unauthorized = 401,
  not_found = 404,
  method_not_allowed = 405,
  payload_too_large = 413,
  uri_too_long = 414,
  request_header_fields_too_large = 431,
  internal_server_error = 500,
  not_implemented = 501,
  http_version_not_supported = 505,
};

constexpr std::string_view method_name(trie::method m) {
  switch (m) {
    case trie::method::get: return "GET";
    case trie::method::post: return "POST";
    case trie::method::put: return "PUT";
    case trie::method::patch: return "PATCH";
    case trie::method::del: return "DELETE";
    case trie::method::head: return "HEAD";
    case trie::method::options: return "OPTIONS";
  }
  return "";
}

struct endpoint {
  std::string host{"127.0.0.1"};
  std::uint16_t port{8080};
};

constexpr std::optional<trie::method> method_from_name(std::string_view name) {
  if (name == "GET") return trie::method::get;
  if (name == "POST") return trie::method::post;
  if (name == "PUT") return trie::method::put;
  if (name == "PATCH") return trie::method::patch;
  if (name == "DELETE") return trie::method::del;
  if (name == "HEAD") return trie::method::head;
  if (name == "OPTIONS") return trie::method::options;
  return std::nullopt;
}

struct header_view {
  std::string_view name;
  std::string_view value;
};

constexpr char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

constexpr bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i)
    if (to_lower(a[i]) != to_lower(b[i])) return false;
  return true;
}

// Non-owning view of an HTTP request. Routing only needs this type, which makes
// it cheap to unit test without a socket.
struct request_view {
  trie::method m = trie::method::get;
  std::string_view target{};
  std::string_view path{};
  std::string_view query{};
  std::span<const header_view> headers{};
  std::string_view body{};

  static request_view from_target(trie::method m, std::string_view target,
                                  std::span<const header_view> headers = {}, std::string_view body = {}) {
    request_view v{};
    v.m = m;
    v.target = target;
    v.body = body;
    v.headers = headers;
    auto q = target.find('?');
    if (q == std::string_view::npos) {
      v.path = target;
    } else {
      v.path = target.substr(0, q);
      v.query = target.substr(q + 1);
    }
    return v;
  }

  std::string_view header(std::string_view name) const {
    for (auto const& h : headers)
      if (iequals(h.name, name)) return h.value;
    return {};
  }

  bool has_header(std::string_view name) const {
    for (auto const& h : headers)
      if (iequals(h.name, name)) return true;
    return false;
  }

  // Raw (still percent-encoded) value of the first `name` query parameter.
  std::string_view query_param(std::string_view name) const {
    std::string_view rest = query;
    while (!rest.empty()) {
      auto amp = rest.find('&');
      std::string_view pair = rest.substr(0, amp);
      auto eq = pair.find('=');
      std::string_view key = eq == std::string_view::npos ? pair : pair.substr(0, eq);
      std::string_view value = eq == std::string_view::npos ? std::string_view{} : pair.substr(eq + 1);
      if (key == name) return value;
      rest = amp == std::string_view::npos ? std::string_view{} : rest.substr(amp + 1);
    }
    return {};
  }

  bool has_query_param(std::string_view name) const {
    std::string_view rest = query;
    while (!rest.empty()) {
      auto amp = rest.find('&');
      std::string_view pair = rest.substr(0, amp);
      std::string_view key = pair.substr(0, pair.find('='));
      if (key == name) return true;
      rest = amp == std::string_view::npos ? std::string_view{} : rest.substr(amp + 1);
    }
    return false;
  }
};

// Owning request, primarily used by the client and by the tests.
struct request {
  trie::method m = trie::method::get;
  std::string target{};
  std::vector<std::pair<std::string, std::string>> headers{};
  std::string body{};

  std::string_view path() const {
    auto q = target.find('?');
    return q == std::string::npos ? std::string_view{target} : std::string_view{target}.substr(0, q);
  }

  std::string_view query() const {
    auto q = target.find('?');
    return q == std::string::npos ? std::string_view{} : std::string_view{target}.substr(q + 1);
  }

  request_view view(std::vector<header_view>& scratch) const {
    scratch.clear();
    scratch.reserve(headers.size());
    for (auto const& h : headers) scratch.push_back(header_view{h.first, h.second});
    return request_view::from_target(m, target, std::span<const header_view>{scratch}, body);
  }
};

struct response {
  int status_code = static_cast<int>(status::ok);
  std::string body{};
  std::vector<std::pair<std::string, std::string>> headers{};

  void set_status(trie::http::status s) { status_code = static_cast<int>(s); }

  void set_header(std::string name, std::string value) {
    headers.emplace_back(std::move(name), std::move(value));
  }

  std::string_view header(std::string_view name) const {
    for (auto const& h : headers)
      if (iequals(h.first, name)) return h.second;
    return {};
  }
};

} // namespace trie::http
