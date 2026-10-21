#pragma once

#include <charconv>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trie/http.hh"

namespace trie::http {

enum class parse_status : unsigned char { complete, incomplete, error };

struct parse_error {
  int status = static_cast<int>(status::bad_request);
  std::string message{};
};

struct parsed_request {
  trie::method m = trie::method::get;
  std::string target{};
  std::vector<std::pair<std::string, std::string>> headers{};
  std::string body{};
  bool keep_alive = true;

  std::string_view header(std::string_view name) const {
    for (auto const& header : headers)
      if (iequals(header.first, name)) return header.second;
    return {};
  }
};

struct parser_limits {
  std::size_t max_header_bytes = 16 * 1024;
  std::size_t max_body_bytes = 1 * 1024 * 1024;
  std::size_t max_target_bytes = 8 * 1024;
};

// Incremental HTTP/1.x request parser. `parse` is a pure function of the
// accumulated buffer, so callers can append bytes and retry until it reports
// `complete` or `error`.
class request_parser {
public:
  explicit request_parser(parser_limits limits = {}) : limits_(limits) {}

  parser_limits limits() const { return limits_; }

  parse_status parse(std::string_view buffer, parsed_request& out, parse_error& error,
                     std::size_t& consumed) const {
    consumed = 0;

    auto head_end = buffer.find("\r\n\r\n");
    if (head_end == std::string_view::npos) {
      if (buffer.size() > limits_.max_header_bytes) {
        error = {static_cast<int>(status::request_header_fields_too_large), "request headers too large"};
        return parse_status::error;
      }
      return parse_status::incomplete;
    }
    if (head_end + 4 > limits_.max_header_bytes) {
      error = {static_cast<int>(status::request_header_fields_too_large), "request headers too large"};
      return parse_status::error;
    }

    std::string_view head = buffer.substr(0, head_end);
    auto line_end = head.find("\r\n");
    std::string_view request_line = line_end == std::string_view::npos ? head : head.substr(0, line_end);

    auto first_space = request_line.find(' ');
    auto second_space =
        first_space == std::string_view::npos ? std::string_view::npos : request_line.find(' ', first_space + 1);
    if (first_space == std::string_view::npos || second_space == std::string_view::npos) {
      error = {static_cast<int>(status::bad_request), "malformed request line"};
      return parse_status::error;
    }

    std::string_view method_text = request_line.substr(0, first_space);
    std::string_view target_text = request_line.substr(first_space + 1, second_space - first_space - 1);
    std::string_view version = request_line.substr(second_space + 1);

    auto parsed_method = trie::http::method_from_name(method_text);
    if (!parsed_method.has_value()) {
      error = {static_cast<int>(status::not_implemented), "unsupported method"};
      return parse_status::error;
    }
    if (target_text.empty() || target_text.front() != '/') {
      error = {static_cast<int>(status::bad_request), "malformed request target"};
      return parse_status::error;
    }
    if (target_text.size() > limits_.max_target_bytes) {
      error = {static_cast<int>(status::uri_too_long), "request target too long"};
      return parse_status::error;
    }

    bool http11 = version == "HTTP/1.1";
    bool http10 = version == "HTTP/1.0";
    if (!http11 && !http10) {
      error = {static_cast<int>(status::http_version_not_supported), "unsupported HTTP version"};
      return parse_status::error;
    }

    std::vector<std::pair<std::string, std::string>> headers;
    std::size_t content_length = 0;
    bool has_content_length = false;
    bool connection_close = false;
    bool connection_keep_alive = false;

    std::size_t position = line_end == std::string_view::npos ? head.size() : line_end + 2;
    while (position < head.size()) {
      auto next = head.find("\r\n", position);
      std::string_view line = head.substr(position, next == std::string_view::npos ? head.size() - position
                                                                                  : next - position);
      position = next == std::string_view::npos ? head.size() : next + 2;

      auto colon = line.find(':');
      if (colon == std::string_view::npos || colon == 0) {
        error = {static_cast<int>(status::bad_request), "malformed header"};
        return parse_status::error;
      }
      std::string_view name = line.substr(0, colon);
      std::string_view value = trim_ows(line.substr(colon + 1));
      if (name.find(' ') != std::string_view::npos || name.find('\t') != std::string_view::npos) {
        error = {static_cast<int>(status::bad_request), "malformed header name"};
        return parse_status::error;
      }

      if (iequals(name, "content-length")) {
        std::size_t parsed = 0;
        auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
        if (ec != std::errc{} || ptr != value.data() + value.size()) {
          error = {static_cast<int>(status::bad_request), "malformed Content-Length"};
          return parse_status::error;
        }
        if (has_content_length && parsed != content_length) {
          error = {static_cast<int>(status::bad_request), "conflicting Content-Length"};
          return parse_status::error;
        }
        content_length = parsed;
        has_content_length = true;
      } else if (iequals(name, "transfer-encoding")) {
        if (!iequals(value, "identity")) {
          error = {static_cast<int>(status::not_implemented), "transfer-encoding is not supported"};
          return parse_status::error;
        }
      } else if (iequals(name, "connection")) {
        if (has_token(value, "close")) connection_close = true;
        if (has_token(value, "keep-alive")) connection_keep_alive = true;
      }

      headers.emplace_back(name, value);
    }

    if (content_length > limits_.max_body_bytes) {
      error = {static_cast<int>(status::payload_too_large), "request body too large"};
      return parse_status::error;
    }

    std::size_t body_start = head_end + 4;
    if (buffer.size() < body_start + content_length) return parse_status::incomplete;

    out.m = *parsed_method;
    out.target.assign(target_text.data(), target_text.size());
    out.headers = std::move(headers);
    out.body.assign(buffer.data() + body_start, content_length);
    out.keep_alive = http11 && !connection_close;
    if (!http11 && connection_keep_alive && !connection_close) out.keep_alive = true;
    consumed = body_start + content_length;
    return parse_status::complete;
  }

private:
  static std::string_view trim_ows(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
  }

  static bool has_token(std::string_view value, std::string_view token) {
    while (!value.empty()) {
      auto comma = value.find(',');
      std::string_view part = trim_ows(value.substr(0, comma));
      if (iequals(part, token)) return true;
      value = comma == std::string_view::npos ? std::string_view{} : value.substr(comma + 1);
    }
    return false;
  }

  parser_limits limits_;
};

} // namespace trie::http
