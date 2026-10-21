#pragma once

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "trie/error.hh"
#include "trie/http.hh"

namespace trie::http {

struct socket_transport_options {
  int connect_timeout_ms = 5000;
  int io_timeout_ms = 5000;
  std::size_t max_response_bytes = 8 * 1024 * 1024;
};

// Blocking HTTP/1.1 transport for trie::client. One TCP connection per request:
// the request is sent with `Connection: close` and the response is read until
// Content-Length bytes or EOF. No connection pooling, no TLS.
class socket_transport {
public:
  explicit socket_transport(endpoint address, socket_transport_options options = {})
      : address_(std::move(address)), options_(options) {}

  std::expected<response, trie::client_error> send(request request) const {
    std::string wire = build_request(request);
    int fd = connect_socket();
    if (fd < 0) {
      return std::unexpected(trie::client_error{
          0, "failed to connect to " + address_.host + ":" + std::to_string(address_.port)});
    }

    auto fail = [&](std::string message) -> std::expected<response, trie::client_error> {
      ::close(fd);
      return std::unexpected(trie::client_error{0, std::move(message)});
    };

    std::string_view pending{wire};
    while (!pending.empty()) {
      auto sent = ::send(fd, pending.data(), pending.size(), MSG_NOSIGNAL);
      if (sent > 0) {
        pending.remove_prefix(static_cast<std::size_t>(sent));
        continue;
      }
      if (sent < 0 && errno == EINTR) continue;
      return fail("failed to send request");
    }

    std::string buffer;
    std::array<char, 8192> chunk{};
    std::size_t head_end = 0;
    std::size_t content_length = 0;
    bool has_head = false;
    bool has_length = false;
    int status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string parse_message;

    while (true) {
      if (has_head && has_length && buffer.size() >= head_end + 4 + content_length) break;
      if (buffer.size() > options_.max_response_bytes) return fail("response too large");

      auto received = ::recv(fd, chunk.data(), chunk.size(), 0);
      if (received == 0) {
        if (!has_head) return fail("connection closed before response head");
        break; // body delimited by EOF
      }
      if (received < 0) {
        if (errno == EINTR) continue;
        return fail("failed to receive response");
      }
      buffer.append(chunk.data(), static_cast<std::size_t>(received));

      if (!has_head) {
        auto position = buffer.find("\r\n\r\n");
        if (position != std::string::npos) {
          head_end = position;
          if (!parse_head(std::string_view{buffer}.substr(0, head_end), status_code, headers, content_length,
                          has_length, parse_message)) {
            return fail(std::move(parse_message));
          }
          has_head = true;
        }
      }
    }
    ::close(fd);

    response result{};
    result.status_code = status_code;
    result.headers = std::move(headers);
    if (has_length) {
      result.body.assign(buffer.data() + head_end + 4, content_length);
    } else {
      result.body.assign(buffer.data() + head_end + 4, buffer.size() - head_end - 4);
    }
    return result;
  }

private:
  std::string build_request(request const& request) const {
    std::string wire;
    wire.reserve(128 + request.body.size());
    wire += method_name(request.m);
    wire += ' ';
    wire += request.target.empty() ? std::string_view{"/"} : std::string_view{request.target};
    wire += " HTTP/1.1\r\n";

    bool has_host = false;
    for (auto const& header : request.headers) {
      if (iequals(header.first, "host")) has_host = true;
      if (iequals(header.first, "connection") || iequals(header.first, "content-length")) continue;
      wire += header.first;
      wire += ": ";
      wire += header.second;
      wire += "\r\n";
    }
    if (!has_host) {
      wire += "Host: ";
      wire += address_.host;
      wire += "\r\n";
    }
    wire += "Connection: close\r\n";
    wire += "Content-Length: ";
    wire += std::to_string(request.body.size());
    wire += "\r\n\r\n";
    wire += request.body;
    return wire;
  }

  int connect_socket() const {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* results = nullptr;
    std::string service = std::to_string(address_.port);
    if (::getaddrinfo(address_.host.c_str(), service.c_str(), &hints, &results) != 0) return -1;

    int connected = -1;
    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
      int fd = ::socket(it->ai_family, it->ai_socktype | SOCK_CLOEXEC, it->ai_protocol);
      if (fd < 0) continue;

      int flags = ::fcntl(fd, F_GETFL, 0);
      (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

      bool ok = ::connect(fd, it->ai_addr, it->ai_addrlen) == 0;
      if (!ok && errno == EINPROGRESS) {
        pollfd descriptor{fd, POLLOUT, 0};
        int ready = ::poll(&descriptor, 1, options_.connect_timeout_ms);
        if (ready > 0) {
          int error = 0;
          socklen_t length = sizeof(error);
          ok = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
        }
      }
      if (!ok) {
        ::close(fd);
        continue;
      }

      (void)::fcntl(fd, F_SETFL, flags);
      timeval timeout{};
      timeout.tv_sec = options_.io_timeout_ms / 1000;
      timeout.tv_usec = (options_.io_timeout_ms % 1000) * 1000;
      (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
      connected = fd;
      break;
    }
    ::freeaddrinfo(results);
    return connected;
  }

  static bool parse_head(std::string_view head, int& status_code,
                         std::vector<std::pair<std::string, std::string>>& headers,
                         std::size_t& content_length, bool& has_length, std::string& message) {
    auto line_end = head.find("\r\n");
    std::string_view status_line = line_end == std::string_view::npos ? head : head.substr(0, line_end);
    auto first_space = status_line.find(' ');
    if (first_space == std::string_view::npos) {
      message = "malformed response status line";
      return false;
    }
    auto second_space = status_line.find(' ', first_space + 1);
    std::string_view code_text =
        status_line.substr(first_space + 1, second_space == std::string_view::npos
                                               ? status_line.size() - first_space - 1
                                               : second_space - first_space - 1);
    auto [ptr, ec] = std::from_chars(code_text.data(), code_text.data() + code_text.size(), status_code);
    if (ec != std::errc{} || ptr != code_text.data() + code_text.size()) {
      message = "malformed response status code";
      return false;
    }

    std::size_t position = line_end == std::string_view::npos ? head.size() : line_end + 2;
    while (position < head.size()) {
      auto next = head.find("\r\n", position);
      std::string_view line =
          head.substr(position, next == std::string_view::npos ? head.size() - position : next - position);
      position = next == std::string_view::npos ? head.size() : next + 2;

      auto colon = line.find(':');
      if (colon == std::string_view::npos) continue;
      std::string_view name = line.substr(0, colon);
      std::string_view value = line.substr(colon + 1);
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
      while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);

      if (iequals(name, "content-length")) {
        auto [length_ptr, length_ec] =
            std::from_chars(value.data(), value.data() + value.size(), content_length);
        if (length_ec != std::errc{} || length_ptr != value.data() + value.size()) {
          message = "malformed Content-Length";
          return false;
        }
        has_length = true;
      } else if (iequals(name, "transfer-encoding") && !iequals(value, "identity")) {
        message = "unsupported transfer-encoding in response";
        return false;
      }
      headers.emplace_back(name, value);
    }
    return true;
  }

  endpoint address_;
  socket_transport_options options_;
};

} // namespace trie::http
