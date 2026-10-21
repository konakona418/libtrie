#pragma once

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <fcntl.h>
#include <memory>
#include <mutex>
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

struct pooled_socket_transport_options {
  int connect_timeout_ms = 5000;
  int io_timeout_ms = 5000;
  std::size_t max_response_bytes = 8 * 1024 * 1024;
  std::size_t max_idle_connections = 8;
};

// Blocking HTTP/1.1 transport with a keep-alive connection pool. Idle
// connections are reused for the same endpoint; a broken idle connection is
// retried once on a fresh connection. Safe to share between threads.
class pooled_socket_transport {
public:
  explicit pooled_socket_transport(endpoint address, pooled_socket_transport_options options = {})
      : address_(std::move(address)), options_(options), state_(std::make_shared<state>()) {}

  ~pooled_socket_transport() {
    if (state_ == nullptr) return;
    std::lock_guard lock(state_->mutex);
    state_->idle.clear();
  }

  pooled_socket_transport(pooled_socket_transport const&) = delete;
  pooled_socket_transport& operator=(pooled_socket_transport const&) = delete;
  pooled_socket_transport(pooled_socket_transport&&) noexcept = default;
  pooled_socket_transport& operator=(pooled_socket_transport&&) noexcept = default;

  std::expected<response, trie::client_error> send(request request) const {
    std::string wire = build_request(request);
    for (int attempt = 0; attempt < 2; ++attempt) {
      bool reused = false;
      connection active = acquire(reused);
      if (!active.valid()) {
        std::string error;
        int fd = connect_socket(error);
        if (fd < 0) return std::unexpected(trie::client_error{0, std::move(error)});
        active = connection{fd};
        reused = false;
      }

      auto exchanged = exchange(active, wire);
      if (!exchanged) {
        active.close();
        if (reused) continue; // idle connection died; retry once with a fresh one
        return std::unexpected(std::move(exchanged.error()));
      }

      auto [result, keep_alive] = std::move(*exchanged);
      if (keep_alive && options_.max_idle_connections > 0)
        release(std::move(active));
      else
        active.close();
      return std::move(result);
    }
    return std::unexpected(trie::client_error{0, "request failed after reconnect"});
  }

  // Number of currently pooled idle connections (mostly useful in tests).
  std::size_t idle_connections() const {
    std::lock_guard lock(state_->mutex);
    return state_->idle.size();
  }

private:
  struct connection {
    int fd = -1;
    std::string buffer{};

    connection() = default;
    explicit connection(int descriptor) : fd(descriptor) {}
    connection(connection&& other) noexcept
        : fd(std::exchange(other.fd, -1)), buffer(std::move(other.buffer)) {}
    connection& operator=(connection&& other) noexcept {
      if (this != &other) {
        close();
        fd = std::exchange(other.fd, -1);
        buffer = std::move(other.buffer);
      }
      return *this;
    }
    connection(connection const&) = delete;
    connection& operator=(connection const&) = delete;
    ~connection() { close(); }

    void close() {
      if (fd >= 0) ::close(fd);
      fd = -1;
      buffer.clear();
    }
    bool valid() const { return fd >= 0; }
  };

  struct state {
    std::mutex mutex{};
    std::vector<connection> idle{};
  };

  connection acquire(bool& reused) const {
    std::lock_guard lock(state_->mutex);
    if (state_->idle.empty()) return connection{};
    connection result = std::move(state_->idle.back());
    state_->idle.pop_back();
    reused = true;
    return result;
  }

  void release(connection active) const {
    std::lock_guard lock(state_->mutex);
    if (state_->idle.size() < options_.max_idle_connections)
      state_->idle.push_back(std::move(active));
    else
      active.close();
  }

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
    wire += "Connection: keep-alive\r\n";
    wire += "Content-Length: ";
    wire += std::to_string(request.body.size());
    wire += "\r\n\r\n";
    wire += request.body;
    return wire;
  }

  int connect_socket(std::string& error) const {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* results = nullptr;
    std::string service = std::to_string(address_.port);
    if (::getaddrinfo(address_.host.c_str(), service.c_str(), &hints, &results) != 0) {
      error = "failed to resolve " + address_.host;
      return -1;
    }

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
          int socket_error = 0;
          socklen_t length = sizeof(socket_error);
          ok = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) == 0 && socket_error == 0;
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
    if (connected < 0) error = "failed to connect to " + address_.host + ":" + std::to_string(address_.port);
    return connected;
  }

  std::expected<std::pair<response, bool>, trie::client_error> exchange(connection& active,
                                                                        std::string_view wire) const {
    std::string_view pending{wire};
    while (!pending.empty()) {
      auto sent = ::send(active.fd, pending.data(), pending.size(), MSG_NOSIGNAL);
      if (sent > 0) {
        pending.remove_prefix(static_cast<std::size_t>(sent));
        continue;
      }
      if (sent < 0 && errno == EINTR) continue;
      return std::unexpected(trie::client_error{0, "failed to send request"});
    }

    std::size_t head_end = 0;
    std::size_t content_length = 0;
    bool has_head = false;
    bool has_length = false;
    int status_code = 0;
    bool server_keep_alive = true;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string message;
    std::array<char, 8192> chunk{};

    while (true) {
      if (has_head && has_length && active.buffer.size() >= head_end + 4 + content_length) break;
      if (active.buffer.size() > options_.max_response_bytes)
        return std::unexpected(trie::client_error{0, "response too large"});

      auto received = ::recv(active.fd, chunk.data(), chunk.size(), 0);
      if (received == 0) {
        if (!has_head) return std::unexpected(trie::client_error{0, "connection closed before response head"});
        server_keep_alive = false; // body delimited by EOF
        break;
      }
      if (received < 0) {
        if (errno == EINTR) continue;
        return std::unexpected(trie::client_error{0, "failed to receive response"});
      }
      active.buffer.append(chunk.data(), static_cast<std::size_t>(received));

      if (!has_head) {
        auto position = active.buffer.find("\r\n\r\n");
        if (position != std::string::npos) {
          head_end = position;
          if (!parse_head(std::string_view{active.buffer}.substr(0, head_end), status_code, headers,
                          content_length, has_length, server_keep_alive, message))
            return std::unexpected(trie::client_error{0, std::move(message)});
          has_head = true;
        }
      }
    }

    response result{};
    result.status_code = status_code;
    result.headers = std::move(headers);
    if (has_length)
      result.body.assign(active.buffer.data() + head_end + 4, content_length);
    else
      result.body.assign(active.buffer.data() + head_end + 4, active.buffer.size() - head_end - 4);
    active.buffer.clear();
    return std::make_pair(std::move(result), server_keep_alive && has_length);
  }

  static bool parse_head(std::string_view head, int& status_code,
                         std::vector<std::pair<std::string, std::string>>& headers,
                         std::size_t& content_length, bool& has_length, bool& keep_alive,
                         std::string& message) {
    auto line_end = head.find("\r\n");
    std::string_view status_line = line_end == std::string_view::npos ? head : head.substr(0, line_end);
    bool http11 = status_line.starts_with("HTTP/1.1");
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

    bool connection_close = false;
    bool connection_keep_alive = false;
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
      } else if (iequals(name, "connection")) {
        if (has_token(value, "close")) connection_close = true;
        if (has_token(value, "keep-alive")) connection_keep_alive = true;
      }
      headers.emplace_back(name, value);
    }

    keep_alive = http11 ? !connection_close : (connection_keep_alive && !connection_close);
    return true;
  }

  static bool has_token(std::string_view value, std::string_view token) {
    while (!value.empty()) {
      auto comma = value.find(',');
      std::string_view part = value.substr(0, comma);
      while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) part.remove_prefix(1);
      while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) part.remove_suffix(1);
      if (iequals(part, token)) return true;
      value = comma == std::string_view::npos ? std::string_view{} : value.substr(comma + 1);
    }
    return false;
  }

  endpoint address_;
  pooled_socket_transport_options options_;
  std::shared_ptr<state> state_;
};

} // namespace trie::http
