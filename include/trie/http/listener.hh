#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "trie/http/event_loop.hh"
#include "trie/http/parser.hh"
#include "trie/http/serializer.hh"

namespace trie::http {

struct serve_options {
  parser_limits limits{};
  // Per-read/write wait timeout.
  std::chrono::milliseconds io_timeout{10000};
  // Absolute time budget for receiving one complete request (headers + body).
  std::chrono::milliseconds request_timeout{15000};
  // How long a keep-alive connection may stay idle between requests.
  std::chrono::milliseconds idle_timeout{30000};
  // How long stop() waits for in-flight requests before forcing the loop down.
  std::chrono::milliseconds drain_timeout{5000};
};

// Blocking epoll server: accepts connections, runs one coroutine per connection
// (requests on a connection are handled sequentially, HTTP/1.1 keep-alive), and
// forwards parsed requests to the compile-time router.
//
// stop() is non-blocking and can be called from another thread: it stops
// accepting, closes idle keep-alive connections, waits up to drain_timeout for
// in-flight requests, then shuts the loop down. `run()` returns when draining
// finishes.
template <class Router>
class listener {
public:
  listener(Router& router, endpoint address, serve_options options = {})
      : router_(router), options_(options) {
    open_socket(std::move(address));
  }

  ~listener() { close_connections(); }

  listener(listener const&) = delete;
  listener& operator=(listener const&) = delete;

  bool valid() const { return listen_fd_ >= 0 && loop_.valid(); }

  int error_code() const { return error_code_; }

  // Bound port; useful when the listener was created with port 0.
  std::uint16_t port() const { return port_; }

  void run() {
    if (!valid()) return;
    if (!loop_.add_permanent(listen_fd_, [this] { accept_ready(); })) return;
    loop_.run([this] { return should_exit(); });
    close_connections();
  }

  // Non-blocking: sets the stopping flag and wakes the run loop. The loop drains
  // existing connections (up to drain_timeout) and then `run()` returns.
  void stop() {
    stopping_.store(true, std::memory_order_relaxed);
    loop_.wake();
  }

  bool stopping() const { return stopping_.load(std::memory_order_relaxed); }

private:
  void open_socket(endpoint address) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* results = nullptr;
    std::string service = std::to_string(address.port);
    if (::getaddrinfo(address.host.c_str(), service.c_str(), &hints, &results) != 0) {
      error_code_ = EADDRNOTAVAIL;
      return;
    }

    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
      int fd = ::socket(it->ai_family, it->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, it->ai_protocol);
      if (fd < 0) continue;

      int reuse = 1;
      (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
      if (it->ai_family == AF_INET6) {
        int only_v6 = 0;
        (void)::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only_v6, sizeof(only_v6));
      }

      if (::bind(fd, it->ai_addr, it->ai_addrlen) < 0 || ::listen(fd, 128) < 0) {
        error_code_ = errno;
        ::close(fd);
        continue;
      }
      listen_fd_ = fd;
      break;
    }
    ::freeaddrinfo(results);

    if (listen_fd_ < 0) return;
    sockaddr_storage address_storage{};
    socklen_t length = sizeof(address_storage);
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&address_storage), &length) == 0) {
      if (address_storage.ss_family == AF_INET)
        port_ = ntohs(reinterpret_cast<sockaddr_in*>(&address_storage)->sin_port);
      else if (address_storage.ss_family == AF_INET6)
        port_ = ntohs(reinterpret_cast<sockaddr_in6*>(&address_storage)->sin6_port);
    }
  }

  void accept_ready() {
    if (stopping_.load(std::memory_order_relaxed)) return;
    while (true) {
      int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0) {
        if (errno == EINTR) continue;
        return;
      }
      int no_delay = 1;
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay));
      connections_.insert_or_assign(fd, false);
      (void)handle_connection(this, fd);
    }
  }

  // Called on the run thread: stop accepting, close idle connections, wait for
  // in-flight requests until drain_timeout expires.
  bool should_exit() {
    if (!stopping_.load(std::memory_order_relaxed)) return false;

    if (!draining_) {
      draining_ = true;
      if (listen_fd_ >= 0) {
        loop_.remove(listen_fd_);
        ::close(listen_fd_);
        listen_fd_ = -1;
      }
      drain_deadline_ = clock::now() + options_.drain_timeout;
    }

    std::vector<int> idle{};
    for (auto const& [fd, active] : connections_)
      if (!active) idle.push_back(fd);
    for (int fd : idle) loop_.cancel_wait(fd);

    if (connections_.empty()) return true;
    return clock::now() >= drain_deadline_;
  }

  static response error_response(int status_code, std::string message) {
    response result{};
    result.status_code = status_code;
    result.set_header("Content-Type", "text/plain");
    result.body = std::move(message);
    return result;
  }

  static task handle_connection(listener* self, int fd) {
    std::string buffer;
    auto finish = [&] {
      self->loop_.remove(fd);
      self->connections_.erase(fd);
      ::close(fd);
    };

    request_parser parser{self->options_.limits};
    serve_options const& options = self->options_;

    while (true) {
      parsed_request request{};
      parse_error error{};
      std::size_t consumed = 0;
      parse_status status = parser.parse(buffer, request, error, consumed);

      bool timed_out = false;
      clock::time_point request_deadline = clock::time_point::max();
      while (status == parse_status::incomplete) {
        std::chrono::milliseconds wait{0};
        if (buffer.empty()) {
          wait = options.idle_timeout;
        } else {
          clock::time_point const now = clock::now();
          if (request_deadline == clock::time_point::max()) request_deadline = now + options.request_timeout;
          auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(request_deadline - now);
          if (remaining.count() <= 0) {
            timed_out = true;
            break;
          }
          wait = std::min(options.io_timeout, remaining);
        }

        io_event read_event{fd, EPOLLIN, wait};
        bool ready = co_await read_event;
        if (!ready) {
          timed_out = true;
          break;
        }

        std::array<char, 8192> chunk{};
        auto received = ::recv(fd, chunk.data(), chunk.size(), 0);
        if (received == 0) {
          finish();
          co_return;
        }
        if (received < 0) {
          if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
          finish();
          co_return;
        }
        buffer.append(chunk.data(), static_cast<std::size_t>(received));
        status = parser.parse(buffer, request, error, consumed);
      }

      // Idle timeout: close silently. Request timeout or parse error: error reply.
      if (timed_out && buffer.empty()) {
        finish();
        co_return;
      }

      std::string out;
      bool close_after = false;
      if (timed_out || status == parse_status::error) {
        int const code = timed_out ? static_cast<int>(status::request_timeout) : error.status;
        std::string message = timed_out ? "request timeout" : std::move(error.message);
        out = serialize_response(error_response(code, std::move(message)), false, false);
        close_after = true;
      } else {
        self->connections_.insert_or_assign(fd, true);

        std::vector<header_view> header_views;
        header_views.reserve(request.headers.size());
        for (auto const& header : request.headers)
          header_views.push_back(header_view{header.first, header.second});

        auto view = request_view::from_target(request.m, request.target, header_views, request.body);
        response result = self->router_.dispatch(view);
        bool const head_only = request.m == method::head;
        out = serialize_response(result, request.keep_alive, head_only);
        close_after = !request.keep_alive;
        buffer.erase(0, consumed);
      }

      std::string_view pending{out};
      bool write_failed = false;
      while (!pending.empty()) {
        auto sent = ::send(fd, pending.data(), pending.size(), MSG_NOSIGNAL);
        if (sent > 0) {
          pending.remove_prefix(static_cast<std::size_t>(sent));
          continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          io_event write_event{fd, EPOLLOUT, options.io_timeout};
          bool ready = co_await write_event;
          if (!ready) {
            write_failed = true;
            break;
          }
          continue;
        }
        write_failed = true;
        break;
      }

      if (write_failed || close_after) {
        finish();
        co_return;
      }
      self->connections_.insert_or_assign(fd, false);
    }
  }

  void close_connections() {
    for (auto const& [fd, active] : connections_) {
      (void)active;
      loop_.remove(fd);
      ::close(fd);
    }
    connections_.clear();
  }

  Router& router_;
  serve_options options_;
  event_loop loop_;
  int listen_fd_ = -1;
  int error_code_ = 0;
  std::uint16_t port_ = 0;
  std::atomic<bool> stopping_{false};
  bool draining_ = false;
  clock::time_point drain_deadline_{};
  std::unordered_map<int, bool> connections_{};
};

template <class Router>
bool serve(Router& router, endpoint address, serve_options options = {}) {
  listener<Router> server{router, std::move(address), options};
  if (!server.valid()) return false;
  server.run();
  return true;
}

} // namespace trie::http
