#pragma once

// Cleartext HTTP/2 server listener (h2c prior knowledge).
//
// Clients must start the HTTP/2 connection preface directly; there is no
// HTTP/1.1 Upgrade dance and no HTTP/1.1 fallback on this listener. Use
// tls_listener with ALPN for browser-style h2, or this listener for h2c
// services on trusted networks / behind a TLS-terminating proxy.

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
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
#include "trie/http/h2.hh"
#include "trie/http/listener.hh"

namespace trie::http {

template <class Router>
class h2c_listener {
public:
  h2c_listener(Router& router, endpoint address, serve_options options = {})
      : router_(router), options_(std::move(options)) {
    if (options_.connection_limit != nullptr)
      limiter_ = options_.connection_limit;
    else
      limiter_ = std::make_shared<connection_limiter>(options_.max_connections);
    open_socket(std::move(address));
  }

  ~h2c_listener() {
    close_connections();
    if (listen_fd_ >= 0) {
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
  }

  h2c_listener(h2c_listener const&) = delete;
  h2c_listener& operator=(h2c_listener const&) = delete;

  bool valid() const { return listen_fd_ >= 0 && loop_.valid(); }
  int error_code() const { return error_code_; }
  std::uint16_t port() const { return port_; }
  bool stopping() const { return stopping_.load(std::memory_order_relaxed); }
  std::size_t accepted_connections() const { return accepted_.load(std::memory_order_relaxed); }

  void run() {
    if (!valid()) return;
    if (!loop_.add_permanent(listen_fd_, [this] { accept_ready(); })) return;
    loop_.run([this] { return should_exit(); });
    close_connections();
  }

  void stop() {
    stopping_.store(true, std::memory_order_relaxed);
    loop_.wake();
  }

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
#if defined(SO_REUSEPORT)
      if (options_.reuse_port) {
        int reuse_port = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port));
      }
#endif
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

      if (!limiter_->acquire()) {
        // Cannot send a plaintext HTTP/1.1 503 to an HTTP/2 client; just close.
        ::close(fd);
        continue;
      }

      accepted_.fetch_add(1, std::memory_order_relaxed);
      connections_.insert_or_assign(fd, false);
      (void)handle_connection(this, fd);
    }
  }

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

  static task handle_connection(h2c_listener* self, int fd) {
    auto finish = [&] {
      self->loop_.remove(fd);
      self->connections_.erase(fd);
      self->limiter_->release();
      ::close(fd);
    };

    h2_connection<Router> connection{self->router_, self->options_.limits.max_body_bytes};
    std::string pending = connection.take_output();
    bool done = false;
    bool closing = false;
    while (!done) {
      // Flush all pending frames.
      self->set_active(fd, true);
      std::string_view outgoing{pending};
      while (!outgoing.empty()) {
        auto sent = ::send(fd, outgoing.data(), outgoing.size(), MSG_NOSIGNAL);
        if (sent > 0) {
          outgoing.remove_prefix(static_cast<std::size_t>(sent));
          continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          io_event write_event{fd, EPOLLOUT, self->options_.io_timeout};
          if (!(co_await write_event)) {
            done = true;
            break;
          }
          continue;
        }
        done = true;
        break;
      }
      pending.clear();
      self->set_active(fd, false);
      if (done || closing || connection.finished()) break;
      if (self->stopping_.load(std::memory_order_relaxed)) break;

      std::array<char, 16384> chunk{};
      auto received = ::recv(fd, chunk.data(), chunk.size(), 0);
      if (received > 0) {
        self->set_active(fd, true);
        bool const alive = connection.consume(
            std::string_view{chunk.data(), static_cast<std::size_t>(received)});
        self->set_active(fd, false);
        pending = connection.take_output();
        if (!alive) {
          // Flush protocol-error frames (e.g. GOAWAY) before closing.
          closing = true;
        }
        continue;
      }
      if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        io_event read_event{fd, EPOLLIN, self->options_.idle_timeout};
        if (!(co_await read_event)) {
          connection.shutdown();
          pending = connection.take_output();
          closing = true;
        }
        continue;
      }
      if (received < 0 && errno == EINTR) continue;
      // EOF or hard socket error: best-effort GOAWAY, then flush and close.
      connection.shutdown();
      pending = connection.take_output();
      closing = true;
    }

    finish();
    co_return;
  }

  void set_active(int fd, bool active) {
    auto entry = connections_.find(fd);
    if (entry != connections_.end()) entry->second = active;
  }

  void close_connections() {
    for (auto const& [fd, active] : connections_) {
      (void)active;
      loop_.remove(fd);
      limiter_->release();
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
  std::shared_ptr<connection_limiter> limiter_{};
  std::atomic<bool> stopping_{false};
  std::atomic<std::size_t> accepted_{0};
  bool draining_ = false;
  clock::time_point drain_deadline_{};
  std::unordered_map<int, bool> connections_{};
};

template <class Router>
bool serve_h2c(Router& router, endpoint address, serve_options options = {}) {
  h2c_listener<Router> server{router, std::move(address), options};
  if (!server.valid()) return false;
  server.run();
  return true;
}

} // namespace trie::http
