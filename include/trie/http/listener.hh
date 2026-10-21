#pragma once

#include <array>
#include <cerrno>
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
#include <unordered_set>
#include <vector>

#include "trie/http/event_loop.hh"
#include "trie/http/parser.hh"
#include "trie/http/serializer.hh"

namespace trie::http {

struct endpoint {
  std::string host{"127.0.0.1"};
  std::uint16_t port{8080};
};

struct serve_options {
  parser_limits limits{};
};

// Blocking epoll server: accepts connections, runs one coroutine per connection
// (requests on a connection are handled sequentially, HTTP/1.1 keep-alive), and
// forwards parsed requests to the compile-time router.
template <class Router>
class listener {
public:
  listener(Router& router, endpoint address, serve_options options = {})
      : router_(router), options_(options) {
    open_socket(std::move(address));
  }

  ~listener() {
    close_connections();
    if (listen_fd_ >= 0) ::close(listen_fd_);
  }

  listener(listener const&) = delete;
  listener& operator=(listener const&) = delete;

  bool valid() const { return listen_fd_ >= 0 && loop_.valid(); }

  int error_code() const { return error_code_; }

  // Bound port; useful when the listener was created with port 0.
  std::uint16_t port() const { return port_; }

  void run() {
    if (!valid()) return;
    if (!loop_.add_permanent(listen_fd_, [this] { accept_ready(); })) return;
    loop_.run();
  }

  void stop() { loop_.stop(); }

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
    while (true) {
      int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0) {
        if (errno == EINTR) continue;
        return;
      }
      int no_delay = 1;
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay));
      connections_.insert(fd);
      (void)handle_connection(this, fd);
    }
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
    bool keep_alive = true;
    while (keep_alive) {
      parsed_request request{};
      parse_error error{};
      std::size_t consumed = 0;
      parse_status status = parser.parse(buffer, request, error, consumed);

      while (status == parse_status::incomplete) {
        std::array<char, 8192> chunk{};
        auto received = ::recv(fd, chunk.data(), chunk.size(), 0);
        if (received == 0) {
          finish();
          co_return;
        }
        if (received < 0) {
          if (errno == EINTR) continue;
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            co_await io_event{fd, EPOLLIN};
            continue;
          }
          finish();
          co_return;
        }
        buffer.append(chunk.data(), static_cast<std::size_t>(received));
        status = parser.parse(buffer, request, error, consumed);
      }

      std::string out;
      if (status == parse_status::error) {
        out = serialize_response(error_response(error.status, std::move(error.message)), false, false);
        keep_alive = false;
      } else {
        std::vector<header_view> header_views;
        header_views.reserve(request.headers.size());
        for (auto const& header : request.headers)
          header_views.push_back(header_view{header.first, header.second});

        auto view = request_view::from_target(request.m, request.target, header_views, request.body);
        response result = self->router_.dispatch(view);
        bool head_only = request.m == method::head;
        out = serialize_response(result, request.keep_alive, head_only);
        keep_alive = request.keep_alive;
        buffer.erase(0, consumed);
      }

      std::string_view pending{out};
      bool failed = false;
      while (!pending.empty()) {
        auto sent = ::send(fd, pending.data(), pending.size(), MSG_NOSIGNAL);
        if (sent > 0) {
          pending.remove_prefix(static_cast<std::size_t>(sent));
          continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          co_await io_event{fd, EPOLLOUT};
          continue;
        }
        failed = true;
        break;
      }
      if (failed || !keep_alive) break;
    }

    finish();
    co_return;
  }

  void close_connections() {
    for (int fd : connections_) {
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
  std::unordered_set<int> connections_{};
};

template <class Router>
bool serve(Router& router, endpoint address, serve_options options = {}) {
  listener<Router> server{router, std::move(address), options};
  if (!server.valid()) return false;
  server.run();
  return true;
}

} // namespace trie::http
