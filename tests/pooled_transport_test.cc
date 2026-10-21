#include "trie/trie.hh"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "harness.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

namespace {

bool send_all(int fd, std::string_view data) {
  while (!data.empty()) {
    auto sent = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
    if (sent <= 0) return false;
    data.remove_prefix(static_cast<std::size_t>(sent));
  }
  return true;
}

// Tiny blocking HTTP/1.1 server that counts accepted connections and can keep
// them alive, close them after each response, or lie about keep-alive.
class connection_counting_server {
public:
  enum class behavior { keep_alive, close_after_response, close_socket_after_response };

  explicit connection_counting_server(behavior mode) : behavior_(mode) {}
  ~connection_counting_server() { stop(); }

  bool start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return false;
    int reuse = 1;
    (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) return false;
    if (::listen(listen_fd_, 16) < 0) return false;
    socklen_t length = sizeof(address);
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&address), &length) < 0) return false;
    port_ = ntohs(address.sin_port);
    thread_ = std::thread([this] { run(); });
    return true;
  }

  std::uint16_t port() const { return port_; }
  int accepts() const { return accepts_.load(); }

  void stop() {
    stop_.store(true);
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) {
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
  }

private:
  void run() {
    while (!stop_.load()) {
      pollfd descriptor{listen_fd_, POLLIN, 0};
      int ready = ::poll(&descriptor, 1, 50);
      if (ready <= 0) continue;
      int fd = ::accept(listen_fd_, nullptr, nullptr);
      if (fd < 0) continue;
      ++accepts_;
      handle(fd);
    }
  }

  void handle(int fd) {
    timeval timeout{};
    timeout.tv_usec = 100 * 1000;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    std::string buffer;
    while (!stop_.load()) {
      while (buffer.find("\r\n\r\n") == std::string::npos) {
        char chunk[4096];
        auto received = ::recv(fd, chunk, sizeof(chunk), 0);
        if (received == 0) {
          ::close(fd);
          return;
        }
        if (received < 0) {
          if (errno == EINTR) continue;
          if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
          ::close(fd);
          return;
        }
        buffer.append(chunk, static_cast<std::size_t>(received));
      }

      auto head_end = buffer.find("\r\n\r\n");
      bool close = behavior_ != behavior::keep_alive;
      std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n";
      if (close) response += "Connection: close\r\n";
      response += "\r\npong";
      if (!send_all(fd, response)) {
        ::close(fd);
        return;
      }
      buffer.erase(0, head_end + 4);
      if (behavior_ == behavior::close_after_response || behavior_ == behavior::close_socket_after_response) {
        ::close(fd);
        return;
      }
    }
    ::close(fd);
  }

  behavior behavior_;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0;
  std::atomic<bool> stop_{false};
  std::atomic<int> accepts_{0};
  std::thread thread_{};
};

struct api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }
};

} // namespace

int main() {
  {
    // Two requests reuse one pooled keep-alive connection.
    connection_counting_server server{connection_counting_server::behavior::keep_alive};
    CHECK(server.start());
    {
      trie::http::pooled_socket_transport transport{trie::http::endpoint{"127.0.0.1", server.port()}};

      trie::http::request first{};
      first.m = trie::method::get;
      first.target = "/one";
      auto first_response = transport.send(std::move(first));
      CHECK(first_response.has_value());
      CHECK_EQ(first_response->status_code, 200);
      CHECK_EQ(first_response->body, std::string{"pong"});
      CHECK_EQ(server.accepts(), 1);
      CHECK_EQ(transport.idle_connections(), std::size_t{1});

      trie::http::request second{};
      second.m = trie::method::get;
      second.target = "/two";
      auto second_response = transport.send(std::move(second));
      CHECK(second_response.has_value());
      CHECK_EQ(second_response->status_code, 200);
      CHECK_EQ(second_response->body, std::string{"pong"});
      CHECK_EQ(server.accepts(), 1);
      CHECK_EQ(transport.idle_connections(), std::size_t{1});
    }
    server.stop();
  }
  {
    // Connection: close responses are not pooled.
    connection_counting_server server{connection_counting_server::behavior::close_after_response};
    CHECK(server.start());
    {
      trie::http::pooled_socket_transport transport{trie::http::endpoint{"127.0.0.1", server.port()}};
      trie::http::request request{};
      request.target = "/one";
      CHECK(transport.send(request).has_value());
      CHECK_EQ(server.accepts(), 1);
      CHECK_EQ(transport.idle_connections(), std::size_t{0});
      CHECK(transport.send(request).has_value());
      CHECK_EQ(server.accepts(), 2);
    }
    server.stop();
  }
  {
    // A pooled connection silently closed by the peer is retried on a new one.
    connection_counting_server server{connection_counting_server::behavior::close_socket_after_response};
    CHECK(server.start());
    {
      trie::http::pooled_socket_transport transport{trie::http::endpoint{"127.0.0.1", server.port()}};
      trie::http::request request{};
      request.target = "/one";
      auto first = transport.send(request);
      CHECK(first.has_value());
      auto second = transport.send(request);
      CHECK(second.has_value());
      CHECK_EQ(second->body, std::string{"pong"});
      CHECK_EQ(server.accepts(), 2);
    }
    server.stop();
  }
  {
    // Works as the type-safe client's transport against the real server.
    trie::server<api> router;
    trie::http::listener<trie::server<api>> listener{router, trie::http::endpoint{"127.0.0.1", 0}};
    CHECK(listener.valid());
    std::thread server_thread{[&listener] { listener.run(); }};

    trie::client<api, trie::http::pooled_socket_transport> client{
        trie::http::pooled_socket_transport{trie::http::endpoint{"127.0.0.1", listener.port()}}};
    auto first = client.call<^^api::ping>();
    auto second = client.call<^^api::ping>();
    CHECK(first.has_value());
    CHECK(second.has_value());
    CHECK_EQ(*first, std::string{"pong"});
    CHECK_EQ(*second, std::string{"pong"});

    listener.stop();
    server_thread.join();
  }
  {
    // Connection failures are reported as transport errors.
    trie::http::pooled_socket_transport transport{trie::http::endpoint{"127.0.0.1", 1},
                                                  trie::http::pooled_socket_transport_options{100, 100}};
    trie::http::request request{};
    request.target = "/";
    auto response = transport.send(std::move(request));
    CHECK(!response.has_value());
    CHECK_EQ(response.error().status, 0);
  }
  return tst::report("pooled_transport_test");
}

#endif
