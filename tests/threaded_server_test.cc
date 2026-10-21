#include "trie/trie.hh"

#include <arpa/inet.h>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <netinet/in.h>
#include <set>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "harness.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

using namespace std::chrono_literals;

namespace {

struct threaded_api {
  std::atomic<int> pings{0};

  [[=trie::get("/ping")]] std::string ping() {
    pings.fetch_add(1, std::memory_order_relaxed);
    return "pong";
  }

  [[=trie::get("/thread")]] std::string thread_id() {
    return std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
  }
};

int connect_to(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  timeval timeout{};
  timeout.tv_sec = 2;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

bool send_all(int fd, std::string_view data) {
  while (!data.empty()) {
    auto sent = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
    if (sent <= 0) return false;
    data.remove_prefix(static_cast<std::size_t>(sent));
  }
  return true;
}

std::string recv_until_close(int fd) {
  std::string data;
  char buffer[4096];
  while (true) {
    auto received = ::recv(fd, buffer, sizeof(buffer), 0);
    if (received <= 0) break;
    data.append(buffer, static_cast<std::size_t>(received));
  }
  return data;
}

std::string read_one_response(int fd) {
  std::string data;
  char buffer[4096];
  std::size_t needed = std::string::npos;
  while (true) {
    if (needed == std::string::npos) {
      auto head_end = data.find("\r\n\r\n");
      if (head_end != std::string::npos) {
        std::string_view head{data.data(), head_end};
        std::string_view length_text;
        std::size_t position = head.find("\r\n");
        position = position == std::string_view::npos ? head.size() : position + 2;
        while (position < head.size()) {
          auto end = head.find("\r\n", position);
          std::string_view line =
              head.substr(position, end == std::string_view::npos ? head.size() - position : end - position);
          auto colon = line.find(':');
          if (colon != std::string_view::npos && trie::http::iequals(line.substr(0, colon), "content-length")) {
            length_text = line.substr(colon + 1);
            while (!length_text.empty() && length_text.front() == ' ') length_text.remove_prefix(1);
          }
          position = end == std::string_view::npos ? head.size() : end + 2;
        }
        std::size_t length = 0;
        if (!length_text.empty())
          std::from_chars(length_text.data(), length_text.data() + length_text.size(), length);
        needed = head_end + 4 + length;
      }
    }
    if (needed != std::string::npos && data.size() >= needed) return data.substr(0, needed);
    auto received = ::recv(fd, buffer, sizeof(buffer), 0);
    if (received <= 0) return data;
    data.append(buffer, static_cast<std::size_t>(received));
  }
}

bool starts_with_status(std::string_view wire, std::string_view status) {
  return wire.starts_with("HTTP/1.1 ") && wire.substr(9).starts_with(status);
}

} // namespace

int main() {
  {
    // Four workers sharing one port via SO_REUSEPORT.
    trie::server<threaded_api> router;
    trie::http::serve_options options{};
    options.idle_timeout = 5000ms;
    options.drain_timeout = 1000ms;
    trie::http::threaded_listener<trie::server<threaded_api>> server{
        router, trie::http::endpoint{"127.0.0.1", 0}, options, 4};
    CHECK(server.valid());
    CHECK_EQ(server.workers(), std::size_t{4});
    CHECK(server.port() != 0);

    std::thread runner{[&server] { server.run(); }};

    // 4 concurrent clients x 25 requests, each request uses its own connection.
    std::atomic<int> successes{0};
    std::vector<std::thread> clients;
    clients.reserve(4);
    for (int t = 0; t < 4; ++t) {
      clients.emplace_back([&server, &successes] {
        trie::client<threaded_api, trie::http::socket_transport> client{
            trie::http::socket_transport{trie::http::endpoint{"127.0.0.1", server.port()}}};
        for (int i = 0; i < 25; ++i) {
          auto result = client.call<^^threaded_api::ping>();
          if (result.has_value() && *result == "pong") successes.fetch_add(1);
        }
      });
    }
    for (auto& client : clients) client.join();
    CHECK_EQ(successes.load(), 100);
    CHECK_EQ(router.controller<threaded_api>().pings.load(), 100);
    CHECK_EQ(server.accepted_connections(), std::size_t{100});

    // Connections are spread over multiple worker loops.
    trie::client<threaded_api, trie::http::socket_transport> client{
        trie::http::socket_transport{trie::http::endpoint{"127.0.0.1", server.port()}}};
    std::set<std::string> worker_ids;
    for (int i = 0; i < 100; ++i) {
      auto result = client.call<^^threaded_api::thread_id>();
      CHECK(result.has_value());
      if (result.has_value()) worker_ids.insert(*result);
    }
    CHECK(worker_ids.size() >= 2);

    auto const per_worker = server.accepted_per_worker();
    CHECK_EQ(per_worker.size(), std::size_t{4});
    std::size_t busy_workers = 0;
    for (std::size_t count : per_worker) busy_workers += count > 0 ? 1 : 0;
    CHECK(busy_workers >= 2);

    server.stop();
    runner.join();
  }
  {
    // Global connection cap shared across workers: third connection gets 503.
    trie::server<threaded_api> router;
    trie::http::serve_options options{};
    options.max_connections = 2;
    options.idle_timeout = 5000ms;
    options.drain_timeout = 1000ms;
    trie::http::threaded_listener<trie::server<threaded_api>> server{
        router, trie::http::endpoint{"127.0.0.1", 0}, options, 2};
    CHECK(server.valid());
    std::thread runner{[&server] { server.run(); }};

    int first = connect_to(server.port());
    CHECK(first >= 0);
    CHECK(send_all(first, "GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto first_response = read_one_response(first);
    CHECK(starts_with_status(first_response, "200"));

    int second = connect_to(server.port());
    CHECK(second >= 0);
    CHECK(send_all(second, "GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto second_response = read_one_response(second);
    CHECK(starts_with_status(second_response, "200"));

    int rejected = connect_to(server.port());
    CHECK(rejected >= 0);
    CHECK(send_all(rejected, "GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto rejected_response = recv_until_close(rejected);
    ::close(rejected);
    CHECK(starts_with_status(rejected_response, "503"));

    // Closing one connection releases the slot for a new one.
    ::close(first);
    std::string recovered;
    int recovered_fd = -1;
    for (int attempt = 0; attempt < 100; ++attempt) {
      std::this_thread::sleep_for(10ms);
      recovered_fd = connect_to(server.port());
      if (recovered_fd < 0) continue;
      CHECK(send_all(recovered_fd, "GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
      recovered = recv_until_close(recovered_fd);
      ::close(recovered_fd);
      if (starts_with_status(recovered, "200")) break;
    }
    CHECK(starts_with_status(recovered, "200"));

    ::close(second);
    server.stop();
    runner.join();
  }
  return tst::report("threaded_server_test");
}

#endif
