#include "trie/trie.hh"

#include <arpa/inet.h>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

#include "harness.hh"

using namespace std::chrono_literals;

#if !defined(__linux__)
int main() { return 0; }
#else

namespace {

struct slow_state {
  std::atomic<bool> started{false};
};

struct api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }
};

// A controller whose handler sets a flag, sleeps, then responds; used to verify
// that in-flight requests are drained before the loop exits.
struct slow_api {
  slow_state* state = nullptr;

  [[=trie::get("/slow")]] std::string slow() {
    state->started.store(true);
    std::this_thread::sleep_for(100ms);
    return "slow";
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

std::string_view response_header(std::string_view wire, std::string_view name) {
  auto line_end = wire.find("\r\n");
  if (line_end == std::string_view::npos) return {};
  std::size_t position = line_end + 2;
  while (position < wire.size()) {
    auto end = wire.find("\r\n", position);
    std::string_view line =
        wire.substr(position, end == std::string_view::npos ? wire.size() - position : end - position);
    auto colon = line.find(':');
    if (colon != std::string_view::npos) {
      std::string_view key = line.substr(0, colon);
      std::string_view value = line.substr(colon + 1);
      while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
      if (trie::http::iequals(key, name)) return value;
    }
    position = end == std::string_view::npos ? wire.size() : end + 2;
  }
  return {};
}

bool starts_with_status(std::string_view wire, std::string_view status) {
  return wire.starts_with("HTTP/1.1 ") && wire.substr(9).starts_with(status);
}

// Reads exactly one response, keeping leftover bytes for the next call.
struct response_reader {
  std::string buffer{};

  std::string read_response(int fd) {
    while (true) {
      auto head_end = buffer.find("\r\n\r\n");
      if (head_end != std::string::npos) {
        std::string_view length_text = response_header(std::string_view{buffer}.substr(0, head_end), "content-length");
        std::size_t length = 0;
        if (!length_text.empty())
          std::from_chars(length_text.data(), length_text.data() + length_text.size(), length);
        std::size_t total = head_end + 4 + length;
        if (buffer.size() >= total) {
          std::string out = buffer.substr(0, total);
          buffer.erase(0, total);
          return out;
        }
      }
      char chunk[4096];
      auto received = ::recv(fd, chunk, sizeof(chunk), 0);
      if (received <= 0) {
        std::string out = std::move(buffer);
        buffer.clear();
        return out;
      }
      buffer.append(chunk, static_cast<std::size_t>(received));
    }
  }
};

trie::http::serve_options fast_options() {
  trie::http::serve_options options{};
  options.io_timeout = 100ms;
  options.request_timeout = 300ms;
  options.idle_timeout = 150ms;
  options.drain_timeout = 500ms;
  return options;
}

} // namespace

int main() {
  {
    // Idle keep-alive connections are closed after idle_timeout.
    trie::server<api> router;
    trie::http::listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                   fast_options()};
    CHECK(server.valid());
    std::thread thread{[&server] { server.run(); }};

    int fd = connect_to(server.port());
    CHECK(fd >= 0);
    std::string data = recv_until_close(fd); // no request sent
    ::close(fd);
    CHECK(data.empty());          // server closed silently
    CHECK(server.stopping() == false);

    server.stop();
    thread.join();
  }
  {
    // A partially received request gets a 408 after the read timeout.
    trie::server<api> router;
    trie::http::listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                   fast_options()};
    std::thread thread{[&server] { server.run(); }};

    int fd = connect_to(server.port());
    CHECK(send_all(fd, "GET /ping HTTP/1.1\r\nHost: test\r\n")); // no terminating CRLF
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "408"));

    server.stop();
    thread.join();
  }
  {
    // Timeout while waiting for a body.
    trie::server<api> router;
    trie::http::listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                   fast_options()};
    std::thread thread{[&server] { server.run(); }};

    int fd = connect_to(server.port());
    CHECK(send_all(fd, "POST /ping HTTP/1.1\r\nHost: test\r\nContent-Length: 10\r\n\r\nabc"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "408"));

    server.stop();
    thread.join();
  }
  {
    // stop() closes idle keep-alive connections and run() returns promptly.
    trie::server<api> router;
    trie::http::listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                   fast_options()};
    std::thread thread{[&server] { server.run(); }};

    int fd = connect_to(server.port());
    CHECK(send_all(fd, "GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    response_reader reader;
    auto first = reader.read_response(fd);
    CHECK(starts_with_status(first, "200"));

    auto const started = std::chrono::steady_clock::now();
    server.stop();
    thread.join();
    auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(elapsed < 2s);

    // The server closed the idle connection during draining.
    char chunk[16];
    CHECK_EQ(::recv(fd, chunk, sizeof(chunk), 0), ssize_t{0});
    ::close(fd);
  }
  {
    // In-flight requests are allowed to finish during drain.
    slow_state state{};
    trie::server<slow_api> router;
    // server<...> owns its controller; configure the owned instance instead.
    router.controller<slow_api>().state = &state;

    trie::http::listener<trie::server<slow_api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                        fast_options()};
    std::thread thread{[&server] { server.run(); }};

    int fd = connect_to(server.port());
    CHECK(send_all(fd, "GET /slow HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));

    while (!state.started.load()) std::this_thread::sleep_for(1ms);
    server.stop();
    thread.join();

    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "200"));
    CHECK(wire.find("slow") != std::string::npos);
  }
  return tst::report("http_server_timeout_test");
}

#endif
