#include "trie/trie.hh"

#include <arpa/inet.h>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "harness.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

struct api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }

  [[=trie::head("/ping")]] void ping_head(trie::http::response& response) {
    response.status_code = 200;
    response.body = "ignored";
  }

  [[=trie::post("/echo")]] void echo([[=trie::body]] std::string_view body, trie::http::response& response) {
    response.status_code = 201;
    response.body.assign(body.data(), body.size());
  }

  [[=trie::get("/status")]] trie::http::status status_only() { return trie::http::status::no_content; }
};

namespace {

int connect_to(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
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
    auto sent = ::send(fd, data.data(), data.size(), 0);
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

std::string_view response_body(std::string_view wire) {
  auto head_end = wire.find("\r\n\r\n");
  if (head_end == std::string_view::npos) return {};
  return wire.substr(head_end + 4);
}

// Reads exactly one response (headers + Content-Length body).
std::string read_response(int fd) {
  std::string data;
  char buffer[4096];
  std::size_t needed = std::string::npos;
  while (true) {
    if (needed == std::string::npos) {
      auto head_end = data.find("\r\n\r\n");
      if (head_end != std::string::npos) {
        std::string_view length_text = response_header(std::string_view{data}.substr(0, head_end), "content-length");
        std::size_t length = 0;
        if (!length_text.empty()) std::from_chars(length_text.data(), length_text.data() + length_text.size(), length);
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
  trie::server<api> router;
  trie::http::listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0}};
  CHECK(server.valid());
  CHECK(server.port() != 0);

  std::thread server_thread{[&server] { server.run(); }};
  const std::uint16_t port = server.port();

  {
    int fd = connect_to(port);
    CHECK(fd >= 0);
    CHECK(send_all(fd, "GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "200"));
    CHECK_EQ(response_body(wire), std::string_view{"pong"});
    CHECK_EQ(response_header(wire, "content-length"), std::string_view{"4"});
  }
  {
    int fd = connect_to(port);
    CHECK(fd >= 0);
    CHECK(send_all(fd, "POST /echo HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "201"));
    CHECK_EQ(response_body(wire), std::string_view{"hello"});
  }
  {
    int fd = connect_to(port);
    CHECK(send_all(fd, "GET /missing HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "404"));
  }
  {
    int fd = connect_to(port);
    CHECK(send_all(fd, "POST /ping HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "405"));
    auto allow = response_header(wire, "allow");
    CHECK(allow.find("GET") != std::string_view::npos);
    CHECK(allow.find("HEAD") != std::string_view::npos);
  }
  {
    // Keep-alive: three requests on one connection.
    int fd = connect_to(port);
    CHECK(send_all(fd, "GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto first = read_response(fd);
    CHECK(starts_with_status(first, "200"));
    CHECK_EQ(response_body(first), std::string_view{"pong"});

    CHECK(send_all(fd, "GET /status HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto second = read_response(fd);
    CHECK(starts_with_status(second, "204"));
    CHECK(response_body(second).empty());

    CHECK(send_all(fd, "GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto third = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(third, "200"));
    CHECK_EQ(response_body(third), std::string_view{"pong"});
  }
  {
    int fd = connect_to(port);
    CHECK(send_all(fd, "HEAD /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "200"));
    CHECK_EQ(response_header(wire, "content-length"), std::string_view{"7"});
    CHECK(response_body(wire).empty());
  }
  {
    int fd = connect_to(port);
    CHECK(send_all(fd, "BROKEN\r\n\r\n"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "400"));
  }
  {
    int fd = connect_to(port);
    CHECK(send_all(fd, "POST /echo HTTP/1.1\r\nHost: test\r\nContent-Length: 2000000\r\n\r\n"));
    auto wire = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(wire, "413"));
  }
  {
    // Pipelined requests in a single write are processed sequentially.
    int fd = connect_to(port);
    CHECK(send_all(fd, "GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"
                        "GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto first = read_response(fd);
    auto second = recv_until_close(fd);
    ::close(fd);
    CHECK(starts_with_status(first, "200"));
    CHECK_EQ(response_body(first), std::string_view{"pong"});
    CHECK(starts_with_status(second, "200"));
    CHECK_EQ(response_body(second), std::string_view{"pong"});
  }

  server.stop();
  server_thread.join();
  return tst::report("http_transport_test");
}

#endif
