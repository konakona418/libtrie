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

bool starts_with_status(std::string_view wire, std::string_view status) {
  return wire.starts_with("HTTP/1.1 ") && wire.substr(9).starts_with(status);
}

// Buffered blocking client: keeps leftover bytes between responses so pipelined
// and keep-alive tests don't depend on TCP segment boundaries.
class connection {
public:
  connection() = default;
  connection(connection const&) = delete;
  connection& operator=(connection const&) = delete;

  ~connection() { close(); }

  bool open(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) return false;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
      close();
      return false;
    }
    return true;
  }

  bool send(std::string_view data) {
    while (!data.empty()) {
      auto sent = ::send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
      if (sent <= 0) return false;
      data.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
  }

  std::string read_response() {
    while (true) {
      auto head_end = buffer_.find("\r\n\r\n");
      if (head_end != std::string::npos) {
        std::string_view head{buffer_.data(), head_end};
        std::string_view length_text = response_header(head, "content-length");
        std::size_t length = 0;
        if (!length_text.empty())
          std::from_chars(length_text.data(), length_text.data() + length_text.size(), length);
        std::size_t total = head_end + 4 + length;
        if (buffer_.size() >= total) {
          std::string out = buffer_.substr(0, total);
          buffer_.erase(0, total);
          return out;
        }
      }
      char chunk[4096];
      auto received = ::recv(fd_, chunk, sizeof(chunk), 0);
      if (received <= 0) {
        std::string out = std::move(buffer_);
        buffer_.clear();
        return out;
      }
      buffer_.append(chunk, static_cast<std::size_t>(received));
    }
  }

  std::string read_until_close() {
    char chunk[4096];
    while (true) {
      auto received = ::recv(fd_, chunk, sizeof(chunk), 0);
      if (received <= 0) break;
      buffer_.append(chunk, static_cast<std::size_t>(received));
    }
    std::string out = std::move(buffer_);
    buffer_.clear();
    return out;
  }

  void close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
  }

private:
  int fd_ = -1;
  std::string buffer_;
};

} // namespace

int main() {
  trie::server<api> router;
  trie::http::listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0}};
  CHECK(server.valid());
  CHECK(server.port() != 0);

  std::thread server_thread{[&server] { server.run(); }};
  const std::uint16_t port = server.port();

  {
    connection client;
    CHECK(client.open(port));
    CHECK(client.send("GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto wire = client.read_until_close();
    CHECK(starts_with_status(wire, "200"));
    CHECK_EQ(response_body(wire), std::string_view{"pong"});
    CHECK_EQ(response_header(wire, "content-length"), std::string_view{"4"});
  }
  {
    connection client;
    CHECK(client.open(port));
    CHECK(client.send(
        "POST /echo HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"));
    auto wire = client.read_until_close();
    CHECK(starts_with_status(wire, "201"));
    CHECK_EQ(response_body(wire), std::string_view{"hello"});
  }
  {
    connection client;
    CHECK(client.open(port));
    CHECK(client.send("GET /missing HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto wire = client.read_until_close();
    CHECK(starts_with_status(wire, "404"));
  }
  {
    connection client;
    CHECK(client.open(port));
    CHECK(client.send(
        "POST /ping HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
    auto wire = client.read_until_close();
    CHECK(starts_with_status(wire, "405"));
    auto allow = response_header(wire, "allow");
    CHECK(allow.find("GET") != std::string_view::npos);
    CHECK(allow.find("HEAD") != std::string_view::npos);
  }
  {
    // Keep-alive: three requests on one connection.
    connection client;
    CHECK(client.open(port));

    CHECK(client.send("GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto first = client.read_response();
    CHECK(starts_with_status(first, "200"));
    CHECK_EQ(response_body(first), std::string_view{"pong"});

    CHECK(client.send("GET /status HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto second = client.read_response();
    CHECK(starts_with_status(second, "204"));
    CHECK(response_body(second).empty());

    CHECK(client.send("GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto third = client.read_until_close();
    CHECK(starts_with_status(third, "200"));
    CHECK_EQ(response_body(third), std::string_view{"pong"});
  }
  {
    connection client;
    CHECK(client.open(port));
    CHECK(client.send("HEAD /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto wire = client.read_until_close();
    CHECK(starts_with_status(wire, "200"));
    CHECK_EQ(response_header(wire, "content-length"), std::string_view{"7"});
    CHECK(response_body(wire).empty());
  }
  {
    connection client;
    CHECK(client.open(port));
    CHECK(client.send("BROKEN\r\n\r\n"));
    auto wire = client.read_until_close();
    CHECK(starts_with_status(wire, "400"));
  }
  {
    connection client;
    CHECK(client.open(port));
    CHECK(client.send("POST /echo HTTP/1.1\r\nHost: test\r\nContent-Length: 2000000\r\n\r\n"));
    auto wire = client.read_until_close();
    CHECK(starts_with_status(wire, "413"));
  }
  {
    // Pipelined requests in a single write are processed sequentially.
    connection client;
    CHECK(client.open(port));
    CHECK(client.send("GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"
                      "GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto first = client.read_response();
    auto second = client.read_response();
    CHECK(starts_with_status(first, "200"));
    CHECK_EQ(response_body(first), std::string_view{"pong"});
    CHECK(starts_with_status(second, "200"));
    CHECK_EQ(response_body(second), std::string_view{"pong"});
  }
  {
    // Two concurrent connections interleaved on the event loop.
    connection first;
    connection second;
    CHECK(first.open(port));
    CHECK(second.open(port));
    CHECK(first.send("GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    CHECK(second.send("GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
    auto first_wire = first.read_until_close();
    auto second_wire = second.read_until_close();
    CHECK(starts_with_status(first_wire, "200"));
    CHECK(starts_with_status(second_wire, "200"));
    CHECK_EQ(response_body(first_wire), std::string_view{"pong"});
    CHECK_EQ(response_body(second_wire), std::string_view{"pong"});
  }

  server.stop();
  server_thread.join();
  return tst::report("http_transport_test");
}

#endif
