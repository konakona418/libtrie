#include "trie/trie.hh"
#include "trie/http/h2c_listener.hh"

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "h2_test_client.hh"
#include "harness.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

using namespace std::chrono_literals;

namespace {

struct api {
  [[=trie::get("/hello")]] std::string hello() { return "hello h2c"; }
  [[=trie::post("/echo")]] std::string echo([[=trie::body]] std::string_view body) {
    return std::string(body);
  }
  [[=trie::get("/json")]] trie::json::value json() {
    trie::json::value value;
    value["ok"] = true;
    return value;
  }
};

int connect_to(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  timeval timeout{};
  timeout.tv_sec = 3;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  timeval send_timeout{};
  send_timeout.tv_sec = 3;
  (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
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

} // namespace

int main() {
  trie::server<api> router;
  trie::http::serve_options options{};
  options.idle_timeout = 5000ms;
  options.drain_timeout = 1000ms;
  trie::http::h2c_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0}, options};
  CHECK(server.valid());
  std::thread runner{[&server] { server.run(); }};

  int fd = connect_to(server.port());
  CHECK(fd >= 0);
  {
    h2test::client client{fd};
    CHECK(client.valid());

    auto hello_id = client.request_and_wait("GET", "/hello");
    CHECK(hello_id >= 0);
    auto const& hello = client.get(hello_id);
    CHECK_EQ(hello.status, 200);
    CHECK_EQ(hello.body, std::string{"hello h2c"});
    CHECK_EQ(std::string{hello.header("content-length")}, std::string{"9"});

    auto echo_id = client.request_and_wait("POST", "/echo", "payload");
    CHECK(echo_id >= 0);
    auto const& echo = client.get(echo_id);
    CHECK_EQ(echo.status, 200);
    CHECK_EQ(echo.body, std::string{"payload"});

    auto json_id = client.request_and_wait("GET", "/json");
    CHECK(json_id >= 0);
    auto const& json = client.get(json_id);
    CHECK_EQ(json.status, 200);
    CHECK(json.body.find("\"ok\":true") != std::string::npos);

    auto missing_id = client.request_and_wait("GET", "/missing");
    CHECK(missing_id >= 0);
    CHECK_EQ(client.get(missing_id).status, 404);

    auto head_id = client.request_and_wait("HEAD", "/hello");
    CHECK(head_id >= 0);
    auto const& head = client.get(head_id);
    CHECK_EQ(head.status, 200);
    CHECK(head.body.empty());
    CHECK_EQ(std::string{head.header("content-length")}, std::string{"9"});

    // Two streams submitted before reading: both complete on one connection.
    auto first = client.submit("GET", "/hello");
    auto second = client.submit("GET", "/json");
    CHECK(first >= 0);
    CHECK(second >= 0);
    CHECK(client.wait(first));
    CHECK(client.wait(second));
    CHECK_EQ(client.get(first).status, 200);
    CHECK_EQ(client.get(second).status, 200);
  }
  ::close(fd);

  server.stop();
  runner.join();
  CHECK(server.stopping());
  CHECK(server.accepted_connections() >= 1);
  return tst::report("h2c_listener_test");
}

#endif
