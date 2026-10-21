#include "trie/trie.hh"

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "harness.hh"
#include "h2_test_client.hh"
#include "trie/http/h2.hh"

#if !defined(__linux__)
int main() { return 0; }
#else

struct person {
  std::string name;
  int age = 0;
};

struct api {
  [[=trie::get("/ping")]] std::string ping() { return "pong"; }

  [[=trie::post("/echo")]] void echo([[=trie::body]] std::string_view body,
                                     trie::http::response& response) {
    response.status_code = 201;
    response.body.assign(body.data(), body.size());
  }

  [[=trie::get("/headers")]] std::string header_echo([[=trie::header("x-test")]] std::string value) {
    return value;
  }

  [[=trie::get("/headers-out")]] void headers_out(trie::http::response& response) {
    response.set_header("X-Custom", "yes");
    response.set_header("Connection", "close");
    response.set_header("Transfer-Encoding", "chunked");
    response.body = "ok";
  }

  [[=trie::get("/person")]] person get_person() { return person{"alice", 30}; }

  [[=trie::post("/person")]] person echo_person([[=trie::body]] person value) { return value; }

  [[=trie::post("/json")]] trie::json::value echo_json([[=trie::body]] trie::json::value body) {
    return body;
  }

  [[=trie::get("/status")]] trie::http::status status_only() { return trie::http::status::no_content; }
};

namespace {

void set_recv_timeout(int fd) {
  timeval timeout{};
  timeout.tv_sec = 5;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

// Server half of the test transport: recv -> consume -> take_output -> send.
// Exits on EOF from the peer, a fatal protocol error, or a completed session.
template <class Router>
void serve(int fd, trie::http::h2_connection<Router>& connection) {
  char buffer[16384];
  for (;;) {
    std::string output = connection.take_output();
    if (!output.empty() && !h2test::write_all(fd, output)) return;
    if (connection.finished()) return;
    auto const received = ::recv(fd, buffer, sizeof(buffer), 0);
    if (received < 0) {
      if (errno == EINTR) continue;
      return;
    }
    if (received == 0) return;
    if (!connection.consume(std::string_view{buffer, static_cast<std::size_t>(received)})) return;
  }
}

// Owns a socketpair, an h2_connection and the server thread driving it.
template <class Router>
class test_connection {
public:
  explicit test_connection(Router& router, std::size_t max_request_body = 1024 * 1024)
      : connection_{router, max_request_body} {
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds_) != 0) {
      fds_[0] = -1;
      fds_[1] = -1;
      return;
    }
    set_recv_timeout(fds_[0]);
    set_recv_timeout(fds_[1]);
    thread_ = std::thread{[this] { serve(fds_[0], connection_); }};
  }

  ~test_connection() {
    stop();
    for (int& fd : fds_) {
      if (fd >= 0) ::close(fd);
      fd = -1;
    }
  }

  test_connection(test_connection const&) = delete;
  test_connection& operator=(test_connection const&) = delete;

  bool valid() const { return fds_[0] >= 0 && fds_[1] >= 0; }
  int client_fd() const { return fds_[1]; }
  trie::http::h2_connection<Router>& connection() { return connection_; }

  // Signals EOF to the server loop and waits for it to finish.
  void stop() {
    if (!thread_.joinable()) return;
    if (fds_[1] >= 0) ::shutdown(fds_[1], SHUT_WR);
    thread_.join();
  }

private:
  int fds_[2] = {-1, -1};
  trie::http::h2_connection<Router> connection_;
  std::thread thread_;
};

bool has_frame(std::string_view wire, uint8_t type) {
  std::size_t position = 0;
  while (position + 9 <= wire.size()) {
    std::size_t const length = (static_cast<std::size_t>(static_cast<unsigned char>(wire[position])) << 16) |
                               (static_cast<std::size_t>(static_cast<unsigned char>(wire[position + 1])) << 8) |
                               static_cast<std::size_t>(static_cast<unsigned char>(wire[position + 2]));
    if (static_cast<uint8_t>(wire[position + 3]) == type) return true;
    position += 9 + length;
  }
  return false;
}

bool has_exact_header(h2test::response const& response, std::string_view name) {
  for (auto const& header : response.headers)
    if (header.first == name) return true;
  return false;
}

} // namespace

int main() {
  {
    // One connection, many requests: basic verbs, JSON, error statuses,
    // HEAD/OPTIONS semantics, sequential and concurrent streams.
    trie::server<api> router;
    test_connection<trie::server<api>> server{router};
    CHECK(server.valid());

    router.on_validation_error([](trie::validation_failure const& failure, trie::http::context&) {
      trie::http::response response{};
      response.status_code = static_cast<int>(trie::http::status::unprocessable_content);
      response.set_header("Content-Type", "application/json");
      response.body = "{\"error\":\"" + failure.message + "\"}";
      return response;
    });

    {
      h2test::client client{server.client_fd()};
      CHECK(client.valid());

      // GET returns 200 + body.
      {
        int32_t const stream = client.request_and_wait("GET", "/ping");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 200);
        CHECK_EQ(response.body, std::string{"pong"});
        CHECK_EQ(response.header("content-length"), std::string_view{"4"});
      }

      // POST with a request body reaches the handler and echoes it.
      {
        int32_t const stream = client.request_and_wait("POST", "/echo", "hello");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 201);
        CHECK_EQ(response.body, std::string{"hello"});
        CHECK_EQ(response.header("content-length"), std::string_view{"5"});
      }

      // Regular request headers are forwarded to the router.
      {
        std::vector<std::pair<std::string, std::string>> headers{{"x-test", "forwarded"}};
        int32_t const stream = client.request_and_wait("GET", "/headers", {}, std::move(headers));
        CHECK(stream > 0);
        CHECK_EQ(client.get(stream).status, 200);
        CHECK_EQ(client.get(stream).body, std::string{"forwarded"});
      }

      // Response headers are lowercased and connection-specific fields dropped.
      {
        int32_t const stream = client.request_and_wait("GET", "/headers-out");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 200);
        CHECK_EQ(response.header("x-custom"), std::string_view{"yes"});
        CHECK(has_exact_header(response, "x-custom"));
        CHECK(response.header("connection").empty());
        CHECK(response.header("transfer-encoding").empty());
        CHECK_EQ(response.header("content-length"), std::string_view{"2"});
      }

      // Typed JSON body round-trips through the HTTP/2 engine.
      {
        int32_t const stream = client.request_and_wait("POST", "/person", R"({"name":"bob","age":41})");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 200);
        CHECK_EQ(response.header("content-type"), std::string_view{"application/json"});
        auto parsed = trie::json::parse_as<person>(response.body);
        CHECK(parsed.has_value());
        if (parsed.has_value()) {
          CHECK_EQ(parsed->name, std::string{"bob"});
          CHECK_EQ(parsed->age, 41);
        }
      }
      {
        int32_t const stream = client.request_and_wait("POST", "/json", R"({"a":[1,true,"x"]})");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 200);
        auto parsed = trie::json::parse(response.body);
        CHECK(parsed.has_value());
        if (parsed.has_value()) CHECK_EQ((*parsed)["a"][2].get<std::string>(), std::string{"x"});
      }

      // Schema validation failures are customized to 422 by the error hook.
      {
        int32_t const stream = client.request_and_wait("POST", "/person", R"({"age":3})");
        CHECK(stream > 0);
        CHECK_EQ(client.get(stream).status, 422);
        CHECK(client.get(stream).body.find("missing required field") != std::string::npos);
      }
      {
        int32_t const stream = client.request_and_wait("POST", "/person", "{bad json");
        CHECK(stream > 0);
        CHECK_EQ(client.get(stream).status, 422);
      }

      // Without the hook the same failures map to the default 400.
      router.on_validation_error(nullptr);
      {
        int32_t const stream = client.request_and_wait("POST", "/person", R"({"age":3})");
        CHECK(stream > 0);
        CHECK_EQ(client.get(stream).status, 400);
        CHECK(client.get(stream).body.find("missing required field") != std::string::npos);
      }

      // 404 for an unknown path.
      {
        int32_t const stream = client.request_and_wait("GET", "/missing");
        CHECK(stream > 0);
        CHECK_EQ(client.get(stream).status, 404);
        CHECK_EQ(client.get(stream).body, std::string{"not found"});
      }

      // 405 for a known path with the wrong method, including the Allow list.
      {
        int32_t const stream = client.request_and_wait("POST", "/ping");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 405);
        auto const allow = response.header("allow");
        CHECK(allow.find("GET") != std::string_view::npos);
        CHECK(allow.find("HEAD") != std::string_view::npos);
      }

      // HEAD: no DATA, but the GET Content-Length is preserved.
      {
        int32_t const stream = client.request_and_wait("HEAD", "/ping");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 200);
        CHECK_EQ(response.header("content-length"), std::string_view{"4"});
        CHECK(response.body.empty());
        CHECK_EQ(response.data_chunks, std::size_t{0});
      }

      // Automatic OPTIONS: 204 + Allow.
      {
        int32_t const stream = client.request_and_wait("OPTIONS", "/ping");
        CHECK(stream > 0);
        auto const& response = client.get(stream);
        CHECK_EQ(response.status, 204);
        CHECK(response.body.empty());
        CHECK(response.header("content-length").empty());
        auto const allow = response.header("allow");
        CHECK(allow.find("GET") != std::string_view::npos);
        CHECK(allow.find("HEAD") != std::string_view::npos);
      }

      // Multiple sequential requests on one connection.
      {
        int32_t const first = client.request_and_wait("GET", "/ping");
        CHECK(first > 0);
        CHECK_EQ(client.get(first).status, 200);
        CHECK_EQ(client.get(first).body, std::string{"pong"});

        int32_t const second = client.request_and_wait("GET", "/status");
        CHECK(second > 0);
        CHECK_EQ(client.get(second).status, 204);
        CHECK(client.get(second).body.empty());

        int32_t const third = client.request_and_wait("GET", "/person");
        CHECK(third > 0);
        CHECK_EQ(client.get(third).status, 200);
      }

      // Two concurrent streams: submit both before reading either response.
      {
        int32_t const first = client.submit("GET", "/ping");
        int32_t const second = client.submit("GET", "/person");
        CHECK(first > 0);
        CHECK(second > 0);
        CHECK(first != second);
        CHECK(client.flush());
        CHECK(client.wait(first));
        CHECK(client.wait(second));
        CHECK_EQ(client.get(first).status, 200);
        CHECK_EQ(client.get(first).body, std::string{"pong"});
        CHECK_EQ(client.get(second).status, 200);
        auto parsed = trie::json::parse_as<person>(client.get(second).body);
        CHECK(parsed.has_value());
        if (parsed.has_value()) CHECK_EQ(parsed->name, std::string{"alice"});
      }

      // A body larger than one HTTP/2 frame (and the initial flow-control
      // window) is split and reassembled by nghttp2 in both directions.
      {
        std::string const payload(128 * 1024, 'q');
        int32_t const stream = client.request_and_wait("POST", "/echo", payload);
        CHECK(stream > 0);
        CHECK_EQ(client.get(stream).status, 201);
        CHECK(client.get(stream).body == payload);
      }

      // Unknown method -> 501, without reaching the router.
      {
        int32_t const stream = client.request_and_wait("BREW", "/ping");
        CHECK(stream > 0);
        CHECK_EQ(client.get(stream).status, 501);
        CHECK_EQ(client.get(stream).body, std::string{"unsupported method"});
      }

      CHECK(!client.failed());
    }

    server.stop();
    CHECK(server.connection().error().empty());
    CHECK_EQ(server.connection().requests_handled(), std::size_t{20});
  }

  {
    // A request body over max_request_body is rejected with 413.
    trie::server<api> router;
    test_connection<trie::server<api>> server{router, 8};
    CHECK(server.valid());
    {
      h2test::client client{server.client_fd()};
      CHECK(client.valid());
      int32_t const stream = client.request_and_wait("POST", "/echo", "123456789");
      CHECK(stream > 0);
      auto const& response = client.get(stream);
      CHECK_EQ(response.status, 413);
      CHECK_EQ(response.body, std::string{"request body too large"});
      CHECK(!client.failed());
    }
    server.stop();
    CHECK(server.connection().error().empty());
    CHECK_EQ(server.connection().requests_handled(), std::size_t{1});
  }

  {
    // shutdown() queues GOAWAY through take_output() and finishes the session.
    trie::server<api> router;
    trie::http::h2_connection<trie::server<api>> connection{router};
    std::string const initial = connection.take_output();
    CHECK(!initial.empty());
    CHECK(!connection.finished());
    CHECK_EQ(connection.requests_handled(), std::size_t{0});

    connection.shutdown();
    std::string const goaway = connection.take_output();
    CHECK(!goaway.empty());
    CHECK(has_frame(goaway, NGHTTP2_GOAWAY));
    CHECK(connection.finished());
    CHECK(connection.error().empty());
  }

  {
    // A non-HTTP/2 peer is a fatal protocol error, reported via error().
    trie::server<api> router;
    trie::http::h2_connection<trie::server<api>> connection{router};
    (void)connection.take_output();
    CHECK(!connection.consume("GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    CHECK(connection.finished());
    CHECK(!connection.error().empty());
  }

  return tst::report("h2_connection_test");
}

#endif
