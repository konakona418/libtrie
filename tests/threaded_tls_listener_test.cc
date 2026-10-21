#include "trie/trie.hh"

#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "harness.hh"
#include "trie/http/threaded_tls_listener.hh"
#include "trie/http/tls_transport.hh"

using namespace std::chrono_literals;

#if !defined(__linux__)
int main() { return 0; }
#else

namespace {

// tests/data holds the test certificates. Tests run from the repo root or from
// a build directory, so look in a few plausible places (an explicit
// -DTRIE_TEST_DATA_DIR=... wins if provided).
std::string const& test_data_dir() {
  static std::string directory = [] {
    std::vector<std::string> candidates;
#if defined(TRIE_TEST_DATA_DIR)
    candidates.emplace_back(TRIE_TEST_DATA_DIR);
#endif
    std::string source{__FILE__};
    auto slash = source.find_last_of('/');
    std::string source_dir = slash == std::string::npos ? std::string{"."} : source.substr(0, slash);
    candidates.push_back(source_dir + "/data");
    candidates.emplace_back("tests/data");
    candidates.emplace_back("../tests/data");
    candidates.emplace_back("../../tests/data");
    for (auto const& candidate : candidates) {
      std::ifstream stream{(candidate + "/server.crt").c_str()};
      if (stream.good()) return candidate;
    }
    return std::string{"tests/data"};
  }();
  return directory;
}

std::string_view response_body(std::string_view wire) {
  auto head_end = wire.find("\r\n\r\n");
  if (head_end == std::string_view::npos) return {};
  return wire.substr(head_end + 4);
}

bool starts_with_status(std::string_view wire, std::string_view status) {
  return wire.starts_with("HTTP/1.1 ") && wire.substr(9).starts_with(status);
}

std::size_t response_content_length(std::string_view head) {
  std::size_t position = head.find("\r\n");
  if (position == std::string_view::npos) return 0;
  position += 2;
  while (position < head.size()) {
    auto end = head.find("\r\n", position);
    // The final header line is not CRLF-terminated: `head` excludes the blank line.
    std::string_view line =
        end == std::string_view::npos ? head.substr(position) : head.substr(position, end - position);
    auto colon = line.find(':');
    if (colon != std::string_view::npos && trie::http::iequals(line.substr(0, colon), "content-length")) {
      std::string_view value = line.substr(colon + 1);
      while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
      std::size_t length = 0;
      (void)std::from_chars(value.data(), value.data() + value.size(), length);
      return length;
    }
    if (end == std::string_view::npos) break;
    position = end + 2;
  }
  return 0;
}

// Tiny blocking TLS client for the cases tls_transport cannot express:
// keep-alive connections (it always sends Connection: close) and holding
// connections open to exhaust the global connection cap.
class raw_tls_client {
public:
  raw_tls_client() = default;
  raw_tls_client(raw_tls_client const&) = delete;
  raw_tls_client& operator=(raw_tls_client const&) = delete;
  ~raw_tls_client() { close(); }

  bool connect(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) return false;
    timeval timeout{2, 0};
    (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
      close();
      return false;
    }

    ctx_ = SSL_CTX_new(TLS_client_method());
    if (ctx_ == nullptr) {
      close();
      return false;
    }
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    ssl_ = SSL_new(ctx_);
    if (ssl_ == nullptr) {
      close();
      return false;
    }
    (void)SSL_set_fd(ssl_, fd_);
    if (SSL_connect(ssl_) != 1) {
      close();
      return false;
    }
    return true;
  }

  bool send_all(std::string_view data) {
    while (!data.empty()) {
      int sent = SSL_write(ssl_, data.data(), static_cast<int>(data.size()));
      if (sent <= 0) return false;
      data.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
  }

  // Reads exactly one Content-Length delimited response (keep-alive tests).
  std::string read_response() {
    while (true) {
      auto head_end = buffer_.find("\r\n\r\n");
      if (head_end != std::string::npos) {
        std::size_t const total =
            head_end + 4 + response_content_length(std::string_view{buffer_}.substr(0, head_end));
        if (buffer_.size() >= total) {
          std::string out = buffer_.substr(0, total);
          buffer_.erase(0, total);
          return out;
        }
      }
      std::array<char, 4096> chunk{};
      int received = SSL_read(ssl_, chunk.data(), static_cast<int>(chunk.size()));
      if (received <= 0) {
        std::string out = std::move(buffer_);
        buffer_.clear();
        return out;
      }
      buffer_.append(chunk.data(), static_cast<std::size_t>(received));
    }
  }

  std::string read_until_eof() {
    std::string out = std::move(buffer_);
    buffer_.clear();
    std::array<char, 4096> chunk{};
    while (true) {
      int received = SSL_read(ssl_, chunk.data(), static_cast<int>(chunk.size()));
      if (received <= 0) break; // ZERO_RETURN/SYSCALL or the 2s socket timeout
      out.append(chunk.data(), static_cast<std::size_t>(received));
    }
    return out;
  }

  void close() {
    if (ssl_ != nullptr) {
      SSL_free(ssl_);
      ssl_ = nullptr;
    }
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

private:
  int fd_ = -1;
  SSL_CTX* ctx_ = nullptr;
  SSL* ssl_ = nullptr;
  std::string buffer_;
};

struct api {
  std::atomic<int>* ping_count = nullptr;
  std::atomic<bool>* slow_started = nullptr;

  [[=trie::get("/ping")]] std::string ping() {
    if (ping_count != nullptr) ping_count->fetch_add(1, std::memory_order_relaxed);
    return "pong";
  }

  [[=trie::get("/slow")]] std::string slow() {
    if (slow_started != nullptr) slow_started->store(true, std::memory_order_relaxed);
    std::this_thread::sleep_for(100ms);
    return "slow";
  }
};

trie::http::tls_transport_options client_options() {
  trie::http::tls_transport_options options{};
  options.verify_peer = false;
  return options;
}

trie::http::request get_request(std::string target) {
  trie::http::request request{};
  request.m = trie::method::get;
  request.target = std::move(target);
  return request;
}

} // namespace

int main() {
  std::string const data_dir = test_data_dir();
  std::string const server_cert = data_dir + "/server.crt";
  std::string const server_key = data_dir + "/server.key";

  auto make_options = [&] {
    trie::http::tls_serve_options options{};
    options.certificate_chain_file = server_cert;
    options.private_key_file = server_key;
    return options;
  };

  // --- 4 workers, concurrent HTTPS clients --------------------------------
  {
    trie::server<api> router;
    std::atomic<int> handled{0};
    router.controller<api>().ping_count = &handled;

    trie::http::threaded_tls_listener<trie::server<api>> server{
        router, trie::http::endpoint{"127.0.0.1", 0}, make_options(), 4};
    CHECK(server.valid());
    CHECK_EQ(server.error_code(), 0);
    CHECK_EQ(server.workers(), std::size_t{4});
    CHECK(server.port() != 0);
    CHECK(!server.stopping());

    std::thread run_thread{[&server] { server.run(); }};

    std::atomic<int> failures{0};
    std::vector<std::thread> clients;
    clients.reserve(4);
    for (int i = 0; i < 4; ++i) {
      clients.emplace_back([&server, &failures, server_cert] {
        trie::client<api, trie::http::tls_transport> client{trie::http::tls_transport{
            trie::http::endpoint{"127.0.0.1", server.port()}, client_options()}};
        for (int request = 0; request < 25; ++request) {
          auto result = client.call<^^api::ping>();
          if (!result.has_value() || *result != std::string{"pong"}) failures.fetch_add(1);
        }
      });
    }
    for (auto& client_thread : clients) client_thread.join();

    CHECK_EQ(failures.load(), 0);
    CHECK_EQ(handled.load(), 100);
    CHECK_EQ(server.accepted_connections(), std::size_t{100});

    auto const per_worker = server.accepted_per_worker();
    CHECK_EQ(per_worker.size(), std::size_t{4});
    std::size_t sum = 0;
    std::size_t busy_workers = 0;
    for (std::size_t count : per_worker) {
      sum += count;
      if (count > 0) ++busy_workers;
    }
    CHECK_EQ(sum, std::size_t{100});
    CHECK_EQ(sum, server.accepted_connections());
    CHECK(busy_workers >= 2);

    // An idle keep-alive TLS connection is drained when stop() is called.
    raw_tls_client idle;
    CHECK(idle.connect(server.port()));
    CHECK(idle.send_all("GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto idle_response = idle.read_response();
    CHECK(starts_with_status(idle_response, "200"));
    CHECK_EQ(response_body(idle_response), std::string_view{"pong"});
    CHECK(server.accepted_connections() >= 101);

    auto const drain_started = std::chrono::steady_clock::now();
    server.stop();
    run_thread.join();
    auto const drain_elapsed = std::chrono::steady_clock::now() - drain_started;
    CHECK(server.stopping());
    CHECK(drain_elapsed < 2s);
    CHECK(idle.read_until_eof().empty()); // connection was closed by the drain
  }

  // --- in-flight request completes during drain ---------------------------
  {
    trie::server<api> router;
    std::atomic<bool> slow_started{false};
    router.controller<api>().slow_started = &slow_started;

    trie::http::threaded_tls_listener<trie::server<api>> server{
        router, trie::http::endpoint{"127.0.0.1", 0}, make_options(), 2};
    CHECK(server.valid());
    CHECK_EQ(server.workers(), std::size_t{2});
    std::thread run_thread{[&server] { server.run(); }};

    raw_tls_client idle;
    CHECK(idle.connect(server.port())); // idle keep-alive connection, no request

    std::string slow_body{"unset"};
    std::thread slow_client{[&server, &slow_body] {
      trie::http::tls_transport transport{trie::http::endpoint{"127.0.0.1", server.port()}, client_options()};
      auto response = transport.send(get_request("/slow"));
      if (response) slow_body = std::move(response->body);
    }};

    auto const wait_deadline = std::chrono::steady_clock::now() + 2s;
    while (!slow_started.load(std::memory_order_relaxed) && std::chrono::steady_clock::now() < wait_deadline)
      std::this_thread::sleep_for(1ms);
    CHECK(slow_started.load(std::memory_order_relaxed));

    auto const drain_started = std::chrono::steady_clock::now();
    server.stop();
    run_thread.join();
    slow_client.join();
    auto const drain_elapsed = std::chrono::steady_clock::now() - drain_started;

    CHECK(server.stopping());
    CHECK(drain_elapsed < 2s);
    CHECK_EQ(slow_body, std::string{"slow"});
    CHECK(idle.read_until_eof().empty());
  }

  // --- global connection cap across 2 workers -----------------------------
  {
    trie::server<api> router;
    trie::http::tls_serve_options options = make_options();
    options.http.max_connections = 2;
    trie::http::threaded_tls_listener<trie::server<api>> server{
        router, trie::http::endpoint{"127.0.0.1", 0}, options, 2};
    CHECK(server.valid());
    CHECK_EQ(server.workers(), std::size_t{2});
    std::thread run_thread{[&server] { server.run(); }};

    // Fill the global cap with two keep-alive connections...
    raw_tls_client first;
    raw_tls_client second;
    CHECK(first.connect(server.port()));
    CHECK(second.connect(server.port()));
    CHECK(first.send_all("GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto first_response = first.read_response();
    CHECK_EQ(response_body(first_response), std::string_view{"pong"});
    CHECK(second.send_all("GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"));
    auto second_response = second.read_response();
    CHECK_EQ(response_body(second_response), std::string_view{"pong"});
    CHECK_EQ(server.accepted_connections(), std::size_t{2});

    {
      // ...so a third connection is rejected before/at the handshake.
      raw_tls_client rejected;
      CHECK(!rejected.connect(server.port()));
    }
    CHECK_EQ(server.accepted_connections(), std::size_t{2}); // rejected earlier than admission

    // Releasing one connection frees the slot for a new one.
    first.close();
    bool recovered = false;
    auto const retry_deadline = std::chrono::steady_clock::now() + 2s;
    while (!recovered && std::chrono::steady_clock::now() < retry_deadline) {
      raw_tls_client attempt;
      if (attempt.connect(server.port())) {
        if (attempt.send_all("GET /ping HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")) {
          auto wire = attempt.read_until_eof();
          if (starts_with_status(wire, "200") && response_body(wire) == std::string_view{"pong"}) recovered = true;
        }
      }
      if (!recovered) std::this_thread::sleep_for(10ms);
    }
    CHECK(recovered);
    CHECK(server.accepted_connections() >= 3);

    second.close();
    server.stop();
    run_thread.join();
    CHECK(server.stopping());
  }

  // --- default worker count ----------------------------------------------
  {
    trie::server<api> router;
    trie::http::threaded_tls_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                                make_options()};
    CHECK(server.valid());
    CHECK(server.workers() >= 1);
    std::thread run_thread{[&server] { server.run(); }};
    server.stop();
    run_thread.join();
    CHECK(server.stopping());
  }

  // --- caller-supplied shared limiter is honored --------------------------
  {
    trie::server<api> router;
    trie::http::tls_serve_options options = make_options();
    auto shared_limiter = std::make_shared<trie::http::connection_limiter>(0); // unlimited
    options.http.connection_limit = shared_limiter;
    options.http.max_connections = 1; // would cap at 1 if the supplied limiter were replaced
    trie::http::threaded_tls_listener<trie::server<api>> server{
        router, trie::http::endpoint{"127.0.0.1", 0}, options, 2};
    CHECK(server.valid());
    std::thread run_thread{[&server] { server.run(); }};

    raw_tls_client holder;
    CHECK(holder.connect(server.port())); // occupies a slot on the supplied limiter
    trie::http::tls_transport transport{trie::http::endpoint{"127.0.0.1", server.port()}, client_options()};
    auto response = transport.send(get_request("/ping"));
    CHECK(response.has_value()); // rejected only if options.max_connections had won
    if (response) CHECK_EQ(response->body, std::string{"pong"});
    CHECK(shared_limiter->current() >= 1);

    holder.close();
    server.stop();
    run_thread.join();
    CHECK(server.stopping());
  }

  // --- HTTP/2 option forwarding (same gating as tls_listener) -------------
  {
    trie::server<api> router;
    trie::http::tls_serve_options options = make_options();
    options.enable_http2 = true;
    trie::http::threaded_tls_listener<trie::server<api>> server{
        router, trie::http::endpoint{"127.0.0.1", 0}, options, 2};
#if defined(TRIE_TLS_LISTENER_WITH_HTTP2)
    CHECK(server.valid());
    CHECK_EQ(server.workers(), std::size_t{2});
    CHECK(server.port() != 0);
    std::thread run_thread{[&server] { server.run(); }};
    server.stop();
    run_thread.join();
    CHECK(server.stopping());
#else
    // Without nghttp2 support tls_listener reports ENOTSUP; the wrapper must
    // forward that instead of starting workers.
    CHECK(!server.valid());
    CHECK_EQ(server.error_code(), ENOTSUP);
    CHECK_EQ(server.workers(), std::size_t{0});
    CHECK_EQ(server.port(), std::uint16_t{0});
    CHECK(!trie::http::serve_tls_threaded(router, trie::http::endpoint{"127.0.0.1", 0}, options, 2));
#endif
  }

  // --- invalid TLS configuration -----------------------------------------
  {
    trie::server<api> router;
    trie::http::tls_serve_options options{};
    options.private_key_file = server_key; // certificate_chain_file is missing

    trie::http::threaded_tls_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", 0},
                                                                options, 2};
    CHECK(!server.valid());
    CHECK(server.error_code() != 0);
    CHECK_EQ(server.workers(), std::size_t{0});
    CHECK_EQ(server.port(), std::uint16_t{0});
    CHECK(!trie::http::serve_tls_threaded(router, trie::http::endpoint{"127.0.0.1", 0}, options, 2));
  }

  return tst::report("threaded_tls_listener_test");
}

#endif
