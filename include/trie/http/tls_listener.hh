#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "trie/http/event_loop.hh"
#include "trie/http/listener.hh"
#include "trie/http/parser.hh"
#include "trie/http/serializer.hh"

// HTTP/2 support is opt-in: define TRIE_TLS_LISTENER_WITH_HTTP2 before
// including this header and link nghttp2 (see include/trie/http/h2.hh). Without
// the macro the listener is HTTPS/HTTP1.1-only and does not require nghttp2.
#if defined(TRIE_TLS_LISTENER_WITH_HTTP2)
#include "trie/http/h2.hh"
#ifndef TRIE_TLS_LISTENER_HAS_H2
#define TRIE_TLS_LISTENER_HAS_H2 1
#endif
#endif

namespace trie::http {

struct tls_serve_options {
  serve_options http{}; // timeouts/limits/limiter/reuse_port
  std::string certificate_chain_file{}; // PEM
  std::string private_key_file{};       // PEM
  std::string ca_file{};                // optional, for client certificate verification
  bool verify_client = false;           // require + verify client cert (mTLS)
  std::chrono::milliseconds handshake_timeout{10000};
  std::vector<std::string> alpn_protocols{"http/1.1"}; // server preference order
  // Enables ALPN "h2" (prepended to alpn_protocols) and HTTP/2 connections.
  // Requires TRIE_TLS_LISTENER_WITH_HTTP2 and linking nghttp2; otherwise the
  // listener is invalid with ENOTSUP.
  bool enable_http2 = false;
};

// Blocking HTTPS server: one epoll loop, one coroutine per TLS connection,
// HTTP/1.1 keep-alive, and the same request parser/router/serializer and
// timeout/drain semantics as trie::http::listener.
//
// OpenSSL runs in nonblocking mode on top of the epoll loop: handshake and
// read/write waits are suspended as coroutines and resumed by EPOLLIN/EPOLLOUT,
// with the same idle/request/io timeouts as the plain listener.
//
// Note: the listener ignores SIGPIPE process-wide (once) because OpenSSL's
// socket BIO uses write(2) and cannot pass MSG_NOSIGNAL.
template <class Router>
class tls_listener {
public:
  tls_listener(Router& router, endpoint address, tls_serve_options options = {})
      : router_(router), options_(std::move(options)) {
#if !defined(TRIE_TLS_LISTENER_HAS_H2)
    if (options_.enable_http2) {
      // HTTP/2 needs nghttp2 headers at build time.
      error_code_ = ENOTSUP;
      return;
    }
#endif
    if (options_.http.connection_limit != nullptr)
      limiter_ = options_.http.connection_limit;
    else
      limiter_ = std::make_shared<connection_limiter>(options_.http.max_connections);

    build_alpn_list();
    ignore_sigpipe_once();
    init_tls();
    // Only bind when TLS configuration succeeded; a failed config leaves
    // valid() false and port() 0.
    if (ctx_ != nullptr) open_socket(std::move(address));
  }

  ~tls_listener() {
    close_connections();
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  tls_listener(tls_listener const&) = delete;
  tls_listener& operator=(tls_listener const&) = delete;

  bool valid() const { return ctx_ != nullptr && listen_fd_ >= 0 && loop_.valid(); }

  int error_code() const { return error_code_; }

  // Bound port; useful when the listener was created with port 0.
  std::uint16_t port() const { return port_; }

  void run() {
    if (!valid()) return;
    if (!loop_.add_permanent(listen_fd_, [this] { accept_ready(); })) return;
    loop_.run([this] { return should_exit(); });
    close_connections();
  }

  // Non-blocking: sets the stopping flag and wakes the run loop. The loop drains
  // existing connections (up to options.http.drain_timeout), then run() returns.
  void stop() {
    stopping_.store(true, std::memory_order_relaxed);
    loop_.wake();
  }

  bool stopping() const { return stopping_.load(std::memory_order_relaxed); }

  // Total connections admitted by this listener (for observability/tests).
  std::size_t accepted_connections() const { return accepted_.load(std::memory_order_relaxed); }

private:
  struct connection_state {
    SSL* ssl = nullptr;
    bool active = false;
  };

  static void ignore_sigpipe_once() {
    static std::atomic<bool> done{false};
    if (done.exchange(true, std::memory_order_acq_rel)) return;
    (void)::signal(SIGPIPE, SIG_IGN);
  }

  // Effective ALPN list: "h2" first when HTTP/2 is enabled, then the
  // configured server preference order (duplicates skipped).
  void build_alpn_list() {
    if (options_.enable_http2) effective_alpn_.emplace_back("h2");
    for (auto const& protocol : options_.alpn_protocols) {
      if (protocol.empty() || protocol.size() > 255) continue;
      if (!options_.enable_http2 && protocol == "h2") continue;
      if (std::find(effective_alpn_.begin(), effective_alpn_.end(), protocol) != effective_alpn_.end())
        continue;
      effective_alpn_.push_back(protocol);
    }
  }

  void init_tls() {
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (ctx_ == nullptr) {
      error_code_ = EINVAL;
      return;
    }
    (void)SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
    // Treat a peer that closes without close_notify as EOF, like plain sockets.
    (void)SSL_CTX_set_options(ctx_, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
#if defined(SSL_OP_NO_RENEGOTIATION)
    (void)SSL_CTX_set_options(ctx_, SSL_OP_NO_RENEGOTIATION);
#endif

    if (SSL_CTX_use_certificate_chain_file(ctx_, options_.certificate_chain_file.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, options_.private_key_file.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx_) != 1) {
      error_code_ = EINVAL;
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
      return;
    }

    if (!options_.ca_file.empty()) {
      if (SSL_CTX_load_verify_locations(ctx_, options_.ca_file.c_str(), nullptr) != 1) {
        error_code_ = EINVAL;
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
        return;
      }
    } else if (options_.verify_client) {
      if (SSL_CTX_set_default_verify_paths(ctx_) != 1) {
        error_code_ = EINVAL;
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
        return;
      }
    }

    if (options_.verify_client)
      SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    else
      SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);

    if (!effective_alpn_.empty()) SSL_CTX_set_alpn_select_cb(ctx_, &tls_listener::alpn_select_cb, &effective_alpn_);
  }

  // Server-preference ALPN selection: walk the server list first, then the
  // client's length-prefixed list. No common protocol -> NOACK (no ALPN).
  static int alpn_select_cb(SSL* /*ssl*/, unsigned char const** out, unsigned char* outlen,
                            unsigned char const* in, unsigned int inlen, void* arg) {
    auto const* protocols = static_cast<std::vector<std::string> const*>(arg);
    for (auto const& protocol : *protocols) {
      for (unsigned int offset = 0; offset < inlen;) {
        unsigned int const length = in[offset];
        ++offset;
        if (length > inlen - offset) break;
        if (protocol.size() == length && std::memcmp(protocol.data(), in + offset, length) == 0) {
          *out = reinterpret_cast<unsigned char const*>(protocol.data());
          *outlen = static_cast<unsigned char>(length);
          return SSL_TLSEXT_ERR_OK;
        }
        offset += length;
      }
    }
    return SSL_TLSEXT_ERR_NOACK;
  }

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
      if (options_.http.reuse_port) {
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
        // Over the connection limit: close immediately (a plaintext 503 cannot
        // be sent before the TLS handshake).
        ::close(fd);
        continue;
      }

      SSL* ssl = SSL_new(ctx_);
      if (ssl == nullptr) {
        limiter_->release();
        ::close(fd);
        continue;
      }
      (void)SSL_set_fd(ssl, fd);
      SSL_set_accept_state(ssl);

      accepted_.fetch_add(1, std::memory_order_relaxed);
      connections_.insert_or_assign(fd, connection_state{ssl, false});
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

  static task handle_connection(tls_listener* self, int fd) {
    auto entry = self->connections_.find(fd);
    if (entry == self->connections_.end()) co_return;
    SSL* ssl = entry->second.ssl;

    auto finish = [&] { self->close_connection(fd); };
    serve_options const& http_options = self->options_.http;

    // --- TLS handshake: nonblocking, bounded by handshake_timeout ----------
    clock::time_point handshake_deadline = clock::time_point::max();
    if (self->options_.handshake_timeout.count() > 0)
      handshake_deadline = clock::now() + self->options_.handshake_timeout;
    bool handshake_complete = false;
    while (true) {
      ERR_clear_error();
      int result = SSL_accept(ssl);
      if (result == 1) {
        handshake_complete = true;
        break;
      }
      int const ssl_error = SSL_get_error(ssl, result);
      if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) break;

      std::chrono::milliseconds wait{0};
      if (handshake_deadline != clock::time_point::max()) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(handshake_deadline - clock::now());
        if (remaining.count() <= 0) break; // handshake timed out
        wait = remaining;
      }
      io_event handshake_event{fd, ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT, wait};
      if (!co_await handshake_event) break;
    }
    if (!handshake_complete) {
      ERR_clear_error();
      finish();
      co_return;
    }

    unsigned char const* alpn_data = nullptr;
    unsigned int alpn_length = 0;
    SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_length);
    std::string_view const selected_alpn{reinterpret_cast<char const*>(alpn_data),
                                         static_cast<std::size_t>(alpn_length)};

    // ======================================================================
    // HTTP/2 INTEGRATION HOOK (Lead)
    //
    // "h2" can only be negotiated when tls_serve_options::enable_http2 is
    // true and "h2" is present in tls_serve_options::alpn_protocols;
    // build_alpn_list() filters it out otherwise. The HTTP/2 engine is not
    // wired in yet, so h2 connections are closed immediately below.
    //
    // To integrate: replace the close with a hand-off to the HTTP/2
    // connection engine. That engine is transport-agnostic: feed it TLS
    // plaintext bytes (from SSL_read) and write its pending output back
    // through SSL_write, suspending this coroutine on WANT_READ/WANT_WRITE
    // exactly like the HTTP/1.1 loop below does. close_connection()/finish()
    // remain responsible for SSL_shutdown/SSL_free/fd/limiter cleanup.
    // ======================================================================
    if (selected_alpn == "h2") {
#if defined(TRIE_TLS_LISTENER_HAS_H2)
      // HTTP/2 over the already-negotiated TLS connection. The engine is
      // transport-agnostic; we drive it with SSL_read/SSL_write and suspend on
      // epoll readiness through io_event.
      h2_connection<Router> connection{self->router_, self->options_.http.limits.max_body_bytes};
      bool const h2_idle_reads = http_options.idle_timeout.count() > 0;
      bool closed = false;

      while (!closed) {
        // Flush pending frames (initial SETTINGS, responses, WINDOW_UPDATE, ...).
        auto pending = connection.take_output();
        std::string_view outgoing{pending};
        self->set_active(fd, true);
        while (!outgoing.empty()) {
          ERR_clear_error();
          int const written = SSL_write(ssl, outgoing.data(), static_cast<int>(outgoing.size()));
          if (written > 0) {
            outgoing.remove_prefix(static_cast<std::size_t>(written));
            continue;
          }
          int const ssl_error = SSL_get_error(ssl, written);
          if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            io_event write_event{fd, ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT,
                                 http_options.io_timeout};
            if (!(co_await write_event)) {
              closed = true;
              break;
            }
            continue;
          }
          closed = true;
          break;
        }
        self->set_active(fd, false);
        if (closed || connection.finished()) break;
        // A stop request drains h2 connections after the current response.
        if (self->stopping_.load(std::memory_order_relaxed)) break;

        std::array<char, 16384> chunk{};
        ERR_clear_error();
        int const received = SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size()));
        if (received > 0) {
          self->set_active(fd, true);
          bool const alive =
              connection.consume(std::string_view{chunk.data(), static_cast<std::size_t>(received)});
          self->set_active(fd, false);
          if (!alive) {
            // Flush any protocol-error frames before closing.
            auto errors = connection.take_output();
            std::string_view error_bytes{errors};
            while (!error_bytes.empty()) {
              ERR_clear_error();
              int const written = SSL_write(ssl, error_bytes.data(), static_cast<int>(error_bytes.size()));
              if (written > 0) {
                error_bytes.remove_prefix(static_cast<std::size_t>(written));
                continue;
              }
              int const ssl_error = SSL_get_error(ssl, written);
              if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                io_event write_event{fd, ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT,
                                     http_options.io_timeout};
                if (!(co_await write_event)) break;
                continue;
              }
              break;
            }
            break;
          }
          continue;
        }

        int const ssl_error = SSL_get_error(ssl, received);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
          std::chrono::milliseconds wait =
              h2_idle_reads ? http_options.idle_timeout : http_options.io_timeout;
          io_event read_event{fd, ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT, wait};
          if (!(co_await read_event)) break;
          continue;
        }
        // EOF, close_notify, TLS error: let a fresh GOAWAY flush best effort.
        connection.shutdown();
        auto final_output = connection.take_output();
        std::string_view final_view{final_output};
        int spins = 0;
        while (!final_view.empty() && spins++ < 4) {
          ERR_clear_error();
          int const written = SSL_write(ssl, final_view.data(), static_cast<int>(final_view.size()));
          if (written > 0) {
            final_view.remove_prefix(static_cast<std::size_t>(written));
            continue;
          }
          int const write_error = SSL_get_error(ssl, written);
          if (write_error == SSL_ERROR_WANT_READ || write_error == SSL_ERROR_WANT_WRITE) {
            io_event write_event{fd, write_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT,
                                 http_options.io_timeout};
            if (!(co_await write_event)) break;
            continue;
          }
          break;
        }
        break;
      }
      finish();
      co_return;
#else
      finish();
      co_return;
#endif
    }

    // --- HTTP/1.1 request loop (mirrors listener::handle_connection) -------
    std::string buffer;
    request_parser parser{http_options.limits};

    while (true) {
      parsed_request request{};
      parse_error error{};
      std::size_t consumed = 0;
      parse_status status = parser.parse(buffer, request, error, consumed);

      bool timed_out = false;
      clock::time_point request_deadline = clock::time_point::max();
      while (status == parse_status::incomplete) {
        std::chrono::milliseconds wait{0};
        if (buffer.empty()) {
          wait = http_options.idle_timeout;
        } else {
          clock::time_point const now = clock::now();
          if (request_deadline == clock::time_point::max()) request_deadline = now + http_options.request_timeout;
          auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(request_deadline - now);
          if (remaining.count() <= 0) {
            timed_out = true;
            break;
          }
          wait = std::min(http_options.io_timeout, remaining);
        }

        io_event read_event{fd, EPOLLIN, wait};
        bool ready = co_await read_event;
        if (!ready) {
          timed_out = true;
          break;
        }

        std::array<char, 8192> chunk{};
        ERR_clear_error();
        int received = SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size()));
        if (received > 0) {
          buffer.append(chunk.data(), static_cast<std::size_t>(received));
          status = parser.parse(buffer, request, error, consumed);
          continue;
        }

        int const ssl_error = SSL_get_error(ssl, received);
        if (ssl_error == SSL_ERROR_WANT_READ) continue; // recompute the wait
        if (ssl_error == SSL_ERROR_WANT_WRITE) {
          io_event write_event{fd, EPOLLOUT, http_options.io_timeout};
          if (!co_await write_event) {
            timed_out = true;
            break;
          }
          continue;
        }
        if (ssl_error == SSL_ERROR_SYSCALL && errno == EINTR) continue;
        // SSL_ERROR_ZERO_RETURN / SSL_ERROR_SYSCALL / SSL_ERROR_SSL: peer gone.
        ERR_clear_error();
        finish();
        co_return;
      }

      // Idle timeout: close silently. Request timeout or parse error: error reply.
      if (timed_out && buffer.empty()) {
        finish();
        co_return;
      }

      std::string out;
      bool close_after = false;
      if (timed_out || status == parse_status::error) {
        int const code = timed_out ? static_cast<int>(status::request_timeout) : error.status;
        std::string message = timed_out ? "request timeout" : std::move(error.message);
        out = serialize_response(error_response(code, std::move(message)), false, false);
        close_after = true;
      } else {
        entry = self->connections_.find(fd);
        if (entry == self->connections_.end()) co_return;
        entry->second.active = true;

        std::vector<header_view> header_views;
        header_views.reserve(request.headers.size());
        for (auto const& header : request.headers)
          header_views.push_back(header_view{header.first, header.second});

        auto view = request_view::from_target(request.m, request.target, header_views, request.body);
        response result = self->router_.dispatch(view);
        bool const head_only = request.m == method::head;
        out = serialize_response(result, request.keep_alive, head_only);
        close_after = !request.keep_alive;
        buffer.erase(0, consumed);
      }

      std::string_view pending{out};
      bool write_failed = false;
      constexpr std::size_t max_write = 1 << 20;
      while (!pending.empty()) {
        std::size_t const amount = pending.size() < max_write ? pending.size() : max_write;
        ERR_clear_error();
        int sent = SSL_write(ssl, pending.data(), static_cast<int>(amount));
        if (sent > 0) {
          pending.remove_prefix(static_cast<std::size_t>(sent));
          continue;
        }
        int const ssl_error = SSL_get_error(ssl, sent);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
          io_event write_event{fd, ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT,
                               http_options.io_timeout};
          if (!co_await write_event) {
            write_failed = true;
            break;
          }
          continue;
        }
        if (ssl_error == SSL_ERROR_SYSCALL && errno == EINTR) continue;
        write_failed = true;
        break;
      }

      if (write_failed || close_after) {
        ERR_clear_error();
        finish();
        co_return;
      }
      entry = self->connections_.find(fd);
      if (entry != self->connections_.end()) entry->second.active = false;
    }
  }

  // Called on the run thread: stop accepting, close idle connections, wait for
  // in-flight requests until drain_timeout expires.
  bool should_exit() {
    if (!stopping_.load(std::memory_order_relaxed)) return false;

    if (!draining_) {
      draining_ = true;
      if (listen_fd_ >= 0) {
        loop_.remove(listen_fd_);
        ::close(listen_fd_);
        listen_fd_ = -1;
      }
      drain_deadline_ = clock::now() + options_.http.drain_timeout;
    }

    std::vector<int> idle{};
    for (auto const& [fd, state] : connections_)
      if (!state.active) idle.push_back(fd);
    for (int fd : idle) loop_.cancel_wait(fd);

    if (connections_.empty()) return true;
    return clock::now() >= drain_deadline_;
  }

  void set_active(int fd, bool active) {
    auto entry = connections_.find(fd);
    if (entry != connections_.end()) entry->second.active = active;
  }

  void close_connection(int fd) {
    loop_.remove(fd);
    auto entry = connections_.find(fd);
    if (entry == connections_.end()) return;
    SSL* ssl = entry->second.ssl;
    connections_.erase(entry);
    limiter_->release();
    if (ssl != nullptr) {
      (void)SSL_shutdown(ssl); // best effort; nonblocking, ignores WANT_*
      SSL_free(ssl);
    }
    ::close(fd);
  }

  void close_connections() {
    std::vector<int> fds;
    fds.reserve(connections_.size());
    for (auto const& [fd, state] : connections_) {
      (void)state;
      fds.push_back(fd);
    }
    for (int fd : fds) close_connection(fd);
  }

  Router& router_;
  tls_serve_options options_;
  event_loop loop_;
  SSL_CTX* ctx_ = nullptr;
  int listen_fd_ = -1;
  int error_code_ = 0;
  std::uint16_t port_ = 0;
  std::shared_ptr<connection_limiter> limiter_{};
  std::vector<std::string> effective_alpn_{};
  std::atomic<bool> stopping_{false};
  std::atomic<std::size_t> accepted_{0};
  bool draining_ = false;
  clock::time_point drain_deadline_{};
  std::unordered_map<int, connection_state> connections_{};
};

template <class Router>
bool serve_tls(Router& router, endpoint address, tls_serve_options options = {}) {
  tls_listener<Router> server{router, std::move(address), std::move(options)};
  if (!server.valid()) return false;
  server.run();
  return true;
}

} // namespace trie::http
