#pragma once

// Blocking HTTP/2 client transport for trie::client.
//
// `trie::client<Api, trie::http::h2_transport>` calls this transport's
// send(request) and gets back `std::expected<http::response, trie::client_error>`,
// so typed handlers can be called over HTTPS with ALPN "h2" exactly like over
// plain sockets or HTTP/1.1 TLS.
//
// Scope of this implementation:
//   * One TLS + HTTP/2 connection per send() call. There is no connection
//     reuse, no connection pool and no multiplexing across calls (see the
//     pooling notes above send()).
//   * Client side only. No server push, no trailers and no h2c upgrade. Pushed
//     or unrelated streams are ignored, never mixed into the response.
//   * Blocking: the TCP connect uses a nonblocking connect + poll bounded by
//     connect_timeout_ms; after the handshake the socket uses
//     SO_RCVTIMEO/SO_SNDTIMEO equal to io_timeout_ms, so a stalled peer turns
//     into a timeout error instead of an indefinite block.
//
// Errors are reported as trie::client_error with status 0 (transport-level
// failure) and a human-readable message; no exceptions or RTTI are used.
//
// Like tls_transport, this uses OpenSSL's socket BIO, so writing to a peer that
// already closed the connection can raise SIGPIPE. Long-running client
// processes should ignore SIGPIPE (tls_listener does so process-wide).

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "trie/error.hh"
#include "trie/http.hh"
#include "trie/http/serializer.hh"

namespace trie::http {

struct h2_transport_options {
  bool verify_peer = true;
  std::string ca_file{};                 // CA bundle or the server certificate itself
  std::string server_name{};             // SNI + hostname verification; empty -> endpoint host
  std::string client_certificate_file{}; // optional mTLS certificate (PEM)
  std::string client_key_file{};         // optional mTLS private key (PEM)
  std::vector<std::string> alpn_protocols{"h2"};
  int connect_timeout_ms = 5000;
  int io_timeout_ms = 10000;
  std::size_t max_response_bytes = 16 * 1024 * 1024;
};

// Blocking HTTPS + HTTP/2 transport. The transport itself is stateless, so one
// instance may be shared by several threads; each send() opens its own
// connection.
class h2_transport {
public:
  explicit h2_transport(endpoint address, h2_transport_options options = {})
      : address_{std::move(address)}, options_{std::move(options)} {}

  // Sends one request over a fresh TLS + HTTP/2 connection.
  //
  // Future pooled transport notes: keep the TLS session and nghttp2 client
  // session alive across calls, use one HTTP/2 stream per request (so a pool
  // can multiplex concurrent calls on one connection), drive the same
  // mem_send2/SSL_write + SSL_read/mem_recv2 pump for all outstanding streams
  // with a per-stream exchange map, and replace the connection on GOAWAY or a
  // transport error. The request/response mapping and header handling in this
  // method can be reused as-is per stream.
  std::expected<response, trie::client_error> send(request request) const {
    auto fail = [](std::string message) -> std::expected<response, trie::client_error> {
      return std::unexpected(trie::client_error{0, std::move(message)});
    };

    std::string error;
    tls_guard guard{};
    guard.fd = connect_socket(error);
    if (guard.fd < 0) return fail(std::move(error));

    peer_name const name = resolve_peer_name();
    guard.ctx = SSL_CTX_new(TLS_client_method());
    if (guard.ctx == nullptr) return fail(openssl_error("failed to create TLS context"));
    if (SSL_CTX_set_min_proto_version(guard.ctx, TLS1_2_VERSION) != 1)
      return fail("failed to require TLS 1.2 or newer");
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
    // A peer that closes without close_notify is treated like EOF, matching the
    // plain/HTTP1 TLS transport.
    (void)SSL_CTX_set_options(guard.ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    (void)SSL_CTX_set_options(guard.ctx, SSL_OP_NO_COMPRESSION);
    if (!configure_context(guard.ctx, name, error)) return fail(std::move(error));

    guard.ssl = SSL_new(guard.ctx);
    if (guard.ssl == nullptr) return fail(openssl_error("failed to create TLS session"));
    if (SSL_set_fd(guard.ssl, guard.fd) != 1)
      return fail(openssl_error("failed to attach TLS session to socket"));
    if (!name.ip && !name.text.empty()) (void)SSL_set_tlsext_host_name(guard.ssl, name.text.c_str());

    // The handshake is part of connecting: bound its blocking reads by the
    // connect timeout, then switch the socket to the I/O timeout.
    set_socket_timeouts(guard.fd, options_.connect_timeout_ms);
    if (!tls_handshake(guard.ssl, guard.fd, error)) return fail(std::move(error));
    guard.established = true;
    set_socket_timeouts(guard.fd, options_.io_timeout_ms);

    unsigned char const* alpn_data = nullptr;
    unsigned int alpn_length = 0;
    SSL_get0_alpn_selected(guard.ssl, &alpn_data, &alpn_length);
    std::string_view const selected{reinterpret_cast<char const*>(alpn_data), static_cast<std::size_t>(alpn_length)};
    if (selected != "h2") {
      std::string message{"server did not negotiate ALPN \"h2\""};
      message += selected.empty() ? " (no ALPN protocol selected)"
                                  : " (selected: " + std::string{selected} + ")";
      return fail(std::move(message));
    }

    exchange state{};
    state.max_response_bytes = options_.max_response_bytes;
    if (!run_exchange(guard.ssl, guard.fd, request, state, error)) return fail(std::move(error));
    if (state.failed) return fail(state.error);
    if (state.status < 100 || state.status > 999)
      return fail("missing or malformed :status in the HTTP/2 response");

    response result{};
    result.status_code = state.status;
    result.headers = std::move(state.headers);
    result.body = std::move(state.body);
    return result;
  }

private:
  struct peer_name {
    std::string text{};
    bool ip = false;
  };

  // Per-send HTTP/2 exchange, handed to the nghttp2 callbacks as user_data.
  struct exchange {
    int32_t stream_id = 0; // stream of the request submitted by this send()
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers{};
    std::string body{};
    std::size_t max_response_bytes = 0;
    bool done = false;
    bool failed = false;
    std::string error{};
  };

  struct body_source {
    std::string const* data = nullptr;
    std::size_t offset = 0;
  };

  // Releases TLS/socket resources on every return path (including early errors).
  struct tls_guard {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int fd = -1;
    bool established = false;

    tls_guard() = default;
    tls_guard(tls_guard const&) = delete;
    tls_guard& operator=(tls_guard const&) = delete;

    ~tls_guard() {
      if (ssl != nullptr) {
        if (established) (void)SSL_shutdown(ssl); // best effort, single round trip
        SSL_free(ssl);
      }
      if (ctx != nullptr) SSL_CTX_free(ctx);
      if (fd >= 0) ::close(fd);
    }
  };

  peer_name resolve_peer_name() const {
    peer_name result{};
    result.text = options_.server_name.empty() ? address_.host : options_.server_name;
    in_addr v4{};
    in6_addr v6{};
    result.ip = ::inet_pton(AF_INET, result.text.c_str(), &v4) == 1 ||
                ::inet_pton(AF_INET6, result.text.c_str(), &v6) == 1;
    return result;
  }

  // :authority value: the SNI/host name, plus a non-default port.
  std::string authority() const {
    std::string name = options_.server_name.empty() ? address_.host : options_.server_name;
    if (name.find(':') != std::string::npos && !(name.size() >= 2 && name.front() == '[')) {
      name = "[" + name + "]"; // IPv6 literal
    }
    if (address_.port != 443) {
      name += ':';
      name += std::to_string(address_.port);
    }
    return name;
  }

  static std::string openssl_error(std::string_view prefix) {
    std::string message{prefix};
    unsigned long code = ERR_get_error();
    if (code != 0) {
      std::array<char, 256> buffer{};
      ERR_error_string_n(code, buffer.data(), buffer.size());
      message += ": ";
      message += buffer.data();
    }
    return message;
  }

  static bool set_verify_name(SSL_CTX* ctx, peer_name const& name) {
    X509_VERIFY_PARAM* param = SSL_CTX_get0_param(ctx);
    if (param == nullptr) return false;
    if (name.ip) return X509_VERIFY_PARAM_set1_ip_asc(param, name.text.c_str()) == 1;
    return X509_VERIFY_PARAM_set1_host(param, name.text.c_str(), name.text.size()) == 1;
  }

  static bool wait_ready(int fd, short events, int timeout_ms) {
    pollfd descriptor{fd, events, 0};
    for (;;) {
      int const ready = ::poll(&descriptor, 1, timeout_ms);
      if (ready > 0) return (descriptor.revents & (events | POLLERR | POLLHUP)) != 0;
      if (ready < 0 && errno == EINTR) continue;
      return false;
    }
  }

  static void set_socket_timeouts(int fd, int timeout_ms) {
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  }

  int connect_socket(std::string& error) const {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* results = nullptr;
    std::string const service = std::to_string(address_.port);
    if (::getaddrinfo(address_.host.c_str(), service.c_str(), &hints, &results) != 0) {
      error = "failed to resolve " + address_.host;
      return -1;
    }

    std::string last_error{};
    int connected = -1;
    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
      int fd = ::socket(it->ai_family, it->ai_socktype | SOCK_CLOEXEC, it->ai_protocol);
      if (fd < 0) {
        last_error = std::strerror(errno);
        continue;
      }

      int const flags = ::fcntl(fd, F_GETFL, 0);
      (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

      bool ok = ::connect(fd, it->ai_addr, it->ai_addrlen) == 0;
      if (!ok && errno == EINPROGRESS) {
        pollfd descriptor{fd, POLLOUT, 0};
        int const ready = ::poll(&descriptor, 1, options_.connect_timeout_ms);
        if (ready > 0) {
          int socket_error = 0;
          socklen_t length = sizeof(socket_error);
          ok = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) == 0 && socket_error == 0;
          if (!ok) last_error = std::strerror(socket_error);
        } else if (ready == 0) {
          last_error = "connect timed out";
        } else {
          last_error = std::strerror(errno);
        }
      } else if (!ok) {
        last_error = std::strerror(errno);
      }

      if (!ok) {
        ::close(fd);
        continue;
      }
      (void)::fcntl(fd, F_SETFL, flags);
      connected = fd;
      break;
    }
    ::freeaddrinfo(results);

    if (connected < 0) {
      error = "failed to connect to " + address_.host + ':' + service;
      if (!last_error.empty()) error += ": " + last_error;
    }
    return connected;
  }

  bool configure_context(SSL_CTX* ctx, peer_name const& name, std::string& error) const {
    if (options_.verify_peer) {
      if (!options_.ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(ctx, options_.ca_file.c_str(), nullptr) != 1) {
          error = openssl_error("failed to load CA file " + options_.ca_file);
          return false;
        }
      } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        error = openssl_error("failed to load system CA certificates");
        return false;
      }
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
      if (!set_verify_name(ctx, name)) {
        error = "failed to configure hostname verification for " + name.text;
        return false;
      }
    } else {
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    if (!options_.client_certificate_file.empty() || !options_.client_key_file.empty()) {
      if (options_.client_certificate_file.empty() || options_.client_key_file.empty()) {
        error = "client_certificate_file and client_key_file must be set together";
        return false;
      }
      if (SSL_CTX_use_certificate_chain_file(ctx, options_.client_certificate_file.c_str()) != 1) {
        error = openssl_error("failed to load client certificate " + options_.client_certificate_file);
        return false;
      }
      if (SSL_CTX_use_PrivateKey_file(ctx, options_.client_key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        error = openssl_error("failed to load client private key " + options_.client_key_file);
        return false;
      }
      if (SSL_CTX_check_private_key(ctx) != 1) {
        error = "client certificate and private key do not match";
        return false;
      }
    }

    if (!options_.alpn_protocols.empty()) {
      std::string wire;
      for (auto const& protocol : options_.alpn_protocols) {
        if (protocol.empty() || protocol.size() > 255) continue;
        wire.push_back(static_cast<char>(protocol.size()));
        wire += protocol;
      }
      if (!wire.empty() &&
          SSL_CTX_set_alpn_protos(ctx, reinterpret_cast<unsigned char const*>(wire.data()),
                                  static_cast<unsigned int>(wire.size())) != 0) {
        error = "failed to configure ALPN protocols";
        return false;
      }
    }
    return true;
  }

  bool tls_handshake(SSL* ssl, int fd, std::string& error) const {
    for (;;) {
      ERR_clear_error();
      int const result = SSL_connect(ssl);
      if (result == 1) return true;
      int const ssl_error = SSL_get_error(ssl, result);
      if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        if (!wait_ready(fd, ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
                        options_.connect_timeout_ms)) {
          error = "TLS handshake timed out";
          return false;
        }
        continue;
      }
      if (ssl_error == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        error = "TLS handshake timed out";
        return false;
      }
      long const verify_result = SSL_get_verify_result(ssl);
      if (verify_result != X509_V_OK) {
        error = std::string{"TLS certificate verification failed: "} +
                X509_verify_cert_error_string(verify_result);
        return false;
      }
      error = openssl_error("TLS handshake failed");
      return false;
    }
  }

  bool write_all(SSL* ssl, int fd, std::string_view data, std::string& error) const {
    constexpr std::size_t max_chunk = 1 << 20;
    while (!data.empty()) {
      ERR_clear_error();
      std::size_t const amount = std::min(data.size(), max_chunk);
      int const written = SSL_write(ssl, data.data(), static_cast<int>(amount));
      if (written > 0) {
        data.remove_prefix(static_cast<std::size_t>(written));
        continue;
      }
      int const ssl_error = SSL_get_error(ssl, written);
      if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        if (!wait_ready(fd, ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, options_.io_timeout_ms)) {
          error = "timed out sending the HTTP/2 request";
          return false;
        }
        continue;
      }
      if (ssl_error == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        error = "timed out sending the HTTP/2 request";
        return false;
      }
      error = openssl_error("failed to send the HTTP/2 request");
      return false;
    }
    return true;
  }

  bool flush_session(nghttp2_session* session, SSL* ssl, int fd, std::string& error) const {
    for (;;) {
      const uint8_t* data = nullptr;
      nghttp2_ssize const produced = nghttp2_session_mem_send2(session, &data);
      if (produced < 0) {
        error = std::string{"nghttp2_session_mem_send2: "} + nghttp2_strerror(static_cast<int>(produced));
        return false;
      }
      if (produced == 0) return true;
      if (!write_all(ssl, fd, std::string_view{reinterpret_cast<const char*>(data),
                                               static_cast<std::size_t>(produced)},
                     error))
        return false;
    }
  }

  bool run_exchange(SSL* ssl, int fd, request const& request, exchange& state, std::string& error) const {
    nghttp2_session_callbacks* callbacks = nullptr;
    if (nghttp2_session_callbacks_new(&callbacks) != 0) {
      error = "nghttp2_session_callbacks_new failed";
      return false;
    }
    nghttp2_session_callbacks_set_on_header_callback(callbacks, &h2_transport::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &h2_transport::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &h2_transport::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &h2_transport::on_stream_close);

    nghttp2_session* session = nullptr;
    int const rc = nghttp2_session_client_new(&session, callbacks, &state);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0) {
      error = std::string{"nghttp2_session_client_new: "} + nghttp2_strerror(rc);
      return false;
    }
    session_guard const guard{session};

    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_ENABLE_PUSH, 0}};
    int const settings_rc = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, 1);
    if (settings_rc != 0) {
      error = std::string{"nghttp2_submit_settings: "} + nghttp2_strerror(settings_rc);
      return false;
    }

    std::string const method{method_name(request.m)};
    if (method.empty()) {
      error = "unsupported request method";
      return false;
    }
    std::string_view const target = request.target.empty() ? std::string_view{"/"} : std::string_view{request.target};

    std::vector<std::string> names;
    std::vector<std::string> values;
    auto add_header = [&names, &values](std::string name, std::string value) {
      names.push_back(std::move(name));
      values.push_back(std::move(value));
    };
    add_header(":method", method);
    add_header(":scheme", "https");
    add_header(":authority", authority());
    add_header(":path", std::string{target});
    if (!request.body.empty()) add_header("content-length", std::to_string(request.body.size()));
    for (auto const& header : request.headers) {
      std::string name = lowercase(header.first);
      if (!valid_header_name(name) || !valid_header_value(header.second)) continue;
      if (forbidden_request_header(name)) continue;
      add_header(std::move(name), header.second);
    }

    std::vector<nghttp2_nv> pairs;
    pairs.reserve(names.size());
    for (std::size_t i = 0; i < names.size(); ++i) {
      nghttp2_nv pair{};
      pair.name = reinterpret_cast<uint8_t*>(names[i].data());
      pair.namelen = names[i].size();
      pair.value = reinterpret_cast<uint8_t*>(values[i].data());
      pair.valuelen = values[i].size();
      pair.flags = NGHTTP2_NV_FLAG_NONE;
      pairs.push_back(pair);
    }

    body_source body{&request.body, 0};
    nghttp2_data_provider2 provider{};
    nghttp2_data_provider2 const* provider_ptr = nullptr;
    if (!request.body.empty()) {
      provider.source.ptr = &body;
      provider.read_callback = &h2_transport::read_request_body;
      provider_ptr = &provider;
    }

    int32_t const stream_id =
        nghttp2_submit_request2(session, nullptr, pairs.data(), pairs.size(), provider_ptr, nullptr);
    if (stream_id < 0) {
      error = std::string{"nghttp2_submit_request2: "} + nghttp2_strerror(stream_id);
      return false;
    }
    state.stream_id = stream_id;
    if (!flush_session(session, ssl, fd, error)) return false;

    std::array<unsigned char, 16384> chunk{};
    while (!state.done && !state.failed) {
      ERR_clear_error();
      int const received = SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size()));
      if (received > 0) {
        nghttp2_ssize const consumed =
            nghttp2_session_mem_recv2(session, chunk.data(), static_cast<std::size_t>(received));
        if (consumed < 0) {
          error = std::string{"nghttp2_session_mem_recv2: "} + nghttp2_strerror(static_cast<int>(consumed));
          return false;
        }
        // ACKs, WINDOW_UPDATEs and RST_STREAMs produced while reading.
        if (!flush_session(session, ssl, fd, error)) return false;
        continue;
      }

      int const ssl_error = SSL_get_error(ssl, received);
      if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        if (!wait_ready(fd, ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, options_.io_timeout_ms)) {
          error = "timed out receiving the HTTP/2 response";
          return false;
        }
        continue;
      }
      if (ssl_error == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        error = "timed out receiving the HTTP/2 response";
        return false;
      }
      if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
        error = "connection closed before the HTTP/2 response completed";
        return false;
      }
      error = openssl_error("failed to receive the HTTP/2 response");
      return false;
    }
    if (state.failed) {
      error = state.error;
      return false;
    }
    return true;
  }

  // ---- nghttp2 callbacks (user_data = exchange*) -------------------------

  static int on_header(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
                       const uint8_t* value, size_t valuelen, uint8_t, void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_RESPONSE) return 0;
    auto* state = static_cast<exchange*>(user_data);
    if (frame->hd.stream_id != state->stream_id) return 0; // e.g. pushed streams
    std::string_view const header_name{reinterpret_cast<const char*>(name), namelen};
    std::string_view const header_value{reinterpret_cast<const char*>(value), valuelen};
    if (header_name == ":status") {
      int status = 0;
      auto const [ptr, error] = std::from_chars(header_value.data(), header_value.data() + header_value.size(), status);
      if (error == std::errc{} && ptr == header_value.data() + header_value.size()) state->status = status;
      return 0;
    }
    if (!header_name.empty() && header_name.front() == ':') return 0;
    state->headers.emplace_back(std::string{header_name}, std::string{header_value});
    return 0;
  }

  static int on_data_chunk_recv(nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t* data, size_t len,
                                void* user_data) {
    auto* state = static_cast<exchange*>(user_data);
    if (stream_id != state->stream_id || state->failed) return 0;
    if (len > state->max_response_bytes - state->body.size()) {
      state->failed = true;
      state->error = "HTTP/2 response body exceeds max_response_bytes";
      return 0;
    }
    state->body.append(reinterpret_cast<const char*>(data), len);
    return 0;
  }

  static int on_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* state = static_cast<exchange*>(user_data);
    if (frame->hd.stream_id != state->stream_id) return 0; // e.g. pushed streams
    if (frame->hd.type == NGHTTP2_RST_STREAM) {
      state->done = true;
      state->failed = true;
      state->error = std::string{"HTTP/2 stream reset by server: "} +
                     nghttp2_http2_strerror(frame->rst_stream.error_code);
      return 0;
    }
    // Only HEADERS/DATA carry END_STREAM; SETTINGS ACK reuses bit 0x01.
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
      state->done = true;
    }
    return 0;
  }

  static int on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t error_code, void* user_data) {
    auto* state = static_cast<exchange*>(user_data);
    if (stream_id != state->stream_id) return 0; // e.g. pushed streams
    state->done = true;
    if (error_code != NGHTTP2_NO_ERROR && !state->failed) {
      state->failed = true;
      state->error = std::string{"HTTP/2 stream closed with error: "} + nghttp2_http2_strerror(error_code);
    }
    return 0;
  }

  static nghttp2_ssize read_request_body(nghttp2_session*, int32_t, uint8_t* buffer, size_t length,
                                         uint32_t* data_flags, nghttp2_data_source* source, void*) {
    auto* body = static_cast<body_source*>(source->ptr);
    if (body == nullptr || body->data == nullptr) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      return 0;
    }
    std::size_t const remaining = body->data->size() - body->offset;
    if (remaining == 0) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      return 0;
    }
    std::size_t const amount = std::min(length, remaining);
    std::memcpy(buffer, body->data->data() + body->offset, amount);
    body->offset += amount;
    if (body->offset >= body->data->size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(amount);
  }

  struct session_guard {
    nghttp2_session* session = nullptr;
    ~session_guard() {
      if (session != nullptr) nghttp2_session_del(session);
    }
  };

  static std::string lowercase(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) out.push_back(to_lower(c));
    return out;
  }

  static bool forbidden_request_header(std::string_view name) {
    // Connection-specific fields, HTTP/2 pseudo-headers and framing headers are
    // generated (or forbidden) by the transport, matching the HTTP/1 transport.
    return iequals(name, "connection") || iequals(name, "keep-alive") ||
           iequals(name, "proxy-connection") || iequals(name, "transfer-encoding") ||
           iequals(name, "upgrade") || iequals(name, "te") || iequals(name, "host") ||
           iequals(name, "content-length");
  }

  endpoint address_;
  h2_transport_options options_;
};

} // namespace trie::http
