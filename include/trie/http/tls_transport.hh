#pragma once

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <expected>
#include <fcntl.h>
#include <limits>
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

#include "trie/error.hh"
#include "trie/http.hh"

namespace trie::http {

struct tls_transport_options {
  int connect_timeout_ms = 5000;
  int io_timeout_ms = 5000;
  std::size_t max_response_bytes = 8 * 1024 * 1024;
  bool verify_peer = true;
  std::string ca_file{}; // optional CA bundle; empty -> system default paths
  std::string client_cert_file{};
  std::string client_key_file{};
  std::string server_name{}; // SNI + hostname verification; empty -> address.host
};

// Blocking TLS transport for trie::client, implemented with OpenSSL. One TLS
// connection per request: the request is sent with `Connection: close` and the
// response is read until Content-Length bytes or EOF. The TCP connect uses a
// nonblocking connect + poll with `connect_timeout_ms`, after which the socket
// is switched back to blocking mode with SO_RCVTIMEO/SO_SNDTIMEO for TLS I/O.
// Peer verification is on by default; hostname verification uses
// `server_name` (falling back to `address.host`) and sends it as SNI.
class tls_transport {
public:
  explicit tls_transport(endpoint address, tls_transport_options options = {})
      : address_(std::move(address)), options_(options) {}

  std::expected<response, trie::client_error> send(request request) const {
    std::string wire = build_request(request);
    bool wants_body = request.m != trie::method::head;

    int fd = connect_socket();
    if (fd < 0) {
      return std::unexpected(trie::client_error{
          0, "failed to connect to " + address_.host + ":" + std::to_string(address_.port)});
    }

    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    auto cleanup = [&] {
      if (ssl != nullptr) {
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
      }
      if (ctx != nullptr) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
      }
      if (fd >= 0) {
        ::close(fd);
        fd = -1;
      }
    };
    auto fail = [&](std::string message) -> std::expected<response, trie::client_error> {
      cleanup();
      return std::unexpected(trie::client_error{0, std::move(message)});
    };

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) return fail(openssl_error("failed to create TLS context"));
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
    // Treat a peer that closes without close_notify as EOF, like plain sockets.
    (void)SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

    peer_name name = resolve_peer_name();
    if (options_.verify_peer) {
      if (!options_.ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(ctx, options_.ca_file.c_str(), nullptr) != 1)
          return fail(openssl_error("failed to load CA file " + options_.ca_file));
      } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        return fail(openssl_error("failed to load system CA certificates"));
      }
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
      if (!set_verify_name(ctx, name)) return fail("failed to configure hostname verification for " + name.text);
    } else {
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    if (!options_.client_cert_file.empty() || !options_.client_key_file.empty()) {
      if (options_.client_cert_file.empty() || options_.client_key_file.empty())
        return fail("client_cert_file and client_key_file must be set together");
      if (SSL_CTX_use_certificate_chain_file(ctx, options_.client_cert_file.c_str()) != 1)
        return fail(openssl_error("failed to load client certificate " + options_.client_cert_file));
      if (SSL_CTX_use_PrivateKey_file(ctx, options_.client_key_file.c_str(), SSL_FILETYPE_PEM) != 1)
        return fail(openssl_error("failed to load client private key " + options_.client_key_file));
      if (SSL_CTX_check_private_key(ctx) != 1) return fail("client certificate and private key do not match");
    }

    ssl = SSL_new(ctx);
    if (ssl == nullptr) return fail(openssl_error("failed to create TLS session"));
    if (SSL_set_fd(ssl, fd) != 1) return fail(openssl_error("failed to attach TLS session to socket"));
    if (!name.ip && !name.text.empty()) (void)SSL_set_tlsext_host_name(ssl, name.text.c_str());

    while (true) {
      ERR_clear_error();
      int result = SSL_connect(ssl);
      if (result == 1) break;
      int error = SSL_get_error(ssl, result);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (!wait_ready(fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT))
          return fail("TLS handshake timed out");
        continue;
      }
      long verify_result = SSL_get_verify_result(ssl);
      if (verify_result != X509_V_OK)
        return fail(std::string{"TLS certificate verification failed: "} +
                    X509_verify_cert_error_string(verify_result));
      return fail(openssl_error("TLS handshake failed"));
    }

    constexpr std::size_t max_write = 1 << 20;
    std::string_view pending{wire};
    while (!pending.empty()) {
      ERR_clear_error();
      std::size_t amount = pending.size() < max_write ? pending.size() : max_write;
      int written = SSL_write(ssl, pending.data(), static_cast<int>(amount));
      if (written > 0) {
        pending.remove_prefix(static_cast<std::size_t>(written));
        continue;
      }
      int error = SSL_get_error(ssl, written);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (!wait_ready(fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT))
          return fail("timed out sending request");
        continue;
      }
      return fail(openssl_error("failed to send request"));
    }

    std::string buffer;
    std::array<char, 8192> chunk{};
    std::size_t head_end = 0;
    std::size_t content_length = 0;
    bool has_head = false;
    bool has_length = false;
    int status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string parse_message;

    while (true) {
      if (has_head && (!wants_body || !has_length || buffer.size() >= head_end + 4 + content_length)) break;
      if (buffer.size() > options_.max_response_bytes) return fail("response too large");

      ERR_clear_error();
      int received = SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size()));
      if (received > 0) {
        buffer.append(chunk.data(), static_cast<std::size_t>(received));
        if (!has_head) {
          auto position = buffer.find("\r\n\r\n");
          if (position != std::string::npos) {
            head_end = position;
            if (!parse_head(std::string_view{buffer}.substr(0, head_end), status_code, headers, content_length,
                            has_length, parse_message)) {
              return fail(std::move(parse_message));
            }
            has_head = true;
            if (status_code == 204 || status_code == 304) wants_body = false;
            if (has_length && (content_length > options_.max_response_bytes ||
                               content_length > std::numeric_limits<std::size_t>::max() - head_end - 4))
              return fail("response too large");
          }
        }
        continue;
      }

      int error = SSL_get_error(ssl, received);
      if (error == SSL_ERROR_ZERO_RETURN) {
        if (!has_head) return fail("connection closed before response head");
        break;
      }
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (!wait_ready(fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT))
          return fail("timed out receiving response");
        continue;
      }
      return fail(has_head ? openssl_error("failed to receive response")
                           : std::string{"connection closed before response head"});
    }

    if (wants_body && has_length && buffer.size() < head_end + 4 + content_length)
      return fail("connection closed before response body");
    cleanup();

    response result{};
    result.status_code = status_code;
    result.headers = std::move(headers);
    if (wants_body) {
      if (has_length) {
        result.body.assign(buffer.data() + head_end + 4, content_length);
      } else {
        result.body.assign(buffer.data() + head_end + 4, buffer.size() - head_end - 4);
      }
    }
    return result;
  }

private:
  struct peer_name {
    std::string text{};
    bool ip = false;
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

  static bool set_verify_name(SSL_CTX* ctx, peer_name const& name) {
    X509_VERIFY_PARAM* param = SSL_CTX_get0_param(ctx);
    if (param == nullptr) return false;
    if (name.ip) return X509_VERIFY_PARAM_set1_ip_asc(param, name.text.c_str()) == 1;
    return X509_VERIFY_PARAM_set1_host(param, name.text.c_str(), name.text.size()) == 1;
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

  bool wait_ready(int fd, short events) const {
    pollfd descriptor{fd, events, 0};
    while (true) {
      int ready = ::poll(&descriptor, 1, options_.io_timeout_ms);
      if (ready > 0) return (descriptor.revents & (events | POLLERR | POLLHUP)) != 0;
      if (ready < 0 && errno == EINTR) continue;
      return false;
    }
  }

  std::string build_request(request const& request) const {
    std::string wire;
    wire.reserve(128 + request.body.size());
    wire += method_name(request.m);
    wire += ' ';
    wire += request.target.empty() ? std::string_view{"/"} : std::string_view{request.target};
    wire += " HTTP/1.1\r\n";

    bool has_host = false;
    for (auto const& header : request.headers) {
      if (iequals(header.first, "host")) has_host = true;
      if (iequals(header.first, "connection") || iequals(header.first, "content-length")) continue;
      wire += header.first;
      wire += ": ";
      wire += header.second;
      wire += "\r\n";
    }
    if (!has_host) {
      wire += "Host: ";
      wire += address_.host;
      wire += "\r\n";
    }
    wire += "Connection: close\r\n";
    wire += "Content-Length: ";
    wire += std::to_string(request.body.size());
    wire += "\r\n\r\n";
    wire += request.body;
    return wire;
  }

  int connect_socket() const {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* results = nullptr;
    std::string service = std::to_string(address_.port);
    if (::getaddrinfo(address_.host.c_str(), service.c_str(), &hints, &results) != 0) return -1;

    int connected = -1;
    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
      int fd = ::socket(it->ai_family, it->ai_socktype | SOCK_CLOEXEC, it->ai_protocol);
      if (fd < 0) continue;

      int flags = ::fcntl(fd, F_GETFL, 0);
      (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

      bool ok = ::connect(fd, it->ai_addr, it->ai_addrlen) == 0;
      if (!ok && errno == EINPROGRESS) {
        pollfd descriptor{fd, POLLOUT, 0};
        int ready = ::poll(&descriptor, 1, options_.connect_timeout_ms);
        if (ready > 0) {
          int error = 0;
          socklen_t length = sizeof(error);
          ok = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
        }
      }
      if (!ok) {
        ::close(fd);
        continue;
      }

      (void)::fcntl(fd, F_SETFL, flags);
      timeval timeout{};
      timeout.tv_sec = options_.io_timeout_ms / 1000;
      timeout.tv_usec = (options_.io_timeout_ms % 1000) * 1000;
      (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
      connected = fd;
      break;
    }
    ::freeaddrinfo(results);
    return connected;
  }

  static bool parse_head(std::string_view head, int& status_code,
                         std::vector<std::pair<std::string, std::string>>& headers, std::size_t& content_length,
                         bool& has_length, std::string& message) {
    auto line_end = head.find("\r\n");
    std::string_view status_line = line_end == std::string_view::npos ? head : head.substr(0, line_end);
    auto first_space = status_line.find(' ');
    if (first_space == std::string_view::npos) {
      message = "malformed response status line";
      return false;
    }
    auto second_space = status_line.find(' ', first_space + 1);
    std::string_view code_text =
        status_line.substr(first_space + 1, second_space == std::string_view::npos
                                               ? status_line.size() - first_space - 1
                                               : second_space - first_space - 1);
    auto [ptr, ec] = std::from_chars(code_text.data(), code_text.data() + code_text.size(), status_code);
    if (ec != std::errc{} || ptr != code_text.data() + code_text.size()) {
      message = "malformed response status code";
      return false;
    }

    std::size_t position = line_end == std::string_view::npos ? head.size() : line_end + 2;
    while (position < head.size()) {
      auto next = head.find("\r\n", position);
      std::string_view line =
          head.substr(position, next == std::string_view::npos ? head.size() - position : next - position);
      position = next == std::string_view::npos ? head.size() : next + 2;

      auto colon = line.find(':');
      if (colon == std::string_view::npos) continue;
      std::string_view name = line.substr(0, colon);
      std::string_view value = line.substr(colon + 1);
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
      while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);

      if (iequals(name, "content-length")) {
        auto [length_ptr, length_ec] = std::from_chars(value.data(), value.data() + value.size(), content_length);
        if (length_ec != std::errc{} || length_ptr != value.data() + value.size()) {
          message = "malformed Content-Length";
          return false;
        }
        has_length = true;
      } else if (iequals(name, "transfer-encoding") && !iequals(value, "identity")) {
        message = "unsupported transfer-encoding in response";
        return false;
      }
      headers.emplace_back(name, value);
    }
    return true;
  }

  endpoint address_;
  tls_transport_options options_;
};

} // namespace trie::http
