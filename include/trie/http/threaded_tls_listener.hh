#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include "trie/http/listener.hh"
#include "trie/http/tls_listener.hh"

namespace trie::http {

// Multi-threaded HTTPS server: one tls_listener worker per thread, each with its
// own listening socket bound to the same port with SO_REUSEPORT so the kernel
// load-balances new connections. All workers share one connection_limiter for a
// global connection cap (tls_serve_options::http.max_connections).
//
// Handlers run on whichever worker accepted the connection. Handler state (and
// middleware state) is shared across workers, so it must be thread-safe. The
// middleware chain is prepared once here, before any worker starts.
//
// HTTP/2 support is inherited from tls_listener.hh: this wrapper only forwards
// tls_serve_options, so it compiles with or without
// TRIE_TLS_LISTENER_WITH_HTTP2.
template <class Router>
class threaded_tls_listener {
public:
  explicit threaded_tls_listener(Router& router, endpoint address, tls_serve_options options = {},
                                 std::size_t workers = 0)
      : router_(router) {
    if (workers == 0) workers = std::thread::hardware_concurrency();
    if (workers == 0) workers = 1;

    // One shared limiter => a global connection cap across all workers. Honor a
    // caller-supplied shared limiter; otherwise derive one from max_connections.
    if (options.http.connection_limit == nullptr)
      options.http.connection_limit = std::make_shared<connection_limiter>(options.http.max_connections);
    options.http.reuse_port = true;

    // Build the middleware chain before any worker thread starts.
    router_.prepare();

    listeners_.push_back(std::make_unique<tls_listener<Router>>(router_, address, options));
    error_code_ = listeners_.front()->error_code();
    port_ = listeners_.front()->port();
    valid_ = listeners_.front()->valid();

    for (std::size_t i = 1; valid_ && i < workers; ++i) {
      endpoint extra = address;
      extra.port = port_;
      listeners_.push_back(std::make_unique<tls_listener<Router>>(router_, extra, options));
      valid_ = listeners_.back()->valid();
      if (!valid_) error_code_ = listeners_.back()->error_code();
    }
    if (!valid_) {
      // Clean up partially created workers; keep valid()/error_code() observable.
      listeners_.clear();
      port_ = 0;
    }
  }

  ~threaded_tls_listener() {
    stop();
    join();
  }

  threaded_tls_listener(threaded_tls_listener const&) = delete;
  threaded_tls_listener& operator=(threaded_tls_listener const&) = delete;

  bool valid() const { return valid_; }

  int error_code() const { return error_code_; }

  std::uint16_t port() const { return port_; }

  std::size_t workers() const { return listeners_.size(); }

  // True once every worker has been asked to stop (i.e. after stop()).
  bool stopping() const {
    if (listeners_.empty()) return false;
    for (auto const& worker : listeners_)
      if (!worker->stopping()) return false;
    return true;
  }

  // Accepted connections summed over all workers (observability/tests).
  std::size_t accepted_connections() const {
    std::size_t total = 0;
    for (auto const& worker : listeners_) total += worker->accepted_connections();
    return total;
  }

  // Per-worker accepted connection counts (observability/tests).
  std::vector<std::size_t> accepted_per_worker() const {
    std::vector<std::size_t> counts;
    counts.reserve(listeners_.size());
    for (auto const& worker : listeners_) counts.push_back(worker->accepted_connections());
    return counts;
  }

  // Blocks until all workers exit (i.e. until stop() drains them).
  void run() {
    if (!valid_) return;
    threads_.reserve(listeners_.size());
    for (auto& worker : listeners_) threads_.emplace_back([&worker] { worker->run(); });
    join();
  }

  // Non-blocking: signals every worker to drain and exit.
  void stop() {
    for (auto& worker : listeners_) worker->stop();
  }

private:
  void join() {
    for (auto& thread : threads_) {
      if (thread.joinable()) thread.join();
    }
    threads_.clear();
  }

  Router& router_;
  std::vector<std::unique_ptr<tls_listener<Router>>> listeners_{};
  std::vector<std::thread> threads_{};
  bool valid_ = false;
  int error_code_ = 0;
  std::uint16_t port_ = 0;
};

// Blocking convenience wrapper around threaded_tls_listener.
template <class Router>
bool serve_tls_threaded(Router& router, endpoint address, tls_serve_options options = {},
                        std::size_t workers = 0) {
  threaded_tls_listener<Router> server{router, std::move(address), std::move(options), workers};
  if (!server.valid()) return false;
  server.run();
  return true;
}

} // namespace trie::http
