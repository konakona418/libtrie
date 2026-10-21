#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include "trie/http/listener.hh"

namespace trie::http {

// Multi-threaded HTTP server: one listener socket + epoll loop per worker,
// bound with SO_REUSEPORT so the kernel load-balances new connections. All
// workers share one connection_limiter when serve_options::max_connections is
// set, enforcing a process-wide connection cap.
//
// Handlers run on whichever worker accepted the connection. Handler state (and
// middleware state) is shared across workers, so it must be thread-safe. Call
// server::use()/validation hooks before constructing the listener; the
// middleware chain is prepared here and must not be mutated afterwards.
template <class Router>
class threaded_listener {
public:
  explicit threaded_listener(Router& router, endpoint address, serve_options options = {},
                             std::size_t workers = 0)
      : router_(router) {
    if (workers == 0) workers = std::thread::hardware_concurrency();
    if (workers == 0) workers = 1;

    // One shared limiter => a global connection cap across all workers.
    options.connection_limit = std::make_shared<connection_limiter>(options.max_connections);
    options.reuse_port = true;

    // Build the middleware chain before any worker thread starts.
    router_.prepare();

    listeners_.push_back(std::make_unique<listener<Router>>(router_, address, options));
    port_ = listeners_.front()->port();
    valid_ = listeners_.front()->valid();

    for (std::size_t i = 1; valid_ && i < workers; ++i) {
      endpoint extra = address;
      extra.port = port_;
      listeners_.push_back(std::make_unique<listener<Router>>(router_, extra, options));
      valid_ = listeners_.back()->valid();
    }
    if (!valid_) listeners_.clear();
  }

  ~threaded_listener() {
    stop();
    join();
  }

  threaded_listener(threaded_listener const&) = delete;
  threaded_listener& operator=(threaded_listener const&) = delete;

  bool valid() const { return valid_; }
  std::uint16_t port() const { return port_; }
  std::size_t workers() const { return listeners_.size(); }
  int error_code() const { return listeners_.empty() ? 0 : listeners_.front()->error_code(); }

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
  std::vector<std::unique_ptr<listener<Router>>> listeners_{};
  std::vector<std::thread> threads_{};
  bool valid_ = false;
  std::uint16_t port_ = 0;
};

// Blocking convenience wrapper around threaded_listener.
template <class Router>
bool serve_threaded(Router& router, endpoint address, serve_options options = {}, std::size_t workers = 0) {
  threaded_listener<Router> server{router, std::move(address), options, workers};
  if (!server.valid()) return false;
  server.run();
  return true;
}

} // namespace trie::http
