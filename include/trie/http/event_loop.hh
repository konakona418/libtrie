#pragma once

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <coroutine>
#include <cstdint>
#include <functional>
#include <iterator>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace trie::http {

// Minimal fire-and-forget coroutine. The frame is destroyed by `final_suspend`
// (suspend_never), so a `task` object never owns it: dropping the task while the
// coroutine is suspended is safe and is how connections are detached.
class task {
public:
  struct promise_type {
    task get_return_object() noexcept {
      return task{std::coroutine_handle<promise_type>::from_promise(*this)};
    }
    std::suspend_never initial_suspend() noexcept { return {}; }
    std::suspend_never final_suspend() noexcept { return {}; }
    void return_void() noexcept {}
    void unhandled_exception() noexcept {}
  };

  using handle_type = std::coroutine_handle<promise_type>;

  explicit task(handle_type handle) noexcept : handle_(handle) {}
  task(task&& other) noexcept : handle_(std::exchange(other.handle_, {})) {}
  task(task const&) = delete;
  task& operator=(task const&) = delete;
  task& operator=(task&&) = delete;
  ~task() = default;

  handle_type handle() const noexcept { return handle_; }

private:
  handle_type handle_{};
};

class event_loop;

using clock = std::chrono::steady_clock;

// Awaiter that arms `fd` for one epoll notification and resumes the coroutine
// when it becomes ready or when the optional timeout expires. After resuming,
// await_resume() reports whether the fd became ready (true) or the wait timed
// out / was cancelled (false).
struct io_event {
  int fd = -1;
  std::uint32_t events = 0;
  clock::time_point deadline = clock::time_point::max();
  mutable bool timed_out_ = false;

  io_event() = default;
  io_event(int descriptor, std::uint32_t ready_events,
           std::chrono::milliseconds timeout = std::chrono::milliseconds{0})
      : fd(descriptor), events(ready_events) {
    if (timeout.count() > 0) deadline = clock::now() + timeout;
  }

  bool await_ready() const noexcept { return false; }
  void await_suspend(std::coroutine_handle<> handle) const;
  bool await_resume() const noexcept { return !timed_out_; }
};

// Single-threaded epoll loop. Permanent handlers (the listening socket,
// wake-up eventfd) coexist with one-shot coroutine waiters keyed by fd. Waiters
// may carry a deadline; expired waiters are resumed with timed_out set.
class event_loop {
public:
  event_loop() {
    epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    wake_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd_ >= 0) (void)add_permanent(wake_fd_, [this] { drain_wakeup(); });
  }

  ~event_loop() {
    if (wake_fd_ >= 0) ::close(wake_fd_);
    if (epoll_fd_ >= 0) ::close(epoll_fd_);
  }

  event_loop(event_loop const&) = delete;
  event_loop& operator=(event_loop const&) = delete;

  bool valid() const { return epoll_fd_ >= 0 && wake_fd_ >= 0; }

  bool add_permanent(int fd, std::function<void()> on_ready) {
    if (epoll_fd_ < 0 || fd < 0) return false;
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = fd;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event) < 0) return false;
    permanent_.insert_or_assign(fd, std::move(on_ready));
    return true;
  }

  // A connection may only have one outstanding wait at a time. A deadline of
  // clock::time_point::max() means "no timeout".
  void wait_for(int fd, std::uint32_t events, std::coroutine_handle<> handle, clock::time_point deadline,
                bool* timed_out) {
    waiters_.insert_or_assign(fd, waiter{handle, deadline, timed_out});
    epoll_event event{};
    event.events = events | EPOLLONESHOT;
    event.data.fd = fd;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &event) < 0 && errno == ENOENT)
      (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event);
  }

  // Resumes the waiter for `fd` as if it timed out. Used for graceful drain.
  bool cancel_wait(int fd) {
    auto entry = waiters_.find(fd);
    if (entry == waiters_.end()) return false;
    waiter pending = entry->second;
    waiters_.erase(entry);
    if (pending.timed_out != nullptr) *pending.timed_out = true;
    if (!pending.handle.done()) pending.handle.resume();
    return true;
  }

  void remove(int fd) {
    if (epoll_fd_ < 0 || fd < 0) return;
    (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    permanent_.erase(fd);
    waiters_.erase(fd);
  }

  // Runs until stop() is called. `should_exit` is polled each iteration (with a
  // short epoll timeout) and can be used for graceful draining.
  void run(std::function<bool()> should_exit = {}) {
    if (!valid()) return;
    current_ = this;
    running_.store(true);
    epoll_event events[64];
    while (running_.load(std::memory_order_relaxed)) {
      if (should_exit && should_exit()) break;

      int timeout_ms = should_exit ? 100 : -1;
      clock::time_point nearest = clock::time_point::max();
      for (auto const& [fd, pending] : waiters_)
        if (pending.deadline < nearest) nearest = pending.deadline;
      if (nearest != clock::time_point::max()) {
        auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(nearest - clock::now()).count();
        if (remaining < 0) remaining = 0;
        int const deadline_ms = static_cast<int>(std::min<long long>(remaining, 60'000));
        if (timeout_ms < 0 || deadline_ms < timeout_ms) timeout_ms = deadline_ms;
      }

      int ready = ::epoll_wait(epoll_fd_, events, static_cast<int>(std::size(events)), timeout_ms);
      if (ready < 0) {
        if (errno == EINTR) continue;
        break;
      }
      for (int i = 0; i < ready; ++i) {
        int fd = events[i].data.fd;
        if (fd == wake_fd_) {
          drain_wakeup();
          continue;
        }
        if (auto permanent = permanent_.find(fd); permanent != permanent_.end()) {
          permanent->second();
          continue;
        }
        if (auto waiter = waiters_.find(fd); waiter != waiters_.end()) {
          auto handle = waiter->second.handle;
          waiters_.erase(waiter);
          if (!handle.done()) handle.resume();
        }
      }
      expire_waiters();
      if (should_exit && should_exit()) break;
    }
    current_ = nullptr;
  }

  void stop() {
    running_.store(false, std::memory_order_relaxed);
    wake();
  }

  // Wakes epoll_wait without stopping the loop.
  void wake() {
    if (wake_fd_ >= 0) {
      std::uint64_t one = 1;
      (void)::write(wake_fd_, &one, sizeof(one));
    }
  }

  static event_loop* current() noexcept { return current_; }

private:
  struct waiter {
    std::coroutine_handle<> handle{};
    clock::time_point deadline = clock::time_point::max();
    bool* timed_out = nullptr;
  };

  void drain_wakeup() {
    std::uint64_t value = 0;
    while (::read(wake_fd_, &value, sizeof(value)) > 0) {
    }
  }

  void expire_waiters() {
    clock::time_point const now = clock::now();
    std::vector<int> expired{};
    for (auto const& [fd, pending] : waiters_)
      if (pending.deadline != clock::time_point::max() && pending.deadline <= now) expired.push_back(fd);

    for (int fd : expired) {
      auto entry = waiters_.find(fd);
      if (entry == waiters_.end()) continue;
      waiter pending = entry->second;
      waiters_.erase(entry);
      if (pending.timed_out != nullptr) *pending.timed_out = true;
      if (!pending.handle.done()) pending.handle.resume();
    }
  }

  int epoll_fd_ = -1;
  int wake_fd_ = -1;
  std::atomic<bool> running_{false};
  std::unordered_map<int, std::function<void()>> permanent_{};
  std::unordered_map<int, waiter> waiters_{};
  static inline thread_local event_loop* current_ = nullptr;
};

inline void io_event::await_suspend(std::coroutine_handle<> handle) const {
  event_loop* loop = event_loop::current();
  if (loop != nullptr) loop->wait_for(fd, events, handle, deadline, &timed_out_);
}

} // namespace trie::http
