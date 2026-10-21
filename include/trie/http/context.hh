#pragma once

#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

#include "trie/http.hh"

namespace trie::http {

// Request-scoped, type-keyed storage shared between middleware and handlers.
// Middleware can `set` an owned value (or `set_ref` a borrowed one); handlers
// receive it through `[[=trie::inject]] T&` parameters. Keys are per-type tokens,
// so no RTTI is required.
class context {
public:
  context() = default;
  context(context const&) = delete;
  context& operator=(context const&) = delete;
  ~context() = default;

  template <class T>
  void set(T value) {
    auto entry = std::make_unique<holder<T>>();
    entry->owned = std::make_unique<T>(std::move(value));
    entry->ptr = entry->owned.get();
    entries_.insert_or_assign(type_key<T>(), std::move(entry));
  }

  template <class T>
  void set_ref(T& value) {
    auto entry = std::make_unique<holder<T>>();
    entry->ptr = std::addressof(value);
    entries_.insert_or_assign(type_key<T>(), std::move(entry));
  }

  template <class T>
  T* get() {
    auto entry = entries_.find(type_key<T>());
    if (entry == entries_.end()) return nullptr;
    return static_cast<holder<T>*>(entry->second.get())->ptr;
  }

  template <class T>
  T const* get() const {
    auto entry = entries_.find(type_key<T>());
    if (entry == entries_.end()) return nullptr;
    return static_cast<holder<T> const*>(entry->second.get())->ptr;
  }

  template <class T>
  bool contains() const {
    return entries_.find(type_key<T>()) != entries_.end();
  }

  void clear() { entries_.clear(); }

private:
  struct holder_base {
    virtual ~holder_base() = default;
  };

  template <class T>
  struct holder : holder_base {
    std::unique_ptr<T> owned{};
    T* ptr = nullptr;
  };

  template <class T>
  static const void* type_key() {
    static const char key = 0;
    return &key;
  }

  std::unordered_map<const void*, std::unique_ptr<holder_base>> entries_{};
};

// The continuation a middleware calls to hand control to the next middleware or
// the router.
using next = std::function<response(context&, request_view const&)>;

} // namespace trie::http
