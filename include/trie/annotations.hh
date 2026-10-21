#pragma once

#include <array>
#include <cstddef>

namespace trie {

enum class method : unsigned char { get, post, put, patch, del, head, options };

inline constexpr std::size_t method_count = 7;

namespace detail {
inline constexpr std::size_t route_path_capacity = 96;
inline constexpr std::size_t annotation_name_capacity = 32;

// Copies a NUL-terminated string into a fixed-size buffer. Sets `ok` to false
// when the string does not fit, so route tables can reject it later.
consteval std::array<char, route_path_capacity> copy_path(const char* p) {
  std::array<char, route_path_capacity> out{};
  std::size_t i = 0;
  for (; p[i] != '\0' && i + 1 < out.size(); ++i) out[i] = p[i];
  return out;
}

consteval std::array<char, annotation_name_capacity> copy_annotation_name(const char* p) {
  std::array<char, annotation_name_capacity> out{};
  std::size_t i = 0;
  for (; p[i] != '\0' && i + 1 < out.size(); ++i) out[i] = p[i];
  return out;
}

consteval bool fits(const char* p, std::size_t capacity) {
  std::size_t i = 0;
  for (; p[i] != '\0'; ++i)
    if (i + 1 >= capacity) return false;
  return i + 1 < capacity;
}
} // namespace detail

// Annotation payload describing an HTTP route. It has to be a structural type:
// annotations cannot hold pointers to string literals (neither GCC nor Clang
// can reflect those), so the path is stored in a fixed-size buffer instead.
//
//   [[=trie::get("/users/{id}")]]
struct route {
  method m;
  std::array<char, detail::route_path_capacity> path{};
  bool valid = true;

  consteval route(method mm, const char* p) : m{mm} {
    valid = detail::fits(p, detail::route_path_capacity);
    path = detail::copy_path(p);
  }
};

consteval route get(const char* p) { return route{method::get, p}; }
consteval route post(const char* p) { return route{method::post, p}; }
consteval route put(const char* p) { return route{method::put, p}; }
consteval route patch(const char* p) { return route{method::patch, p}; }
consteval route del(const char* p) { return route{method::del, p}; }
consteval route head(const char* p) { return route{method::head, p}; }
consteval route options(const char* p) { return route{method::options, p}; }

// Parameter annotations. `from_path` is optional (path parameters are inferred
// positionally); `query` and `header` select a named value; `body` takes the
// request body.
struct from_path_t {};
inline constexpr from_path_t from_path{};

struct query_t {
  std::array<char, detail::annotation_name_capacity> name{};
  bool valid = true;

  consteval query_t(const char* n) {
    valid = detail::fits(n, detail::annotation_name_capacity);
    name = detail::copy_annotation_name(n);
  }
};

struct header_t {
  std::array<char, detail::annotation_name_capacity> name{};
  bool valid = true;

  consteval header_t(const char* n) {
    valid = detail::fits(n, detail::annotation_name_capacity);
    name = detail::copy_annotation_name(n);
  }
};

struct body_t {};
inline constexpr body_t body{};

consteval query_t query(const char* n) { return query_t{n}; }
consteval header_t header(const char* n) { return header_t{n}; }

} // namespace trie
