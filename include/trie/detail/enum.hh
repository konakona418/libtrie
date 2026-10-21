#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <string_view>

#include <meta>

namespace trie::detail {

template <class E>
consteval std::size_t enumerator_count() {
  return std::meta::enumerators_of(^^E).size();
}

template <class E>
struct enumerator_entry {
  std::string_view name;
  E value;
};

template <class E>
consteval auto make_enumerator_table() {
  std::array<enumerator_entry<E>, enumerator_count<E>()> out{};
  std::size_t index = 0;
  template for (constexpr auto enumerator : std::define_static_array(std::meta::enumerators_of(^^E))) {
    constexpr auto name = std::define_static_string(std::meta::identifier_of(enumerator));
    out[index++] = enumerator_entry<E>{std::string_view{name}, std::meta::extract<E>(enumerator)};
  }
  return out;
}

template <class E>
inline constexpr auto enumerator_table = make_enumerator_table<E>();

} // namespace trie::detail

namespace trie {

// Identifier of `value`, or an empty view when the value is not a named
// enumerator (e.g. a combination of flag values).
template <class E>
constexpr std::string_view enum_name(E value) {
  for (auto const& entry : detail::enumerator_table<E>)
    if (entry.value == value) return entry.name;
  return {};
}

template <class E>
constexpr std::optional<E> enum_from_name(std::string_view name) {
  for (auto const& entry : detail::enumerator_table<E>)
    if (entry.name == name) return entry.value;
  return std::nullopt;
}

} // namespace trie
