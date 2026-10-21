#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace trie::detail {

constexpr bool is_unreserved(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == '-' || c == '.' || c == '_' || c == '~';
}

constexpr int hex_value(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Percent-decodes `src` into `dst`. Returns the number of bytes written, or
// `npos` when `dst` is too small or the encoding is malformed.
inline std::size_t url_decode(std::string_view src, std::span<char> dst) {
  std::size_t out = 0;
  for (std::size_t i = 0; i < src.size(); ++i) {
    unsigned char c = static_cast<unsigned char>(src[i]);
    if (c == '+') {
      if (out >= dst.size()) return std::string_view::npos;
      dst[out++] = ' ';
    } else if (c == '%') {
      if (i + 2 >= src.size()) return std::string_view::npos;
      int hi = hex_value(static_cast<unsigned char>(src[i + 1]));
      int lo = hex_value(static_cast<unsigned char>(src[i + 2]));
      if (hi < 0 || lo < 0) return std::string_view::npos;
      if (out >= dst.size()) return std::string_view::npos;
      dst[out++] = static_cast<char>((hi << 4) | lo);
      i += 2;
    } else {
      if (out >= dst.size()) return std::string_view::npos;
      dst[out++] = static_cast<char>(c);
    }
  }
  return out;
}

inline std::string url_encode(std::string_view src) {
  static constexpr char hex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(src.size());
  for (unsigned char c : src) {
    if (is_unreserved(c)) {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 0x0F]);
    }
  }
  return out;
}

} // namespace trie::detail
