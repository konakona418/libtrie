#include "trie/detail/url.hh"

#include <array>
#include <string_view>

#include "harness.hh"

int main() {
  {
    std::array<char, 32> buffer{};
    auto written = trie::detail::url_decode("a%2Fb%20c", buffer);
    CHECK_EQ(written, std::size_t{5});
    CHECK_EQ((std::string_view{buffer.data(), written}), std::string_view{"a/b c"});
  }
  {
    std::array<char, 32> buffer{};
    auto written = trie::detail::url_decode("hello+world", buffer);
    CHECK_EQ(written, std::size_t{11});
    CHECK_EQ((std::string_view{buffer.data(), written}), std::string_view{"hello world"});
  }
  {
    std::array<char, 3> buffer{};
    CHECK_EQ(trie::detail::url_decode("abcd", buffer), std::string_view::npos);
  }
  {
    std::array<char, 8> buffer{};
    CHECK_EQ(trie::detail::url_decode("%zz", buffer), std::string_view::npos);
    CHECK_EQ(trie::detail::url_decode("%4", buffer), std::string_view::npos);
  }

  CHECK_EQ(trie::detail::url_encode("hello world"), std::string{"hello%20world"});
  CHECK_EQ(trie::detail::url_encode("a/b?c=d&e"), std::string{"a%2Fb%3Fc%3Dd%26e"});
  CHECK_EQ(trie::detail::url_encode("abc-._~123"), std::string{"abc-._~123"});

  {
    std::array<char, 32> buffer{};
    auto written = trie::detail::url_decode(trie::detail::url_encode("x/y z"), buffer);
    CHECK_EQ((std::string_view{buffer.data(), written}), std::string_view{"x/y z"});
  }
  return tst::report("url_test");
}
