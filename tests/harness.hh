#pragma once

#include <cstdio>

namespace tst {

inline int failures = 0;
inline int checks = 0;

inline void check(bool ok, const char* expression, const char* file, int line) {
  ++checks;
  if (ok) return;
  ++failures;
  std::printf("FAIL %s:%d: %s\n", file, line, expression);
}

inline int report(const char* name) {
  std::printf("%s: %d checks, %d failures\n", name, checks, failures);
  return failures == 0 ? 0 : 1;
}

} // namespace tst

#define CHECK(condition) ::tst::check(static_cast<bool>(condition), #condition, __FILE__, __LINE__)

#define CHECK_EQ(lhs, rhs)                                                                      \
  do {                                                                                          \
    auto tst_lhs = (lhs);                                                                       \
    auto tst_rhs = (rhs);                                                                       \
    ::tst::check(tst_lhs == tst_rhs, #lhs " == " #rhs, __FILE__, __LINE__);                     \
  } while (false)
