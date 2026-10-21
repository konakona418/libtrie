#pragma once

#include <string>

namespace trie {

// Error reported by the type-safe client (transport failures use status 0).
struct client_error {
  int status = 0;
  std::string message{};
};

} // namespace trie
