// Multi-threaded HTTP server: SO_REUSEPORT across worker event loops.
//
//   ./build/dev/examples/trie_06_threaded 8083        # 4 workers by default
//   ./build/dev/examples/trie_06_threaded 8083 8      # 8 workers

#include "trie/trie.hh"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

struct api {
  [[=trie::get("/hello")]] std::string hello() { return "hello, threaded world"; }
};

int main(int argc, char** argv) {
  const std::uint16_t port = argc > 1 ? static_cast<std::uint16_t>(std::atoi(argv[1])) : 8083;
  const std::size_t workers = argc > 2 ? static_cast<std::size_t>(std::atoi(argv[2])) : 4;

  trie::http::serve_options options{};
  options.max_connections = 1024; // process-wide cap across workers

  trie::server<api> router;
  trie::http::threaded_listener<trie::server<api>> server{router, trie::http::endpoint{"127.0.0.1", port},
                                                            options, workers};
  if (!server.valid()) {
    std::printf("failed to bind 127.0.0.1:%u\n", static_cast<unsigned>(port));
    return 1;
  }
  std::printf("listening on http://127.0.0.1:%u with %zu workers (SO_REUSEPORT)\n",
              static_cast<unsigned>(server.port()), server.workers());
  server.run();
  return 0;
}
