// 01 — Hello, libtrie.
//
// The smallest useful program: one handler annotated with [[=trie::get(...)]]
// and a listener bound to an ephemeral port. A real application would simply
// call server.run() and block; this demo stops the event loop from a helper
// thread so the example terminates on its own.
#include "trie/trie.hh"

#include <chrono>
#include <cstdio>
#include <thread>

struct hello_api {
  // The annotation is the whole route table: no registration call is needed.
  [[=trie::get("/hello")]] std::string hello() { return "hello, world"; }
};

int main() {
  trie::server<hello_api> router;

  // Port 0 asks the kernel for a free port; listener::port() reports the one
  // that was actually bound, so the example never collides with another server.
  trie::http::listener<trie::server<hello_api>> server{router, trie::http::endpoint{"127.0.0.1", 0}};
  if (!server.valid()) {
    std::puts("error: could not bind 127.0.0.1:0");
    return 1;
  }

  const unsigned port = static_cast<unsigned>(server.port());
  std::printf("listening on http://127.0.0.1:%u/hello\n", port);
  std::printf("try: curl http://127.0.0.1:%u/hello\n", port);

  // A normal server calls server.run() and blocks: the listener serves requests
  // until stop() is called. For a runnable demo, stop after a short delay.
  std::thread stopper{[&server] {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    server.stop();
  }};
  server.run();
  stopper.join();

  std::puts("listener stopped");
  return 0;
}
