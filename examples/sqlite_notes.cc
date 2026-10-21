#include "trie/trie.hh"
#include "trie/middleware/sqlite.hh"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

struct note_input {
  std::string text;
};

// Minimal quoting helper for the demo. Parameter binding is not implemented by
// trie::sqlite yet, so a real application should not paste unescaped input.
std::string quote(std::string_view text) {
  std::string out = "'";
  for (char c : text) {
    if (c == '\'') out += '\'';
    out += c;
  }
  out += '\'';
  return out;
}

struct notes_api {
  [[=trie::post("/notes")]] trie::json::value add_note(
      [[=trie::inject]] trie::sqlite::transaction& tx, [[=trie::body]] note_input input) {
    auto inserted = tx.exec("INSERT INTO notes(text) VALUES(" + quote(input.text) + ")");
    if (!inserted) return trie::json::value{{"error", inserted.error()}};
    trie::json::value result = trie::json::value::object();
    result["ok"] = true;
    return result;
  }

  [[=trie::get("/notes")]] trie::json::value list_notes(
      [[=trie::inject]] trie::sqlite::transaction& tx) {
    auto rows = tx.query("SELECT id, text FROM notes ORDER BY id");
    if (!rows) return trie::json::value{{"error", rows.error()}};
    trie::json::value result = trie::json::value::array();
    for (auto const& row : *rows) {
      trie::json::value item = trie::json::value::object();
      if (row.size() == 2) {
        item["id"] = row[0].value_or("");
        item["text"] = row[1].value_or("");
      }
      result.push_back(std::move(item));
    }
    return result;
  }
};

int main(int argc, char** argv) {
  const std::uint16_t port = argc > 1 ? static_cast<std::uint16_t>(std::atoi(argv[1])) : 8081;
  const std::string path = argc > 2 ? argv[2] : ":memory:";

  trie::sqlite::database database{};
  if (auto opened = database.open(path); !opened) {
    std::printf("failed to open sqlite database %s: %s\n", path.c_str(), opened.error().c_str());
    return 1;
  }
  if (auto created = database.exec("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, text TEXT)");
      !created) {
    std::printf("failed to create schema: %s\n", created.error().c_str());
    return 1;
  }

  trie::server<notes_api> router;
  router.use(trie::sqlite::middleware{&database});

  trie::http::listener<trie::server<notes_api>> server{router, trie::http::endpoint{"127.0.0.1", port}};
  if (!server.valid()) {
    std::printf("failed to bind 127.0.0.1:%u\n", static_cast<unsigned>(port));
    return 1;
  }
  std::printf("sqlite notes server on http://127.0.0.1:%u (db=%s)\n",
              static_cast<unsigned>(server.port()), path.c_str());
  std::printf("  curl -X POST -H 'Content-Type: application/json' -d '{\"text\":\"hello\"}' "
              "http://127.0.0.1:%u/notes\n",
              static_cast<unsigned>(server.port()));
  std::printf("  curl http://127.0.0.1:%u/notes\n", static_cast<unsigned>(server.port()));
  server.run();
  return 0;
}
