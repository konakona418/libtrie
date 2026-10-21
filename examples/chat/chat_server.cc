// A small SQLite-backed chat room demonstrating libtrie's main features:
//   - annotated routing with path/query parameters
//   - typed JSON bodies with schema validation and custom validation hooks
//   - middleware (request counter + SQLite transaction per request)
//   - SQLite prepared-statement parameter binding
//   - JSON responses and a tiny browser UI served from a handler
//
// Build:   cmake --build --preset dev --target trie_chat
// Run:     ./build/dev/examples/trie_chat 8082 chat.db
// Browser: http://127.0.0.1:8082/
//
//   curl http://127.0.0.1:8082/api/rooms
//   curl -X POST -H 'Content-Type: application/json' -d '{"name":"random"}'
//        http://127.0.0.1:8082/api/rooms
//   curl -X POST -H 'Content-Type: application/json'
//        -d '{"author":"alice","text":"hello"}'
//        http://127.0.0.1:8082/api/rooms/general/messages
//   curl 'http://127.0.0.1:8082/api/rooms/general/messages?after=0&limit=50'

#include "trie/middleware/sqlite.hh"
#include "trie/trie.hh"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr std::int64_t default_limit = 50;
constexpr std::int64_t max_limit = 200;

std::int64_t parse_int64(std::string_view text) {
  std::int64_t value = 0;
  auto [pointer, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  return error == std::errc{} && pointer == text.data() + text.size() ? value : 0;
}

std::int64_t clamp_limit(std::optional<int> limit) {
  if (!limit.has_value()) return default_limit;
  return std::max<std::int64_t>(1, std::min<std::int64_t>(max_limit, *limit));
}

trie::json::value message_json(trie::sqlite::row const& row) {
  trie::json::value message = trie::json::value::object();
  message["id"] = parse_int64(row[0].value_or("0"));
  message["author"] = row[1].value_or("");
  message["text"] = row[2].value_or("");
  message["created_at"] = row[3].value_or("");
  return message;
}

trie::json::value error_json(std::string message) {
  return trie::json::value{{"error", std::move(message)}};
}

struct room_input {
  std::string name;
};

struct message_input {
  std::string author;
  std::string text;
};

struct request_info {
  std::int64_t number = 0;
};

// Counts requests and exposes the number to handlers through the request context.
struct counting_middleware {
  std::int64_t count = 0;

  trie::http::response operator()(trie::http::context& context, const trie::http::request_view& request,
                                  const trie::http::next& next) {
    context.set<request_info>(request_info{++count});
    return next(context, request);
  }
};

constexpr std::string_view chat_html = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>libtrie chat</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
  #messages { border: 1px solid #ccc; border-radius: 6px; height: 420px; overflow-y: auto;
              padding: .75rem; background: #fafafa; }
  .message { margin: .35rem 0; }
  .author { font-weight: 600; color: #0645ad; }
  .time { color: #888; font-size: .75rem; margin-left: .5rem; }
  form { display: flex; gap: .5rem; margin-top: .75rem; }
  input, button { font: inherit; padding: .4rem .6rem; }
  input[type=text] { flex: 1; }
</style>
</head>
<body>
<h1>libtrie chat</h1>
<p>
  Room: <select id="room"></select>
  <input id="new-room" type="text" placeholder="new room">
  <button id="create-room">create</button>
  <span id="status"></span>
</p>
<div id="messages"></div>
<form id="compose">
  <input id="author" type="text" placeholder="your name" value="anon">
  <input id="text" type="text" placeholder="message" autocomplete="off">
  <button type="submit">send</button>
</form>
<script>
let lastId = 0;
let currentRoom = "general";

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || ("HTTP " + response.status));
  return body;
}

function render(messages) {
  const box = document.getElementById("messages");
  for (const message of messages) {
    lastId = Math.max(lastId, message.id);
    const line = document.createElement("div");
    line.className = "message";
    const author = document.createElement("span");
    author.className = "author";
    author.textContent = message.author;
    const time = document.createElement("span");
    time.className = "time";
    time.textContent = message.created_at;
    const text = document.createElement("span");
    text.textContent = " " + message.text;
    line.append(author, time, text);
    box.appendChild(line);
  }
  if (messages.length) box.scrollTop = box.scrollHeight;
}

async function loadRooms() {
  const rooms = await api("/api/rooms");
  const select = document.getElementById("room");
  const selected = currentRoom;
  select.innerHTML = "";
  for (const room of rooms) {
    const option = document.createElement("option");
    option.value = room.name;
    option.textContent = room.name + " (" + room.messages + ")";
    select.appendChild(option);
  }
  select.value = selected;
}

async function poll() {
  try {
    const messages = await api("/api/rooms/" + encodeURIComponent(currentRoom) +
                               "/messages?after=" + lastId + "&limit=100");
    render(messages);
    document.getElementById("status").textContent = "";
  } catch (error) {
    document.getElementById("status").textContent = error.message;
  }
  setTimeout(poll, 1000);
}

document.getElementById("room").addEventListener("change", async (event) => {
  currentRoom = event.target.value;
  lastId = 0;
  document.getElementById("messages").innerHTML = "";
});

document.getElementById("create-room").addEventListener("click", async () => {
  const name = document.getElementById("new-room").value.trim();
  if (!name) return;
  try {
    await api("/api/rooms", { method: "POST", headers: { "Content-Type": "application/json" },
                              body: JSON.stringify({ name }) });
    currentRoom = name;
    lastId = 0;
    document.getElementById("messages").innerHTML = "";
    document.getElementById("new-room").value = "";
    await loadRooms();
  } catch (error) {
    document.getElementById("status").textContent = error.message;
  }
});

document.getElementById("compose").addEventListener("submit", async (event) => {
  event.preventDefault();
  const author = document.getElementById("author").value.trim() || "anon";
  const text = document.getElementById("text").value.trim();
  if (!text) return;
  try {
    await api("/api/rooms/" + encodeURIComponent(currentRoom) + "/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ author, text }),
    });
    document.getElementById("text").value = "";
    await poll();
  } catch (error) {
    document.getElementById("status").textContent = error.message;
  }
});

loadRooms().then(poll);
</script>
</body>
</html>)HTML";

struct chat_api {
  // Browser UI.
  [[=trie::get("/")]] void index(trie::http::response& response) {
    response.set_header("Content-Type", "text/html; charset=utf-8");
    response.body = std::string{chat_html};
  }

  [[=trie::get("/api/health")]] trie::json::value health([[=trie::inject]] request_info const& info) {
    return trie::json::value{{"ok", true}, {"requests", info.number}};
  }

  // List rooms with message counts.
  [[=trie::get("/api/rooms")]] trie::json::value list_rooms(
      [[=trie::inject]] trie::sqlite::transaction& tx, trie::http::response& response) {
    auto rows = tx.query(
        "SELECT r.id, r.name, COUNT(m.id) FROM rooms r "
        "LEFT JOIN messages m ON m.room_id = r.id GROUP BY r.id ORDER BY r.name");
    if (!rows) {
      response.status_code = 500;
      return error_json(rows.error());
    }
    trie::json::value result = trie::json::value::array();
    for (auto const& row : *rows) {
      result.push_back(trie::json::value{
          {"id", parse_int64(row[0].value_or("0"))},
          {"name", row[1].value_or("")},
          {"messages", parse_int64(row[2].value_or("0"))},
      });
    }
    return result;
  }

  // Create a room (schema validation guarantees a non-empty string field).
  [[=trie::post("/api/rooms")]] trie::json::value create_room(
      [[=trie::inject]] trie::sqlite::transaction& tx, [[=trie::body]] room_input input,
      trie::http::response& response) {
    auto inserted = tx.exec("INSERT INTO rooms(name) VALUES(?1)", input.name);
    if (!inserted) {
      response.status_code = 409;
      return error_json("room already exists");
    }
    response.status_code = 201;
    return trie::json::value{{"id", tx.last_insert_rowid()}, {"name", input.name}};
  }

  // List messages in a room, optionally only those newer than `after`.
  [[=trie::get("/api/rooms/{room}/messages")]] trie::json::value list_messages(
      [[=trie::inject]] trie::sqlite::transaction& tx, std::string_view room,
      [[=trie::query("after")]] std::optional<std::int64_t> after,
      [[=trie::query("limit")]] std::optional<int> limit, trie::http::response& response) {
    auto room_rows = tx.query("SELECT id FROM rooms WHERE name = ?1", room);
    if (!room_rows) {
      response.status_code = 500;
      return error_json(room_rows.error());
    }
    if (room_rows->empty()) {
      response.status_code = 404;
      return error_json("unknown room");
    }
    std::int64_t const room_id = parse_int64((*room_rows)[0][0].value_or("0"));
    std::int64_t const row_limit = clamp_limit(limit);
    std::int64_t const after_id = after.value_or(0);

    auto rows = tx.query(
        "SELECT m.id, m.author, m.text, m.created_at FROM messages m "
        "WHERE m.room_id = ?1 AND m.id > ?2 ORDER BY m.id LIMIT ?3",
        room_id, after_id, row_limit);
    if (!rows) {
      response.status_code = 500;
      return error_json(rows.error());
    }
    trie::json::value result = trie::json::value::array();
    for (auto const& row : *rows) result.push_back(message_json(row));
    return result;
  }

  // Post a message. The body is schema-validated and additionally checked by
  // the server-level body validation hook (length limits).
  [[=trie::post("/api/rooms/{room}/messages")]] trie::json::value post_message(
      [[=trie::inject]] trie::sqlite::transaction& tx, std::string_view room,
      [[=trie::body]] message_input input, trie::http::response& response) {
    auto room_rows = tx.query("SELECT id FROM rooms WHERE name = ?1", room);
    if (!room_rows) {
      response.status_code = 500;
      return error_json(room_rows.error());
    }
    if (room_rows->empty()) {
      response.status_code = 404;
      return error_json("unknown room");
    }
    std::int64_t const room_id = parse_int64((*room_rows)[0][0].value_or("0"));

    auto inserted = tx.exec("INSERT INTO messages(room_id, author, text) VALUES(?1, ?2, ?3)", room_id,
                            input.author, input.text);
    if (!inserted) {
      response.status_code = 500;
      return error_json(inserted.error());
    }
    auto rows = tx.query("SELECT id, author, text, created_at FROM messages WHERE id = ?1",
                         tx.last_insert_rowid());
    if (!rows || rows->empty()) {
      response.status_code = 500;
      return error_json("failed to read the inserted message");
    }
    response.status_code = 201;
    return message_json((*rows)[0]);
  }
};

} // namespace

int main(int argc, char** argv) {
  const std::uint16_t port = argc > 1 ? static_cast<std::uint16_t>(std::atoi(argv[1])) : 8082;
  const std::string database_path = argc > 2 ? argv[2] : ":memory:";

  trie::sqlite::database database;
  if (auto opened = database.open(database_path, trie::sqlite::open_options{
                                                      .busy_timeout_ms = 5000,
                                                      .enable_wal = database_path != ":memory:",
                                                      .foreign_keys = true,
                                                  });
      !opened) {
    std::printf("failed to open database: %s\n", opened.error().c_str());
    return 1;
  }

  auto schema = database.exec(
      "CREATE TABLE IF NOT EXISTS rooms("
      "  id INTEGER PRIMARY KEY,"
      "  name TEXT NOT NULL UNIQUE,"
      "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
      "CREATE TABLE IF NOT EXISTS messages("
      "  id INTEGER PRIMARY KEY,"
      "  room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,"
      "  author TEXT NOT NULL,"
      "  text TEXT NOT NULL,"
      "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
      "CREATE INDEX IF NOT EXISTS messages_room_id ON messages(room_id, id);"
      "INSERT OR IGNORE INTO rooms(name) VALUES ('general');");
  if (!schema) {
    std::printf("failed to create schema: %s\n", schema.error().c_str());
    return 1;
  }

  trie::server<chat_api> router;
  router.use(counting_middleware{});
  router.use(trie::sqlite::middleware{&database});

  // Additional validation on top of the reflected schema.
  router.on_body_validation([](const trie::http::request_view&, std::string_view type_name,
                               const trie::json::value& body,
                               trie::http::context&) -> std::expected<void, std::string> {
    if (type_name.find("message_input") != std::string_view::npos) {
      auto const& text = body.at("text").get_ref<std::string const&>();
      auto const& author = body.at("author").get_ref<std::string const&>();
      if (author.size() > 64) return std::unexpected("author must be at most 64 bytes");
      if (text.empty()) return std::unexpected("text must not be empty");
      if (text.size() > 500) return std::unexpected("text must be at most 500 bytes");
    }
    if (type_name.find("room_input") != std::string_view::npos) {
      auto const& name = body.at("name").get_ref<std::string const&>();
      if (name.empty() || name.size() > 64) return std::unexpected("room name must be 1..64 bytes");
    }
    return {};
  });

  // Validation failures become JSON errors that the browser UI can display.
  router.on_validation_error([](const trie::validation_failure& failure, trie::http::context&) {
    trie::http::response response{};
    response.status_code = 400;
    response.set_header("Content-Type", "application/json");
    response.body = trie::json::dump(
        trie::json::value{{"error", failure.message}, {"type", std::string{failure.type_name}}});
    return response;
  });

  trie::http::listener<trie::server<chat_api>> server{router, trie::http::endpoint{"127.0.0.1", port}};
  if (!server.valid()) {
    std::printf("failed to bind 127.0.0.1:%u\n", static_cast<unsigned>(port));
    return 1;
  }
  std::printf("chat server on http://127.0.0.1:%u (db=%s)\n", static_cast<unsigned>(server.port()),
              database_path.c_str());
  server.run();
  return 0;
}
