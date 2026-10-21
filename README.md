# libtrie

A C++26 reflection HTTP framework built on P2996 (reflection), P3394
(annotations) and P1306 (expansion statements):

- **Compile-time routing.** `[[=trie::get("/users/{id}")]]` annotations on
  handler methods become a trie at compile time. Matching is a chain of static
  nested calls, not a runtime table lookup.
- **HTTP/1.1 transport.** A blocking server built on C++20 coroutines + epoll
  (one coroutine per connection, single-threaded event loop).
- **JSON.** Vendored [nlohmann/json](https://github.com/nlohmann/json) plus a
  reflection layer that converts aggregate types to/from JSON.
- **Schema validation with hooks.** Typed request bodies are validated against a
  schema derived from the C++ type before the handler runs; strictness, extra
  validators and error responses are configurable per server.
- **Middleware.** Spring-like request-scoped context injection
  (`[[=trie::inject]] T&`), an ordered middleware chain, and an optional SQLite
  transaction middleware.
- **Type-safe client.** Method, path, parameters and return type come from the
  same reflection metadata; calls are checked at compile time. Ships with
  blocking `socket_transport`, pooled `pooled_socket_transport`, OpenSSL-based
  `tls_transport`, and a pluggable transport concept.

## Requirements

- **GCC 16 or newer** with `-freflection`.
- CMake ≥ 3.23 and Ninja (the `dev` preset uses Ninja).
- **Linux** for the HTTP transport (epoll). Routing, JSON, middleware and the
  client core are platform-independent.
- Optional: SQLite 3 development files for the SQLite middleware examples/tests.
- Optional: OpenSSL development files for `trie/http/tls_transport.hh` (the TLS
  client transport is an opt-in header, not part of the umbrella include).

Stock Clang does not implement P2996 yet; clangd cannot parse `^^`/`[[=...]]`
either, so expect editor false positives. The build is the source of truth.

The JSON dependency is a git submodule, so clone/track it first:

```sh
git submodule update --init --recursive
```

## Build and test

```sh
git submodule update --init --recursive
cmake --preset dev
cmake --build --preset dev
ctest --preset dev            # 17 tests with SQLite + OpenSSL available
```

Examples (small, focused, readable; run any of them without arguments):

```sh
./build/dev/examples/trie_01_hello                 # minimal annotated route + listener
./build/dev/examples/trie_02_params                # path/query/header/enum params, 404/405
./build/dev/examples/trie_03_json_schema           # typed JSON + schema validation hooks
./build/dev/examples/trie_04_middleware            # context injection, auth middleware, hooks
./build/dev/examples/trie_05_client                # type-safe client over a real socket
./build/dev/examples/trie_basic                    # routing + loopback client
./build/dev/examples/trie_http_server 8080         # routes, JSON, schema, middleware (serves HTTP)
./build/dev/examples/trie_sqlite_notes 8081        # SQLite notes API with transactions
./build/dev/examples/trie_chat 8082 [chat.db]      # browser chat room (see below)
```

### Chat example

`examples/chat/chat_server.cc` is a small browser chat room that exercises most
of the framework end to end: annotated routing, typed JSON bodies, schema +
custom validation hooks, request-scoped middleware context, SQLite transactions
and prepared-statement binding, plus a tiny HTML/JS UI served by a handler.

```sh
./build/dev/examples/trie_chat 8082 chat.db
# open http://127.0.0.1:8082/
```

REST API (also used by the UI):

```sh
curl http://127.0.0.1:8082/api/rooms
curl -X POST -H 'Content-Type: application/json' -d '{"name":"random"}' \
     http://127.0.0.1:8082/api/rooms
curl -X POST -H 'Content-Type: application/json' \
     -d '{"author":"alice","text":"hello"}' \
     http://127.0.0.1:8082/api/rooms/general/messages
curl 'http://127.0.0.1:8082/api/rooms/general/messages?after=0&limit=50'
```

Validation failures are returned as JSON (`{"error":"...","type":"..."}`) via
`on_validation_error`; message/room length limits are enforced with
`on_body_validation`; every request gets a SQLite transaction and a request
counter from middleware.

## Quick start

### Router + HTTP server

```cpp
#include "trie/trie.hh"

struct person {
  std::string name;          // no default -> required in JSON bodies
  int age = 0;               // defaulted -> optional
};

struct users_api {
  [[=trie::get("/users/{id}")]]
  int get_user(int id) { return id * 2; }

  // Typed JSON request/response. The body is schema-validated and the return
  // value is serialized with Content-Type: application/json.
  [[=trie::post("/person")]]
  person bump_age([[=trie::body]] person value) {
    value.age += 1;
    return value;
  }

  [[=trie::get("/search")]]
  std::string search([[=trie::query("q")]] std::string_view q,
                     [[=trie::query("limit")]] std::optional<int> limit);
};

int main() {
  trie::server<users_api> router;
  trie::http::serve(router, trie::http::endpoint{"127.0.0.1", 8080});   // blocking
}
```

For lifecycle control (testing, port 0, stopping from another thread) use the
listener directly:

```cpp
trie::http::listener<trie::server<users_api>> server{router, {"127.0.0.1", 0}};
std::thread thread{[&] { server.run(); }};
auto port = server.port();          // actual bound port
server.stop();                      // safe from another thread
thread.join();
```

Multiple controllers are composed as template arguments:
`trie::server<users_api, admin_api>`. Registering the same `(method, path)`
twice is a compile error.

### Middleware and request context

Middleware is any callable with the signature
`(http::context&, const http::request_view&, const http::next&) -> http::response`.
The first `use` call is the outermost middleware; a middleware decides whether
to call `next(context, request)`, may short-circuit, and may modify the response
afterwards.

```cpp
struct request_info {
  int number = 0;
};

struct counting_middleware {
  int count = 0;

  trie::http::response operator()(trie::http::context& context,
                                  const trie::http::request_view& request,
                                  const trie::http::next& next) {
    context.set<request_info>(request_info{++count});   // owned value
    return next(context, request);                      // or short-circuit here
  }
};

struct api {
  [[=trie::get("/request-number")]]
  int number([[=trie::inject]] request_info const& info) { return info.number; }
};

int main() {
  trie::server<api> router;
  router.use(counting_middleware{});
  trie::http::serve(router, {"127.0.0.1", 8080});
}
```

- `context.set<T>(value)` stores an owned request-scoped value;
  `context.set_ref<T>(ref)` stores a borrowed one.
- Handlers receive values with `[[=trie::inject]] T&` / `T const&`.
- A handler using an injected type with no middleware providing it returns
  `500 missing request context`.
- Authentication is a natural middleware: inspect `request.header("X-Token")`
  and return `401` without calling `next`.

### SQLite middleware

`include/trie/middleware/sqlite.hh` is an optional, header-only module (the only
libtrie header that includes `<sqlite3.h>`; link with `-lsqlite3`):

```cpp
#include "trie/middleware/sqlite.hh"

struct notes_api {
  [[=trie::post("/notes")]]
  trie::json::value add([[=trie::inject]] trie::sqlite::transaction& tx,
                        [[=trie::body]] note_input input) {
    auto result = tx.exec("INSERT INTO notes(text) VALUES(...)");
    // returning a response with status >= 500 makes the middleware roll back
    return trie::json::value{{"ok", result.has_value()}};
  }
};

int main() {
  trie::sqlite::database db;
  (void)db.open("notes.db");
  (void)db.exec("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, text TEXT)");

  trie::server<notes_api> router;
  router.use(trie::sqlite::middleware{&db});   // BEGIN IMMEDIATE ... COMMIT/ROLLBACK
  trie::http::serve(router, {"127.0.0.1", 8080});
}
```

`trie::sqlite::middleware` opens a transaction per request
(`BEGIN IMMEDIATE` by default), injects `trie::sqlite::transaction&`, commits on
responses below 500 and rolls back on 5xx (or when a handler never finishes the
transaction). The module provides:

- **Bound parameters** for `exec`/`query`, so user input never becomes SQL:
  `tx.exec("INSERT INTO notes(text) VALUES(?1)", text)`,
  `tx.query("SELECT id FROM notes WHERE author = ?1", author)`.
  Supported bind types: integers, enums, floating point, `bool`, `std::string`,
  `std::string_view`, `const char*`, `std::optional<T>` and `nullptr`.
- **`statement`**: RAII prepared statement with `bind`, `reset`, `step`,
  `current_row`, `column_count` for manual iteration; `database::prepare` and
  `transaction::prepare` return one.
- **`open_options`**: `busy_timeout_ms`, `enable_wal`, `foreign_keys`
  (`db.open(path, {.enable_wal = true})`).
- **Transaction modes**: `transaction_mode::deferred/immediate/exclusive`
  (`transaction{handle, transaction_mode::deferred}` and
  `middleware{&db, transaction_mode::deferred}`).
- `last_insert_rowid()` / `changes()` on `database`, `transaction` and
  `statement`, plus `std::expected` errors everywhere.

### JSON

```cpp
struct person {
  std::string name;
  int age = 0;
  std::optional<std::string> nickname;
  std::vector<std::string> tags;
};

trie::json::value document = trie::json::to_json(person{"a", 1, std::nullopt, {"x"}});
std::string text = trie::json::dump(document);

auto parsed = trie::json::parse_as<person>(text);   // expected<person, json::error>
auto value  = trie::json::parse(R"({"ok":true})");  // expected<json::value, json::error>
```

- `trie::json::value` is `nlohmann::json`; the nlohmann API is available.
- Conversion rules: fundamentals, strings, enums (by enumerator name),
  `std::optional`, `std::vector`, `std::array`, and aggregate classes whose
  public non-static data members are serializable.
- `parse_as<T>` rejects types that would borrow parsed storage
  (`string_view`/`const char*` members) to prevent dangling views.
- All JSON errors are returned as `std::expected`; nothing throws or aborts.

### Schema validation

`[[=trie::body]] T` bodies are validated before conversion:

- unknown fields are rejected by default (`reject_unknown = true`);
- a field is required when it has no default member initializer and is not
  `std::optional` (`require_all = true` makes every field required);
- type, integer range, enum names, vector elements, `std::array` length and
  nested object paths are checked;
- failures return `400` with a path-aware message and never call the handler:

```
home.zip: expected integer, got string
points[0].y: missing required field
unknown field 'extra'
favorite: unknown enumerator 'purple'
```

```cpp
auto valid = trie::json::validate<person>(*document);  // expected<void, error>
trie::json::value description = trie::json::schema<person>();
// {"type":"object","properties":{...},"required":["name"],"additionalProperties":false}
```

`validate<T>(value, {.reject_unknown, .require_all})` adjusts strictness;
`schema<T>()` emits draft-07-style object/properties/required/items/enum/
minItems/maxItems.

Servers expose three validation hooks:

```cpp
router.set_validation_options(trie::json::validate_options{
    .reject_unknown = false,      // accept unknown JSON fields
    .require_all = true,          // every member is required
});

// Extra validation after the built-in schema checks (may use middleware context).
router.on_body_validation([](const trie::http::request_view& request,
                             std::string_view type_name,
                             const trie::json::value& body,
                             trie::http::context& context)
                              -> std::expected<void, std::string> {
  if (body.contains("age") && body["age"].get<int>() > 150) return std::unexpected("age must be <= 150");
  return {};
});

// Customize the response for parse/schema/hook failures.
router.on_validation_error([](const trie::validation_failure& failure, trie::http::context& context) {
  trie::http::response response{};
  response.status_code = 422;
  response.set_header("Content-Type", "application/json");
  response.body = R"({"error":")" + failure.message + R"(","type":")" + std::string(failure.type_name) + R"("})";
  return response;
});
```

The body validator receives the reflected C++ type name and runs after schema
validation; the error handler also covers malformed JSON and plain parameter
conversion failures (e.g. `/users/not-a-number`).

### Type-safe client

The client derives method, path template, argument types and return type from
the handler reflection. Arguments must match the handler's non-context
parameters exactly; this is checked at compile time. Calls return
`std::expected<T, client_error>` (2xx is success, anything else carries the
status and body).

```cpp
struct loopback_transport {
  trie::server<users_api>* server;
  std::expected<trie::http::response, trie::client_error> send(trie::http::request request) {
    std::vector<trie::http::header_view> scratch;
    for (auto const& h : request.headers) scratch.push_back({h.first, h.second});
    return server->dispatch(
        trie::http::request_view::from_target(request.m, request.target, scratch, request.body));
  }
};

trie::client<users_api, loopback_transport> client{loopback_transport{&router}};
auto user   = client.call<^^users_api::get_user>(21);   // expected<int, client_error>
auto person = client.call<^^users_api::bump_age>(p);    // expected<person, client_error>
```

To talk to a real server, use the built-in blocking transport (one connection
per request, `Connection: close`):

```cpp
trie::client<users_api, trie::http::socket_transport> http_client{
    trie::http::socket_transport{trie::http::endpoint{"127.0.0.1", 8080}}};

auto user = http_client.call<^^users_api::get_user>(21);
```

`socket_transport_options{connect_timeout_ms, io_timeout_ms, max_response_bytes}`
configures timeouts and response size limits.

For keep-alive connection reuse use `pooled_socket_transport` (thread-safe,
retries once on a dead pooled connection):

```cpp
trie::client<users_api, trie::http::pooled_socket_transport> client{
    trie::http::pooled_socket_transport{
        trie::http::endpoint{"127.0.0.1", 8080},
        trie::http::pooled_socket_transport_options{.max_idle_connections = 8}}};
```

TLS is an opt-in OpenSSL transport (link `-lssl -lcrypto`, include the header
explicitly; it is not pulled in by `trie/trie.hh`):

```cpp
#include "trie/http/tls_transport.hh"

trie::client<users_api, trie::http::tls_transport> client{
    trie::http::tls_transport{
        trie::http::endpoint{"api.example.com", 443},
        trie::http::tls_transport_options{
            .verify_peer = true,          // default
            .ca_file = {},                // empty -> system trust store
            .server_name = "api.example.com"}}};
```

`tls_transport_options` also supports client certificates (`client_cert_file` /
`client_key_file`) for mTLS and disables verification with `verify_peer = false`
(tests only). The transport concept is:

```cpp
template <class T>
concept transport = requires(T& t, trie::http::request request) {
  { t.send(std::move(request)) } -> std::same_as<std::expected<trie::http::response, trie::client_error>>;
};
```

## Parameter injection

| Parameter | Source |
| --- | --- |
| `trie::http::request_view const&` | current request |
| `trie::http::response&` | response to fill |
| `int id` / `std::string_view name` | path parameter, positional (`{placeholder}`) |
| `[[=trie::query("q")]] std::string_view q` | query parameter (percent-decoded) |
| `[[=trie::query("limit")]] std::optional<int> limit` | optional query parameter |
| `[[=trie::header("X-Token")]] std::string_view token` | request header (case-insensitive, decoded) |
| `[[=trie::body]] std::string_view body` | raw request body |
| `[[=trie::body]] person body` | JSON body (parsed, schema-validated) |
| `[[=trie::inject]] app_state& state` | request-scoped context value from middleware |

Path/query/header value types: integers, floats, `bool`, `std::string`,
`std::string_view`, enums and `std::optional<T>`. Enums parse from enumerator
identifiers (e.g. `/colors/green`) with a numeric fallback; the client serializes
the same way. `trie::enum_name(value)` / `trie::enum_from_name<E>(name)` are
public helpers. Path placeholder count must match the handler's path parameter
count, otherwise compilation fails.

## Handler return values

| Return type | Behaviour |
| --- | --- |
| `void` | handler fills `response` itself |
| `std::string` / `std::string_view` / `const char*` | text response body |
| integers / floats / `bool` | text response body |
| `trie::http::status` | sets the status code |
| `trie::json::value` | JSON response body |
| serializable aggregate/container/enum | reflection-serialized JSON response body |

## HTTP transport

- HTTP/1.1: keep-alive, pipelining (sequential), HEAD (headers only),
  `Content-Length`.
- Request limits: 16 KiB headers, 1 MiB body, 8 KiB target; at most 32 path
  segments; 24 bytes per segment.
- Status handling: 404, 405 (with `Allow`), 400, 401, 413, 414, 431, 500, 501,
  505.
- Single-threaded epoll loop, one coroutine per connection;
  `listener::stop()` may be called from another thread.
- The client transports are `socket_transport` (one connection per request),
  `pooled_socket_transport` (keep-alive pool) and `tls_transport` (OpenSSL,
  one connection per request).
- No server-side TLS yet, no HTTP/2, no chunked request bodies, no server
  timeouts or connection limits.
- `serve(router, endpoint)` is the blocking helper; `listener` exposes
  `valid()/error_code()/port()/run()/stop()`.

## Design

```
edit time            compile time                                 runtime
annotations  ──►  members_of / annotations_of  ──►  trie node array (NTTP)
                                                     │
                                                     ├─ one template instance per node
                                                     └─ template for expands children
                                                        → static nested calls
                                                              │
                                                     handler params from
                                                     parameters_of + type_of

socket ──► epoll ──► connection coroutine ──► parser ──► request_view
                                                            │
                                                   middleware chain
                                                            │
                                                 server<...>::dispatch
                                                            │
                                        response ──► serializer ──► socket
```

- Route annotations must be structural types. Paths/names live in
  `std::array<char, N>`; pointers to string literals cannot be reflected.
- The reflected annotation type is `const route`, so comparisons use
  `remove_const`.
- Reflection vectors cannot be stored in `constexpr` variables; the code uses
  `define_static_array` or `consteval` lookup functions instead.
- Everything works with `-fno-exceptions -fno-rtti`; reflection errors are hard
  compile errors.
- Handlers must be public (`access_context::unprivileged()`) and carry at least
  one route annotation.
- Unused methods and path subtrees are pruned at compile time.

## Layout

```
include/trie/
  annotations.hh        route / method / query / header / body / inject annotations
  http.hh               request_view / request / response / status / method helpers
  json.hh               trie::json: nlohmann adapter, reflection conversion, schema
  error.hh              client_error
  validation.hh         validation hooks (options/body validator/error handler)
  server.hh             server<Controllers...>: middleware chain, 404/405, dispatch
  client.hh             client<Api, Transport>: type-safe client
  trie.hh               umbrella header
  detail/reflect.hh     reflection metadata, parameter classification, static checks
  detail/trie.hh        compile-time trie, static dispatch, argument conversion
  detail/enum.hh        enumerator name tables, enum_name / enum_from_name
  detail/url.hh         percent encoding/decoding
  http/parser.hh        incremental HTTP/1.1 request parser
  http/serializer.hh    response serializer
  http/context.hh       request-scoped context + middleware next function
  http/event_loop.hh    epoll event loop + task / io awaiter
  http/listener.hh      listener / connection coroutine / serve()
  http/socket_transport.hh  blocking HTTP/1.1 client transport
  http/pooled_socket_transport.hh  keep-alive pooled client transport
  http/tls_transport.hh     optional OpenSSL TLS client transport
  middleware/sqlite.hh  optional SQLite: database/statement/transaction/middleware
vendor/nlohmann-json/   nlohmann/json git submodule, pinned to v3.12.0
tests/                  16 framework-free tests (incl. real-socket and TLS tests)
examples/               01_hello, 02_params, 03_json_schema, 04_middleware,
                        05_client, basic, http_server, sqlite_notes,
                        chat/chat_server (SQLite-backed browser chat room)
```

## Third-party

[`nlohmann/json`](https://github.com/nlohmann/json) is a git submodule at
`vendor/nlohmann-json`, pinned to tag `v3.12.0` (MIT). The repository ships the
multi-header distribution; CMake adds `vendor/nlohmann-json/include` to the
include path. `trie/json.hh` defines `JSON_NOEXCEPTION` before including it.

## Current limitations

- No server-side TLS (HTTPS listener) yet; `tls_transport` is client-side only.
- The TLS transport does not pool connections (it opens one per request);
  pooling is available for plain HTTP via `pooled_socket_transport`.
- Single-threaded event loop; no TLS, HTTP/2, chunked requests, timeouts or
  connection limits.
- Schema validation is a built-in validator, not a full JSON Schema engine;
  no multipart or streaming bodies.
- SQLite middleware supports bound parameters but not typed row/column decoding
  (rows are optional strings) or migrations.
- Path/query/header parameters do not support arbitrary user-defined types
  (enums are supported; JSON bodies support much richer types).
- Route templates are limited to 95 characters, 32 path segments and 12 handler
  parameters.
- Compile time grows with the number of routes (unused methods/subtrees are
  pruned). Measured on GCC 16.2 at `-O0`, including nlohmann header parsing:
  ~5 s for 24 GET routes, ~5 s for 28 routes covering all 7 methods.
