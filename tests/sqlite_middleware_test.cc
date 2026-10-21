#include "trie/trie.hh"
#include "trie/middleware/sqlite.hh"

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "harness.hh"

// The public API is intentionally small; lock it down at compile time.
static_assert(std::is_same_v<trie::sqlite::row, std::vector<std::optional<std::string>>>);
static_assert(std::is_same_v<trie::sqlite::rows, std::vector<trie::sqlite::row>>);
static_assert(!std::is_copy_constructible_v<trie::sqlite::database>);
static_assert(!std::is_copy_assignable_v<trie::sqlite::database>);
static_assert(!std::is_move_constructible_v<trie::sqlite::database>);
static_assert(!std::is_copy_constructible_v<trie::sqlite::transaction>);
static_assert(!std::is_copy_assignable_v<trie::sqlite::transaction>);
static_assert(std::is_move_constructible_v<trie::sqlite::transaction>);
static_assert(std::is_move_assignable_v<trie::sqlite::transaction>);

static_assert(std::is_same_v<decltype(std::declval<trie::sqlite::database&>().open(std::string_view{})),
                             std::expected<void, std::string>>);
static_assert(std::is_same_v<decltype(std::declval<trie::sqlite::database&>().exec(std::string_view{})),
                             std::expected<void, std::string>>);
static_assert(std::is_same_v<decltype(std::declval<trie::sqlite::database&>().query(std::string_view{})),
                             std::expected<trie::sqlite::rows, std::string>>);
static_assert(std::is_same_v<decltype(std::declval<trie::sqlite::transaction&>().commit()),
                             std::expected<void, std::string>>);
static_assert(std::is_same_v<decltype(std::declval<trie::sqlite::transaction&>().rollback()),
                             std::expected<void, std::string>>);

namespace {

// Runs a single-value query, or returns an empty string on failure.
std::string scalar(trie::sqlite::database& db, std::string_view sql) {
  auto result = db.query(sql);
  if (!result || result->empty() || (*result)[0].empty()) return {};
  return (*result)[0][0].value_or("");
}

std::string row_count(trie::sqlite::database& db) { return scalar(db, "SELECT COUNT(*) FROM notes"); }

void create_notes(trie::sqlite::database& db) {
  auto created = db.exec("CREATE TABLE notes(id INTEGER PRIMARY KEY, text TEXT)");
  CHECK(created.has_value());
}

struct notes_api {
  int created = 0;
  int failed = 0;
  int rejected = 0;
  int early_commits = 0;
  int early_rollbacks = 0;

  // 200 + JSON: the middleware commits the transaction.
  [[=trie::post("/notes")]] trie::json::value create([[=trie::inject]] trie::sqlite::transaction& tx) {
    ++created;
    auto inserted = tx.exec("INSERT INTO notes(id, text) VALUES (1, 'committed')");
    trie::json::value body = trie::json::value::object();
    if (!inserted) {
      body["error"] = inserted.error();
      return body;
    }
    body["id"] = 1;
    body["ok"] = true;
    return body;
  }

  // 500 after inserting: the middleware rolls the transaction back.
  [[=trie::post("/notes/fail")]] trie::http::status fail([[=trie::inject]] trie::sqlite::transaction& tx) {
    ++failed;
    (void)tx.exec("INSERT INTO notes(id, text) VALUES (2, 'rolled back')");
    return trie::http::status::internal_server_error;
  }

  // 4xx after inserting: only 5xx rolls back, so this one is committed.
  [[=trie::post("/notes/rejected")]] trie::http::status rejected_handler(
      [[=trie::inject]] trie::sqlite::transaction& tx) {
    ++rejected;
    (void)tx.exec("INSERT INTO notes(id, text) VALUES (3, 'committed on 400')");
    return trie::http::status::bad_request;
  }

  // The handler finishes the transaction itself; the middleware must not touch it again.
  [[=trie::post("/notes/commit-early")]] trie::http::status commit_early(
      [[=trie::inject]] trie::sqlite::transaction& tx) {
    ++early_commits;
    if (!tx.exec("INSERT INTO notes(id, text) VALUES (4, 'early commit')").has_value())
      return trie::http::status::internal_server_error;
    if (!tx.commit().has_value()) return trie::http::status::internal_server_error;
    return trie::http::status::created;
  }

  [[=trie::post("/notes/rollback-early")]] trie::http::status rollback_early(
      [[=trie::inject]] trie::sqlite::transaction& tx) {
    ++early_rollbacks;
    (void)tx.exec("INSERT INTO notes(id, text) VALUES (5, 'early rollback')");
    if (!tx.rollback().has_value()) return trie::http::status::internal_server_error;
    return trie::http::status::ok;
  }
};

void test_database() {
  trie::sqlite::database db;
  CHECK(!db.valid());
  CHECK(db.handle() == nullptr);
  CHECK(db.error().empty());
  CHECK(!db.exec("SELECT 1").has_value());
  CHECK(!db.query("SELECT 1").has_value());

  auto opened = db.open(":memory:");
  CHECK(opened.has_value());
  CHECK(db.valid());
  CHECK(db.handle() != nullptr);
  CHECK(db.error().empty());
  create_notes(db);

  auto empty = db.query("SELECT id, text FROM notes");
  CHECK(empty.has_value());
  CHECK_EQ(empty->size(), std::size_t{0});

  // Empty or comment-only SQL prepares no statement; query reports zero rows.
  auto none = db.query("-- nothing here");
  CHECK(none.has_value());
  CHECK_EQ(none->size(), std::size_t{0});

  CHECK(db.exec("INSERT INTO notes(text) VALUES ('hello')").has_value());
  CHECK(db.exec("INSERT INTO notes(text) VALUES (NULL)").has_value());

  auto result = db.query("SELECT id, text FROM notes ORDER BY id");
  CHECK(result.has_value());
  CHECK_EQ(result->size(), std::size_t{2});
  CHECK_EQ((*result)[0].size(), std::size_t{2});
  CHECK((*result)[0][0].has_value());
  CHECK_EQ(*(*result)[0][0], std::string{"1"});
  CHECK_EQ(*(*result)[0][1], std::string{"hello"});
  CHECK(!(*result)[1][1].has_value()); // NULL -> std::nullopt

  // Failed operations report the sqlite message through both the result and error().
  auto missing = db.query("SELECT * FROM missing_table");
  CHECK(!missing.has_value());
  CHECK(!missing.error().empty());
  CHECK_EQ(db.error(), missing.error());

  auto bad_exec = db.exec("INSERT INTO missing_table VALUES (1)");
  CHECK(!bad_exec.has_value());
  CHECK_EQ(db.error(), bad_exec.error());

  // Reopening closes the old connection: a fresh :memory: database has no table.
  auto reopened = db.open(":memory:");
  CHECK(reopened.has_value());
  CHECK(!db.query("SELECT * FROM notes").has_value());

  db.close();
  CHECK(!db.valid());
  CHECK(db.handle() == nullptr);
  db.close(); // idempotent
  CHECK(!db.exec("SELECT 1").has_value());

  // Opening a path whose parent directory does not exist fails cleanly.
  auto failed_open = db.open("/nonexistent-libtrie-directory/test.db");
  CHECK(!failed_open.has_value());
  CHECK(!failed_open.error().empty());
  CHECK(!db.valid());
  CHECK_EQ(db.error(), failed_open.error());
}

void test_transaction() {
  trie::sqlite::database db;
  CHECK(db.open(":memory:").has_value());
  create_notes(db);

  // Destructor rolls back an unfinished transaction.
  {
    trie::sqlite::transaction tx{db.handle()};
    CHECK(tx.valid());
    CHECK(tx.error().empty());
    CHECK(tx.exec("INSERT INTO notes(text) VALUES ('unfinished')").has_value());
    auto inside = tx.query("SELECT COUNT(*) FROM notes");
    CHECK(inside.has_value());
    CHECK_EQ(*(*inside)[0][0], std::string{"1"});
  }
  CHECK_EQ(row_count(db), std::string{"0"});

  // Explicit commit.
  {
    trie::sqlite::transaction tx{db.handle()};
    CHECK(tx.valid());
    CHECK(tx.exec("INSERT INTO notes(text) VALUES ('committed')").has_value());
    CHECK(tx.commit().has_value());
    CHECK(!tx.valid());
  }
  CHECK_EQ(row_count(db), std::string{"1"});

  // Finishing twice is an error, not a silent double commit/rollback.
  {
    trie::sqlite::transaction tx{db.handle()};
    CHECK(tx.commit().has_value());
    CHECK(!tx.commit().has_value());
    CHECK(!tx.rollback().has_value());
  }
  CHECK_EQ(row_count(db), std::string{"1"});

  // Explicit rollback is idempotent.
  {
    trie::sqlite::transaction tx{db.handle()};
    CHECK(tx.exec("INSERT INTO notes(text) VALUES ('rolled back')").has_value());
    CHECK(tx.rollback().has_value());
    CHECK(tx.rollback().has_value());
    CHECK(!tx.valid());
  }
  CHECK_EQ(row_count(db), std::string{"1"});

  // Move construction transfers the rollback responsibility.
  {
    trie::sqlite::transaction first{db.handle()};
    CHECK(first.valid());
    CHECK(first.exec("INSERT INTO notes(text) VALUES ('moved')").has_value());
    trie::sqlite::transaction second{std::move(first)};
    CHECK(!first.valid());
    CHECK(second.valid());
    CHECK(second.commit().has_value());
  }
  CHECK_EQ(row_count(db), std::string{"2"});

  // Move assignment adopts the source transaction and rolls back the target's.
  trie::sqlite::database other;
  CHECK(other.open(":memory:").has_value());
  create_notes(other);
  {
    trie::sqlite::transaction source{db.handle()};
    CHECK(source.exec("INSERT INTO notes(text) VALUES ('adopted')").has_value());
    trie::sqlite::transaction target{other.handle()};
    CHECK(target.exec("INSERT INTO notes(text) VALUES ('discarded')").has_value());
    target = std::move(source);
    CHECK(!source.valid());
    CHECK(target.valid());
    CHECK(target.commit().has_value());
  }
  CHECK_EQ(row_count(db), std::string{"3"});
  CHECK_EQ(row_count(other), std::string{"0"}); // target's old transaction was rolled back

  // Invalid handle: no transaction, and errors are reported instead of throwing.
  {
    trie::sqlite::transaction none{nullptr};
    CHECK(!none.valid());
    CHECK(!none.error().empty());
    CHECK(!none.commit().has_value());
    CHECK(!none.rollback().has_value());
    CHECK(!none.exec("SELECT 1").has_value());
    CHECK(!none.query("SELECT 1").has_value());
  }

  // A second BEGIN IMMEDIATE on the same connection fails and reports why.
  {
    trie::sqlite::transaction outer{db.handle()};
    CHECK(outer.valid());
    trie::sqlite::transaction inner{db.handle()};
    CHECK(!inner.valid());
    CHECK(!inner.error().empty());
    CHECK(!inner.commit().has_value());
  }
  CHECK_EQ(row_count(db), std::string{"3"});
}

void test_middleware_success_and_failure() {
  trie::sqlite::database db;
  CHECK(db.open(":memory:").has_value());
  create_notes(db);

  trie::server<notes_api> server;
  server.use(trie::sqlite::middleware{&db});
  auto& api = server.controller<notes_api>();

  // 200 + JSON: committed.
  auto response = server.dispatch(trie::method::post, "/notes");
  CHECK_EQ(response.status_code, 200);
  CHECK_EQ(response.header("content-type"), std::string_view{"application/json"});
  auto parsed = trie::json::parse(response.body);
  CHECK(parsed.has_value());
  if (parsed) {
    // Note: value(1), not value{1}: braced init would build a JSON array.
    CHECK_EQ((*parsed)["id"], trie::json::value(1));
    CHECK_EQ((*parsed)["ok"], trie::json::value(true));
  }
  CHECK_EQ(api.created, 1);
  CHECK_EQ(row_count(db), std::string{"1"});

  // 500 after the insert: rolled back.
  response = server.dispatch(trie::method::post, "/notes/fail");
  CHECK_EQ(response.status_code, 500);
  CHECK_EQ(api.failed, 1);
  CHECK_EQ(row_count(db), std::string{"1"});

  // 4xx after the insert: committed (only 5xx rolls back).
  response = server.dispatch(trie::method::post, "/notes/rejected");
  CHECK_EQ(response.status_code, 400);
  CHECK_EQ(api.rejected, 1);
  CHECK_EQ(row_count(db), std::string{"2"});

  // The handler committed itself: the middleware must not commit twice.
  response = server.dispatch(trie::method::post, "/notes/commit-early");
  CHECK_EQ(response.status_code, 201);
  CHECK_EQ(api.early_commits, 1);
  CHECK_EQ(row_count(db), std::string{"3"});

  // The handler rolled back itself and still returned 200.
  response = server.dispatch(trie::method::post, "/notes/rollback-early");
  CHECK_EQ(response.status_code, 200);
  CHECK_EQ(api.early_rollbacks, 1);
  CHECK_EQ(row_count(db), std::string{"3"});

  // Only the committed rows survive: 1, 3 and 4 (2 and 5 were rolled back).
  auto ids = db.query("SELECT id FROM notes ORDER BY id");
  CHECK(ids.has_value());
  if (ids) {
    CHECK_EQ(ids->size(), std::size_t{3});
    CHECK_EQ(*(*ids)[0][0], std::string{"1"});
    CHECK_EQ(*(*ids)[1][0], std::string{"3"});
    CHECK_EQ(*(*ids)[2][0], std::string{"4"});
  }
}

void test_middleware_errors() {
  trie::sqlite::database db;
  CHECK(db.open(":memory:").has_value());
  create_notes(db);

  // No middleware: the injected transaction is missing.
  {
    trie::server<notes_api> server;
    auto response = server.dispatch(trie::method::post, "/notes");
    CHECK_EQ(response.status_code, 500);
    CHECK_EQ(response.body, std::string{"missing request context"});
    CHECK_EQ(server.controller<notes_api>().created, 0);
  }

  // Middleware without a database.
  {
    trie::server<notes_api> server;
    server.use(trie::sqlite::middleware{});
    auto response = server.dispatch(trie::method::post, "/notes");
    CHECK_EQ(response.status_code, 500);
    CHECK_EQ(response.body, std::string{"sqlite: no database configured"});
    CHECK_EQ(server.controller<notes_api>().created, 0);
  }

  // Middleware with a database object that was never opened.
  {
    trie::sqlite::database closed;
    trie::server<notes_api> server;
    server.use(trie::sqlite::middleware{&closed});
    auto response = server.dispatch(trie::method::post, "/notes");
    CHECK_EQ(response.status_code, 500);
    CHECK_EQ(response.body, std::string{"sqlite: database is not open"});
    CHECK_EQ(server.controller<notes_api>().created, 0);
  }

  // BEGIN failure (connection already inside a transaction) surfaces as a 500.
  {
    trie::server<notes_api> server;
    server.use(trie::sqlite::middleware{&db});
    CHECK(db.exec("BEGIN IMMEDIATE").has_value());
    auto response = server.dispatch(trie::method::post, "/notes");
    CHECK_EQ(response.status_code, 500);
    CHECK(response.body.starts_with("sqlite: "));
    CHECK_EQ(server.controller<notes_api>().created, 0);
    CHECK(db.exec("ROLLBACK").has_value());
  }

  CHECK_EQ(row_count(db), std::string{"0"});
}

} // namespace

int main() {
  test_database();
  test_transaction();
  test_middleware_success_and_failure();
  test_middleware_errors();
  return tst::report("sqlite_middleware_test");
}
