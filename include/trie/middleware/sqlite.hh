#pragma once

// Optional SQLite integration for libtrie.
//
// This is the only libtrie header that depends on SQLite, so applications that
// do not use it never need <sqlite3.h> or `-lsqlite3`. It is header-only:
// include it with `-Iinclude` and link with `-lsqlite3`.
//
//   trie::sqlite::database db;
//   auto opened = db.open(":memory:");
//
//   struct api {
//     [[=trie::post("/notes")]] trie::json::value create(
//         [[=trie::inject]] trie::sqlite::transaction& tx);
//   };
//
//   trie::server<api> server;
//   server.use(trie::sqlite::middleware{&db});
//
// The middleware begins one "BEGIN IMMEDIATE" transaction per request, stores
// it in the request context under trie::sqlite::transaction, and after the
// handler finishes commits when the response status is below 500, rolling back
// otherwise. The transaction destructor rolls back any transaction the
// middleware never finished, so an early return or a handler that forgets to
// commit can never leak an open transaction.
//
// Errors never throw: every fallible operation returns
// std::expected<T, std::string>, and the last error is also kept in error().

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sqlite3.h>

#include "trie/http.hh"
#include "trie/http/context.hh"

namespace trie::sqlite {

// One result row: one optional string per column (NULL -> std::nullopt).
using row = std::vector<std::optional<std::string>>;

// All rows returned by a query.
using rows = std::vector<row>;

namespace detail {

inline std::string last_error(sqlite3* handle) {
  char const* message = handle != nullptr ? sqlite3_errmsg(handle) : nullptr;
  if (message == nullptr) return std::string{"unknown sqlite error"};
  return std::string{message};
}

// Runs one (or more) statements without returning rows.
inline std::expected<void, std::string> run_exec(sqlite3* handle, std::string_view sql) {
  if (handle == nullptr) return std::unexpected(std::string{"database is not open"});
  std::string statement{sql};
  char* message = nullptr;
  int const result = sqlite3_exec(handle, statement.c_str(), nullptr, nullptr, &message);
  if (result != SQLITE_OK) {
    std::string error = message != nullptr ? std::string{message} : last_error(handle);
    if (message != nullptr) sqlite3_free(message);
    return std::unexpected(std::move(error));
  }
  if (message != nullptr) sqlite3_free(message);
  return {};
}

// Prepares and steps one statement, materializing every returned row.
inline std::expected<rows, std::string> run_query(sqlite3* handle, std::string_view sql) {
  if (handle == nullptr) return std::unexpected(std::string{"database is not open"});
  std::string statement{sql};
  sqlite3_stmt* prepared = nullptr;
  if (sqlite3_prepare_v2(handle, statement.c_str(), -1, &prepared, nullptr) != SQLITE_OK)
    return std::unexpected(last_error(handle));
  // Empty or comment-only SQL prepares successfully with no statement.
  if (prepared == nullptr) return rows{};

  rows result{};
  while (true) {
    int const step = sqlite3_step(prepared);
    if (step == SQLITE_DONE) break;
    if (step != SQLITE_ROW) {
      std::string error = last_error(handle);
      sqlite3_finalize(prepared);
      return std::unexpected(std::move(error));
    }
    int const column_count = sqlite3_column_count(prepared);
    row values{};
    values.reserve(static_cast<std::size_t>(column_count));
    for (int column = 0; column < column_count; ++column) {
      if (sqlite3_column_type(prepared, column) == SQLITE_NULL) {
        values.emplace_back(std::nullopt);
        continue;
      }
      auto const* text = sqlite3_column_text(prepared, column);
      int const bytes = sqlite3_column_bytes(prepared, column);
      if (text == nullptr)
        values.emplace_back(std::nullopt);
      else
        values.emplace_back(std::string{reinterpret_cast<char const*>(text), static_cast<std::size_t>(bytes)});
    }
    result.push_back(std::move(values));
  }
  sqlite3_finalize(prepared);
  return result;
}

} // namespace detail

// Owns one sqlite3 connection. Non-copyable so exactly one owner closes it;
// the destructor closes the connection if it is still open.
class database {
public:
  database() = default;
  database(database const&) = delete;
  database& operator=(database const&) = delete;
  database(database&&) = delete;
  database& operator=(database&&) = delete;

  ~database() { close(); }

  // Opens `path` (":memory:" for an in-memory database), closing any previously
  // open connection first. Failure leaves the database closed.
  std::expected<void, std::string> open(std::string_view path) {
    close();
    std::string filename{path};
    sqlite3* opened = nullptr;
    int const result =
        sqlite3_open_v2(filename.c_str(), &opened, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (result != SQLITE_OK) {
      error_ = detail::last_error(opened);
      if (opened != nullptr) sqlite3_close_v2(opened);
      return std::unexpected(error_);
    }
    handle_ = opened;
    error_.clear();
    return {};
  }

  // Closes the connection. Safe to call repeatedly or on a closed database.
  void close() {
    if (handle_ == nullptr) return;
    // close_v2 always deallocates the handle, deferring it until outstanding
    // statements are finalized, so a busy connection cannot deadlock the owner.
    (void)sqlite3_close_v2(handle_);
    handle_ = nullptr;
  }

  bool valid() const noexcept { return handle_ != nullptr; }

  sqlite3* handle() const noexcept { return handle_; }

  // Message from the most recent failed operation on this object.
  std::string const& error() const noexcept { return error_; }

  std::expected<void, std::string> exec(std::string_view sql) {
    auto result = detail::run_exec(handle_, sql);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

  std::expected<rows, std::string> query(std::string_view sql) {
    auto result = detail::run_query(handle_, sql);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

private:
  sqlite3* handle_ = nullptr;
  std::string error_{};
};

// A transaction on a connection owned by someone else (normally `database`).
//
// BEGIN IMMEDIATE is executed by the constructor. The destructor rolls back a
// transaction that is still active, so RAII alone is enough for correctness.
// Move-only: moving transfers the rollback responsibility. The underlying
// connection must outlive the transaction.
class transaction {
public:
  explicit transaction(sqlite3* handle) : handle_{handle} {
    if (handle == nullptr) {
      error_ = "database is not open";
      return;
    }
    auto begun = detail::run_exec(handle_, "BEGIN IMMEDIATE");
    if (!begun) {
      error_ = std::move(begun.error());
      return;
    }
    state_ = state::active;
  }

  transaction(transaction const&) = delete;
  transaction& operator=(transaction const&) = delete;

  transaction(transaction&& other) noexcept
      : handle_{std::exchange(other.handle_, nullptr)},
        state_{std::exchange(other.state_, state::idle)},
        error_{std::move(other.error_)} {}

  transaction& operator=(transaction&& other) noexcept {
    if (this == &other) return *this;
    abandon();
    handle_ = std::exchange(other.handle_, nullptr);
    state_ = std::exchange(other.state_, state::idle);
    error_ = std::move(other.error_);
    return *this;
  }

  ~transaction() { abandon(); }

  // True while the transaction is open (BEGIN succeeded and no commit or
  // rollback has finished it yet).
  bool valid() const noexcept { return state_ == state::active; }

  // Message from the most recent failed operation on this transaction.
  std::string const& error() const noexcept { return error_; }

  std::expected<void, std::string> commit() {
    if (state_ != state::active) return not_active();
    auto finished = detail::run_exec(handle_, "COMMIT");
    if (!finished) {
      error_ = finished.error();
      return finished;
    }
    state_ = state::committed;
    error_.clear();
    return {};
  }

  std::expected<void, std::string> rollback() {
    if (state_ == state::rolled_back) return {};
    if (state_ != state::active) return not_active();
    auto finished = detail::run_exec(handle_, "ROLLBACK");
    if (!finished) {
      error_ = finished.error();
      return finished;
    }
    state_ = state::rolled_back;
    error_.clear();
    return {};
  }

  std::expected<void, std::string> exec(std::string_view sql) {
    auto result = detail::run_exec(handle_, sql);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

  std::expected<rows, std::string> query(std::string_view sql) {
    auto result = detail::run_query(handle_, sql);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

private:
  enum class state : unsigned char { idle, active, committed, rolled_back };

  std::expected<void, std::string> not_active() const {
    if (!error_.empty()) return std::unexpected(error_);
    if (state_ == state::committed) return std::unexpected(std::string{"transaction already committed"});
    if (state_ == state::rolled_back) return std::unexpected(std::string{"transaction already rolled back"});
    return std::unexpected(std::string{"transaction is not active"});
  }

  void abandon() noexcept {
    if (state_ == state::active && handle_ != nullptr) {
      (void)sqlite3_exec(handle_, "ROLLBACK", nullptr, nullptr, nullptr);
      state_ = state::rolled_back;
    }
  }

  sqlite3* handle_ = nullptr;
  state state_ = state::idle;
  std::string error_{};
};

// Middleware that gives every request its own transaction, injected with
// `[[=trie::inject]] trie::sqlite::transaction&`. The response decides the
// outcome: status >= 500 rolls back, anything else commits.
struct middleware {
  // Must outlive the server (or at least every dispatch using this middleware).
  database* db = nullptr;

  http::response operator()(http::context& context, http::request_view const& request,
                            http::next const& next) const {
    if (db == nullptr) return failure("sqlite: no database configured");
    if (!db->valid()) return failure("sqlite: database is not open");

    transaction tx{db->handle()};
    if (!tx.valid()) return failure("sqlite: " + tx.error());

    context.set<transaction>(std::move(tx));
    http::response response = next(context, request);

    auto* current = context.get<transaction>();
    if (current != nullptr && current->valid()) {
      auto finished = response.status_code >= static_cast<int>(http::status::internal_server_error)
                          ? current->rollback()
                          : current->commit();
      if (!finished) return failure("sqlite: " + finished.error());
    }
    return response;
  }

private:
  static http::response failure(std::string message) {
    http::response response{};
    response.status_code = static_cast<int>(http::status::internal_server_error);
    response.body = std::move(message);
    return response;
  }
};

} // namespace trie::sqlite
