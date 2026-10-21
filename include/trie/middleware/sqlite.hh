#pragma once

// Optional SQLite integration for libtrie.
//
// This is the only libtrie header that depends on SQLite, so applications that
// do not use it never need <sqlite3.h> or `-lsqlite3`. It is header-only:
// include it with `-Iinclude` and link with `-lsqlite3`.
//
//   trie::sqlite::database db;
//   auto opened = db.open("app.db");
//
//   struct api {
//     [[=trie::post("/notes")]] trie::json::value create(
//         [[=trie::inject]] trie::sqlite::transaction& tx);
//   };
//
//   trie::server<api> server;
//   server.use(trie::sqlite::middleware{&db});
//
// The middleware begins one transaction per request (BEGIN IMMEDIATE by
// default), stores it in the request context under trie::sqlite::transaction,
// and after the handler finishes commits when the response status is below 500,
// rolling back otherwise. The transaction destructor rolls back any transaction
// the middleware never finished, so an early return or a handler that forgets to
// commit can never leak an open transaction.
//
// Statements take bound parameters, so SQL never has to be built by string
// concatenation:
//
//   (void)tx.exec("INSERT INTO notes(text) VALUES(?1)", input.text);
//   auto rows = tx.query("SELECT id FROM notes WHERE text = ?1", input.text);
//
// Errors never throw: every fallible operation returns
// std::expected<T, std::string>, and the last error is also kept in error().

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
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

// Options applied when a database is opened.
struct open_options {
  int busy_timeout_ms = 5000;
  bool enable_wal = false;
  bool foreign_keys = true;
};

// Isolation level used when a transaction starts.
enum class transaction_mode : unsigned char { deferred, immediate, exclusive };

namespace detail {

template <class>
inline constexpr bool always_false_v = false;

inline std::string last_error(sqlite3* handle) {
  char const* message = handle != nullptr ? sqlite3_errmsg(handle) : nullptr;
  if (message == nullptr) return std::string{"unknown sqlite error"};
  return std::string{message};
}

// Runs one (or more) statements without returning rows or binding arguments.
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

// Runs one statement without binding arguments and materializes every row.
inline std::expected<rows, std::string> run_query(sqlite3* handle, std::string_view sql);

inline int bind_text(sqlite3_stmt* statement, int index, std::string_view text) {
  char const* data = text.data() != nullptr ? text.data() : "";
  return sqlite3_bind_text(statement, index, data, static_cast<int>(text.size()), SQLITE_TRANSIENT);
}

inline int bind_value(sqlite3_stmt* statement, int index, std::nullptr_t) {
  return sqlite3_bind_null(statement, index);
}

inline int bind_value(sqlite3_stmt* statement, int index, std::nullopt_t) {
  return sqlite3_bind_null(statement, index);
}

inline int bind_value(sqlite3_stmt* statement, int index, const char* value) {
  if (value == nullptr) return sqlite3_bind_null(statement, index);
  return bind_text(statement, index, std::string_view{value});
}

inline int bind_value(sqlite3_stmt* statement, int index, char* value) {
  return bind_value(statement, index, static_cast<const char*>(value));
}

inline int bind_value(sqlite3_stmt* statement, int index, std::string const& value) {
  return bind_text(statement, index, std::string_view{value});
}

inline int bind_value(sqlite3_stmt* statement, int index, std::string_view value) {
  return bind_text(statement, index, value);
}

inline int bind_value(sqlite3_stmt* statement, int index, bool value) {
  return sqlite3_bind_int64(statement, index, value ? 1 : 0);
}

template <class T>
  requires(std::is_integral_v<T> && !std::is_same_v<T, bool>) || std::is_enum_v<T>
inline int bind_value(sqlite3_stmt* statement, int index, T value) {
  if constexpr (std::is_enum_v<T>)
    return sqlite3_bind_int64(statement, index, static_cast<std::int64_t>(static_cast<std::underlying_type_t<T>>(value)));
  else
    return sqlite3_bind_int64(statement, index, static_cast<std::int64_t>(value));
}

template <class T>
  requires std::is_floating_point_v<T> && (!std::is_same_v<T, long double>)
inline int bind_value(sqlite3_stmt* statement, int index, T value) {
  return sqlite3_bind_double(statement, index, static_cast<double>(value));
}

template <class T>
inline int bind_value(sqlite3_stmt* statement, int index, std::optional<T> const& value) {
  if (!value.has_value()) return sqlite3_bind_null(statement, index);
  return bind_value(statement, index, *value);
}

// Binds one value at a 1-based index. Returns sqlite3 result code.
template <class T>
inline int bind_any(sqlite3_stmt* statement, int index, T const& value) {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, std::nullptr_t> || std::is_same_v<U, std::nullopt_t>) {
    return bind_value(statement, index, nullptr);
  } else if constexpr (std::is_array_v<U> && std::is_same_v<std::remove_extent_t<U>, char>) {
    return bind_value(statement, index, std::string_view{value});
  } else if constexpr (std::is_convertible_v<U const&, std::string_view>) {
    return bind_value(statement, index, std::string_view{value});
  } else if constexpr (std::is_enum_v<U> || std::is_integral_v<U> || std::is_floating_point_v<U>) {
    return bind_value(statement, index, value);
  } else {
    static_assert(always_false_v<U>, "unsupported SQLite bind type");
  }
}

} // namespace detail

// RAII wrapper around sqlite3_stmt. Move-only; the destructor finalizes the
// statement. Rows can be read with current_row() after step() returns true.
class statement {
public:
  statement() = default;
  explicit statement(sqlite3_stmt* prepared) : statement_{prepared} {}
  statement(statement const&) = delete;
  statement& operator=(statement const&) = delete;
  statement(statement&& other) noexcept
      : statement_{std::exchange(other.statement_, nullptr)}, error_{std::move(other.error_)} {}
  statement& operator=(statement&& other) noexcept {
    if (this == &other) return *this;
    reset_handle();
    statement_ = std::exchange(other.statement_, nullptr);
    error_ = std::move(other.error_);
    return *this;
  }
  ~statement() { reset_handle(); }

  bool valid() const noexcept { return statement_ != nullptr; }
  sqlite3_stmt* handle() const noexcept { return statement_; }
  std::string const& error() const noexcept { return error_; }
  int column_count() const noexcept {
    return statement_ != nullptr ? sqlite3_column_count(statement_) : 0;
  }

  // Binds `value` at a 1-based parameter index. Accepts integers, enums,
  // floats, bool, strings/string_views, const char*, optional<T> and nullptr.
  template <class T>
  std::expected<void, std::string> bind(int index, T const& value) {
    if (statement_ == nullptr) return std::unexpected(std::string{"statement is not prepared"});
    int const result = detail::bind_any(statement_, index, value);
    if (result != SQLITE_OK) {
      error_ = detail::last_error(sqlite3_db_handle(statement_));
      return std::unexpected(error_);
    }
    error_.clear();
    return {};
  }

  std::expected<void, std::string> reset() {
    if (statement_ == nullptr) return std::unexpected(std::string{"statement is not prepared"});
    sqlite3_reset(statement_);
    sqlite3_clear_bindings(statement_);
    error_.clear();
    return {};
  }

  // true -> a row is available; false -> SQLITE_DONE (also for comment-only SQL,
  // which prepares without a statement).
  std::expected<bool, std::string> step() {
    if (statement_ == nullptr) return false;
    int const result = sqlite3_step(statement_);
    if (result == SQLITE_ROW) return true;
    if (result == SQLITE_DONE) return false;
    error_ = detail::last_error(sqlite3_db_handle(statement_));
    return std::unexpected(error_);
  }

  // Materializes the current row as optional strings.
  row current_row() const {
    row values{};
    if (statement_ == nullptr) return values;
    int const columns = sqlite3_column_count(statement_);
    values.reserve(static_cast<std::size_t>(columns));
    for (int column = 0; column < columns; ++column) {
      if (sqlite3_column_type(statement_, column) == SQLITE_NULL) {
        values.emplace_back(std::nullopt);
        continue;
      }
      auto const* text = sqlite3_column_text(statement_, column);
      int const bytes = sqlite3_column_bytes(statement_, column);
      if (text == nullptr)
        values.emplace_back(std::nullopt);
      else
        values.emplace_back(std::string{reinterpret_cast<char const*>(text), static_cast<std::size_t>(bytes)});
    }
    return values;
  }

  // SQLite's rowid of the most recent successful INSERT on this connection.
  std::int64_t last_insert_rowid() const noexcept {
    return statement_ != nullptr ? sqlite3_last_insert_rowid(sqlite3_db_handle(statement_)) : 0;
  }

private:
  void reset_handle() noexcept {
    if (statement_ != nullptr) sqlite3_finalize(statement_);
    statement_ = nullptr;
  }

  sqlite3_stmt* statement_ = nullptr;
  std::string error_{};
};

namespace detail {

inline std::expected<statement, std::string> prepare(sqlite3* handle, std::string_view sql) {
  if (handle == nullptr) return std::unexpected(std::string{"database is not open"});
  sqlite3_stmt* prepared = nullptr;
  int const result = sqlite3_prepare_v2(handle, sql.data(), static_cast<int>(sql.size()), &prepared, nullptr);
  if (result != SQLITE_OK) return std::unexpected(last_error(handle));
  return statement{prepared};
}

inline std::expected<void, std::string> bind_all(statement&, int) { return {}; }

template <class T, class... Rest>
std::expected<void, std::string> bind_all(statement& prepared, int index, T const& value, Rest const&... rest) {
  auto bound = prepared.bind(index, value);
  if (!bound) return bound;
  return bind_all(prepared, index + 1, rest...);
}

template <class... Args>
std::expected<void, std::string> run_exec_with(sqlite3* handle, std::string_view sql, Args const&... args) {
  auto prepared = prepare(handle, sql);
  if (!prepared) return std::unexpected(prepared.error());
  auto bound = bind_all(*prepared, 1, args...);
  if (!bound) return bound;
  auto stepped = prepared->step();
  if (!stepped) return std::unexpected(stepped.error());
  if (*stepped) return std::unexpected(std::string{"exec() statement returned rows; use query()"});
  return {};
}

template <class... Args>
std::expected<rows, std::string> run_query_with(sqlite3* handle, std::string_view sql, Args const&... args) {
  auto prepared = prepare(handle, sql);
  if (!prepared) return std::unexpected(prepared.error());
  auto bound = bind_all(*prepared, 1, args...);
  if (!bound) return std::unexpected(bound.error());
  rows result{};
  while (true) {
    auto stepped = prepared->step();
    if (!stepped) return std::unexpected(stepped.error());
    if (!*stepped) break;
    result.push_back(prepared->current_row());
  }
  return result;
}

inline std::expected<rows, std::string> run_query(sqlite3* handle, std::string_view sql) {
  return run_query_with(handle, sql);
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
  std::expected<void, std::string> open(std::string_view path, open_options options = {}) {
    close();
    std::string filename{path};
    sqlite3* opened = nullptr;
    int const result = sqlite3_open_v2(filename.c_str(), &opened,
                                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                       nullptr);
    if (result != SQLITE_OK) {
      error_ = detail::last_error(opened);
      if (opened != nullptr) sqlite3_close_v2(opened);
      return std::unexpected(error_);
    }
    handle_ = opened;
    error_.clear();

    if (options.busy_timeout_ms > 0) sqlite3_busy_timeout(handle_, options.busy_timeout_ms);
    if (auto pragma = exec(options.foreign_keys ? "PRAGMA foreign_keys = ON" : "PRAGMA foreign_keys = OFF");
        !pragma)
      return pragma;
    if (options.enable_wal) {
      // WAL is not available for in-memory databases; sqlite reports "memory"
      // as the resulting journal mode and the pragma still succeeds.
      if (auto pragma = exec(std::string_view{"PRAGMA journal_mode = WAL"}); !pragma) return pragma;
    }
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

  // Runs one or more statements without bound parameters.
  std::expected<void, std::string> exec(std::string_view sql) {
    auto result = detail::run_exec(handle_, sql);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

  // Runs one statement with bound parameters (see statement::bind).
  template <class... Args>
    requires(sizeof...(Args) > 0)
  std::expected<void, std::string> exec(std::string_view sql, Args const&... args) {
    auto result = detail::run_exec_with(handle_, sql, args...);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

  // Runs one statement without bound parameters and materializes all rows.
  std::expected<rows, std::string> query(std::string_view sql) {
    auto result = detail::run_query(handle_, sql);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

  // Runs one statement with bound parameters and materializes all rows.
  template <class... Args>
    requires(sizeof...(Args) > 0)
  std::expected<rows, std::string> query(std::string_view sql, Args const&... args) {
    auto result = detail::run_query_with(handle_, sql, args...);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

  // Prepares a statement for repeated execution.
  std::expected<statement, std::string> prepare(std::string_view sql) {
    auto result = detail::prepare(handle_, sql);
    if (!result) error_ = result.error();
    return result;
  }

  std::int64_t last_insert_rowid() const noexcept {
    return handle_ != nullptr ? sqlite3_last_insert_rowid(handle_) : 0;
  }

  int changes() const noexcept { return handle_ != nullptr ? sqlite3_changes(handle_) : 0; }

private:
  sqlite3* handle_ = nullptr;
  std::string error_{};
};

// A transaction on a connection owned by someone else (normally `database`).
//
// The constructor runs BEGIN (IMMEDIATE by default). The destructor rolls back a
// transaction that is still active, so RAII alone is enough for correctness.
// Move-only: moving transfers the rollback responsibility. The underlying
// connection must outlive the transaction.
class transaction {
public:
  explicit transaction(sqlite3* handle, transaction_mode mode = transaction_mode::immediate)
      : handle_{handle} {
    if (handle == nullptr) {
      error_ = "database is not open";
      return;
    }
    char const* begin = mode == transaction_mode::deferred    ? "BEGIN DEFERRED"
                        : mode == transaction_mode::exclusive ? "BEGIN EXCLUSIVE"
                                                              : "BEGIN IMMEDIATE";
    if (auto begun = detail::run_exec(handle_, begin); !begun) {
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

  template <class... Args>
    requires(sizeof...(Args) > 0)
  std::expected<void, std::string> exec(std::string_view sql, Args const&... args) {
    auto result = detail::run_exec_with(handle_, sql, args...);
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

  template <class... Args>
    requires(sizeof...(Args) > 0)
  std::expected<rows, std::string> query(std::string_view sql, Args const&... args) {
    auto result = detail::run_query_with(handle_, sql, args...);
    if (result)
      error_.clear();
    else
      error_ = result.error();
    return result;
  }

  std::expected<statement, std::string> prepare(std::string_view sql) {
    auto result = detail::prepare(handle_, sql);
    if (!result) error_ = result.error();
    return result;
  }

  std::int64_t last_insert_rowid() const noexcept {
    return handle_ != nullptr ? sqlite3_last_insert_rowid(handle_) : 0;
  }

  int changes() const noexcept { return handle_ != nullptr ? sqlite3_changes(handle_) : 0; }

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
  transaction_mode mode = transaction_mode::immediate;

  http::response operator()(http::context& context, http::request_view const& request,
                            http::next const& next) const {
    if (db == nullptr) return failure("sqlite: no database configured");
    if (!db->valid()) return failure("sqlite: database is not open");

    transaction tx{db->handle(), mode};
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
