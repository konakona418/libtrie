#include "trie/middleware/sqlite.hh"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "harness.hh"

namespace {

void create_schema(trie::sqlite::database& db) {
  auto created = db.exec("CREATE TABLE notes(id INTEGER PRIMARY KEY, author TEXT NOT NULL, text TEXT, score REAL)");
  CHECK(created.has_value());
}

} // namespace

int main() {
  {
    // Open options: foreign keys on, WAL requested, busy timeout accepted.
    trie::sqlite::database db;
    auto opened = db.open(":memory:", trie::sqlite::open_options{
                                         .busy_timeout_ms = 1000,
                                         .enable_wal = true,
                                         .foreign_keys = true,
                                     });
    CHECK(opened.has_value());
    CHECK(db.valid());
    create_schema(db);
  }
  {
    // Bound parameters for exec/query (no string concatenation).
    trie::sqlite::database db;
    CHECK(db.open(":memory:").has_value());
    create_schema(db);

    auto inserted = db.exec("INSERT INTO notes(author, text, score) VALUES(?1, ?2, ?3)", std::string_view{"alice"},
                            std::string_view{"hello"}, 1.5);
    CHECK(inserted.has_value());
    CHECK_EQ(db.last_insert_rowid(), std::int64_t{1});
    CHECK_EQ(db.changes(), 1);

    auto rows = db.query("SELECT id, author, text, score FROM notes WHERE author = ?1 AND id > ?2",
                         std::string_view{"alice"}, std::int64_t{0});
    CHECK(rows.has_value());
    CHECK_EQ(rows->size(), std::size_t{1});
    CHECK_EQ((*rows)[0][1].value_or(""), std::string{"alice"});
    CHECK_EQ((*rows)[0][2].value_or(""), std::string{"hello"});
    CHECK_EQ((*rows)[0][3].value_or(""), std::string{"1.5"});
  }
  {
    // Strings containing quotes cannot break out of the statement.
    trie::sqlite::database db;
    CHECK(db.open(":memory:").has_value());
    create_schema(db);

    std::string_view hostile{"'; DROP TABLE notes; --"};
    CHECK(db.exec("INSERT INTO notes(author, text) VALUES(?1, ?2)", std::string_view{"eve"}, hostile).has_value());

    auto rows = db.query("SELECT text FROM notes WHERE author = ?1", std::string_view{"eve"});
    CHECK(rows.has_value());
    CHECK_EQ(rows->size(), std::size_t{1});
    CHECK_EQ((*rows)[0][0].value_or(""), hostile);

    auto count = db.query("SELECT COUNT(*) FROM notes");
    CHECK(count.has_value());
    CHECK_EQ((*count)[0][0].value_or(""), std::string{"1"}); // table still exists
  }
  {
    // Optional/null/integer/double binding and NULL round-trip.
    trie::sqlite::database db;
    CHECK(db.open(":memory:").has_value());
    create_schema(db);

    CHECK(db.exec("INSERT INTO notes(author, text, score) VALUES(?1, ?2, ?3)", std::string_view{"bob"},
                  std::nullopt, 2.25)
              .has_value());
    auto rows = db.query("SELECT author, text, score FROM notes");
    CHECK(rows.has_value());
    CHECK_EQ(rows->size(), std::size_t{1});
    CHECK_EQ((*rows)[0][0].value_or(""), std::string{"bob"});
    CHECK(!(*rows)[0][1].has_value());
    CHECK_EQ((*rows)[0][2].value_or(""), std::string{"2.25"});
  }
  {
    // Prepared statements can be reused with reset and rebound parameters.
    trie::sqlite::database db;
    CHECK(db.open(":memory:").has_value());
    create_schema(db);

    auto prepared = db.prepare("INSERT INTO notes(author, text) VALUES(?1, ?2)");
    CHECK(prepared.has_value());
    auto& insert = *prepared;

    CHECK(insert.bind(1, std::string_view{"carol"}).has_value());
    CHECK(insert.bind(2, std::string_view{"first"}).has_value());
    auto first_step = insert.step();
    CHECK(first_step.has_value());
    CHECK(!*first_step);

    CHECK(insert.reset().has_value());
    CHECK(insert.bind(1, std::string_view{"carol"}).has_value());
    CHECK(insert.bind(2, std::string_view{"second"}).has_value());
    auto second_step = insert.step();
    CHECK(second_step.has_value());
    CHECK(!*second_step);

    auto rows = db.query("SELECT text FROM notes ORDER BY id");
    CHECK(rows.has_value());
    CHECK_EQ(rows->size(), std::size_t{2});
    CHECK_EQ((*rows)[0][0].value_or(""), std::string{"first"});
    CHECK_EQ((*rows)[1][0].value_or(""), std::string{"second"});
  }
  {
    // Manual row iteration through statement::step/current_row/column_count.
    trie::sqlite::database db;
    CHECK(db.open(":memory:").has_value());
    create_schema(db);
    CHECK(db.exec("INSERT INTO notes(author, text) VALUES(?1, ?2)", std::string_view{"a"}, std::string_view{"x"})
              .has_value());
    CHECK(db.exec("INSERT INTO notes(author, text) VALUES(?1, ?2)", std::string_view{"b"}, std::string_view{"y"})
              .has_value());

    auto prepared = db.prepare("SELECT author, text FROM notes ORDER BY id");
    CHECK(prepared.has_value());
    CHECK_EQ(prepared->column_count(), 2);
    std::vector<std::string> authors;
    while (true) {
      auto stepped = prepared->step();
      CHECK(stepped.has_value());
      if (!*stepped) break;
      auto row = prepared->current_row();
      CHECK_EQ(row.size(), std::size_t{2});
      authors.push_back(row[0].value_or(""));
    }
    CHECK_EQ(authors.size(), std::size_t{2});
    CHECK_EQ(authors[0], std::string{"a"});
    CHECK_EQ(authors[1], std::string{"b"});
  }
  {
    // Transaction modes and commit/rollback still behave.
    trie::sqlite::database db;
    CHECK(db.open(":memory:").has_value());
    create_schema(db);

    {
      trie::sqlite::transaction deferred{db.handle(), trie::sqlite::transaction_mode::deferred};
      CHECK(deferred.valid());
      CHECK(deferred.exec("INSERT INTO notes(author, text) VALUES(?1, ?2)", std::string_view{"a"},
                          std::string_view{"deferred"})
                .has_value());
      CHECK(deferred.commit().has_value());
    }
    {
      trie::sqlite::transaction exclusive{db.handle(), trie::sqlite::transaction_mode::exclusive};
      CHECK(exclusive.valid());
      CHECK(exclusive.exec("INSERT INTO notes(author, text) VALUES(?1, ?2)", std::string_view{"b"},
                           std::string_view{"exclusive"})
                .has_value());
      CHECK(exclusive.rollback().has_value());
    }
    auto count = db.query("SELECT COUNT(*) FROM notes");
    CHECK(count.has_value());
    CHECK_EQ((*count)[0][0].value_or(""), std::string{"1"});
  }
  {
    // Errors are reported through std::expected.
    trie::sqlite::database db;
    CHECK(db.open(":memory:").has_value());
    create_schema(db);
    CHECK(!db.exec("INSERT INTO missing_table(a) VALUES(?1)", std::int64_t{1}).has_value());
    CHECK(!db.query("SELECT * FROM missing_table WHERE id = ?1", std::int64_t{1}).has_value());
    CHECK(!db.exec("THIS IS NOT SQL", std::int64_t{1}).has_value());

    // exec() rejects statements that produce rows.
    CHECK(!db.exec("SELECT ?1", std::int64_t{1}).has_value());

    auto prepared = db.prepare("INSERT INTO notes(author, text) VALUES(?1, ?2)");
    CHECK(prepared.has_value());
    // Unbound parameters default to NULL in SQLite.
    CHECK(prepared->bind(1, std::string_view{"x"}).has_value());
    auto stepped = prepared->step();
    CHECK(stepped.has_value());
    CHECK(!*stepped);
    auto rows = db.query("SELECT text FROM notes WHERE author = ?1", std::string_view{"x"});
    CHECK(rows.has_value());
    CHECK_EQ(rows->size(), std::size_t{1});
    CHECK(!(*rows)[0][0].has_value());
  }
  return tst::report("sqlite_api_test");
}
