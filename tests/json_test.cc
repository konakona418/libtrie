#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "harness.hh"
#include "trie/json.hh"

namespace {

enum class color { red, green, blue };

struct point {
  int x;
  int y;
};

struct address {
  std::string city;
  int zip;
};

struct user {
  std::string name;
  int id;
  bool active;
  std::optional<std::string> nickname;
  std::optional<int> age;
  std::vector<point> points;
  std::array<int, 3> scores;
  color favorite;
  address home;
};

// serializable() is what router headers will constrain body parameters with.
static_assert(trie::json::serializable<user>());
static_assert(trie::json::serializable<point>());
static_assert(trie::json::serializable<color>());
static_assert(trie::json::serializable<trie::json::value>());
static_assert(trie::json::serializable<std::vector<std::optional<int>>>());
static_assert(trie::json::serializable<std::array<point, 2>>());
static_assert(trie::json::serializable<std::string_view>());
static_assert(!trie::json::serializable<int*>());
static_assert(!trie::json::serializable<std::vector<int*>>());
static_assert(!trie::json::serializable<std::map<std::string, int>>());

bool roundtrip_user(user const& original) {
  trie::json::value encoded = trie::json::to_json(original);
  auto decoded = trie::json::from_json<user>(encoded);
  if (!decoded) return false;
  return decoded->name == original.name && decoded->id == original.id &&
         decoded->active == original.active && decoded->nickname == original.nickname &&
         decoded->age == original.age && decoded->points.size() == original.points.size() &&
         decoded->scores == original.scores && decoded->favorite == original.favorite &&
         decoded->home.city == original.home.city && decoded->home.zip == original.home.zip &&
         (decoded->points.empty() ||
          (decoded->points[0].x == original.points[0].x &&
           decoded->points[0].y == original.points[0].y));
}

} // namespace

int main() {
  using trie::json::dump;
  using trie::json::from_json;
  using trie::json::parse;
  using trie::json::parse_as;
  using trie::json::to_json;
  using trie::json::value;

  // -------------------------------------------------------------------------
  // Scalars
  // -------------------------------------------------------------------------
  {
    auto null_value = parse("null");
    CHECK(null_value.has_value());
    CHECK(null_value->is_null());

    auto true_value = parse("true");
    CHECK(true_value.has_value());
    CHECK(true_value->is_boolean());
    CHECK_EQ(true_value->get<bool>(), true);

    auto false_value = parse("false");
    CHECK(false_value.has_value());
    CHECK_EQ(false_value->get<bool>(), false);

    auto integer = parse("42");
    CHECK(integer.has_value());
    CHECK(integer->is_number_integer());
    CHECK_EQ(integer->get<std::int64_t>(), std::int64_t{42});

    auto negative = parse("-17");
    CHECK(negative.has_value());
    CHECK_EQ(negative->get<std::int64_t>(), std::int64_t{-17});

    auto floating = parse("3.5");
    CHECK(floating.has_value());
    CHECK(floating->is_number_float());
    CHECK_EQ(floating->get<double>(), 3.5);

    auto exponent = parse("1e3");
    CHECK(exponent.has_value());
    CHECK_EQ(exponent->get<double>(), 1000.0);

    auto text = parse("\"hello\"");
    CHECK(text.has_value());
    CHECK(text->is_string());
    CHECK_EQ(text->get<std::string>(), std::string{"hello"});
  }

  // -------------------------------------------------------------------------
  // Objects and arrays
  // -------------------------------------------------------------------------
  {
    auto doc = parse(R"({"name":"trie","tags":["a","b"],"nested":{"count":2,"ok":false},"nil":null})");
    CHECK(doc.has_value());
    CHECK(doc->is_object());
    CHECK(doc->contains("name"));
    CHECK_EQ((*doc)["name"].get<std::string>(), std::string{"trie"});
    CHECK((*doc)["tags"].is_array());
    CHECK_EQ((*doc)["tags"].size(), std::size_t{2});
    CHECK_EQ((*doc)["tags"][1].get<std::string>(), std::string{"b"});
    CHECK((*doc)["nested"].is_object());
    CHECK_EQ((*doc)["nested"]["count"].get<std::int64_t>(), std::int64_t{2});
    CHECK((*doc)["nested"]["ok"].is_boolean());
    CHECK((*doc)["nil"].is_null());
    CHECK(!doc->contains("missing"));

    auto empty_object = parse("{}");
    CHECK(empty_object.has_value());
    CHECK(empty_object->is_object());
    CHECK_EQ(empty_object->size(), std::size_t{0});

    auto empty_array = parse("[]");
    CHECK(empty_array.has_value());
    CHECK(empty_array->is_array());
    CHECK_EQ(empty_array->size(), std::size_t{0});
  }

  // -------------------------------------------------------------------------
  // Strings: escapes and unicode (including surrogate pairs)
  // -------------------------------------------------------------------------
  {
    auto escaped = parse(R"("a\"b\\c\/d\b\f\n\r\t")");
    CHECK(escaped.has_value());
    CHECK_EQ(escaped->get<std::string>(), std::string{"a\"b\\c/d\b\f\n\r\t"});

    auto unicode = parse(R"("\u0041\u00e9\u4e2d\ud83d\ude00")");
    CHECK(unicode.has_value());
    CHECK_EQ(unicode->get<std::string>(), std::string{"A\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80"});

    // A parsed document can be dumped and parsed again losslessly.
    auto first = parse(R"({"esc":"line\nbreak","uni":"\u00e9"})");
    CHECK(first.has_value());
    auto second = parse(dump(*first));
    CHECK(second.has_value());
    CHECK(*first == *second);
  }

  // -------------------------------------------------------------------------
  // Parse/dump roundtrip and compact output
  // -------------------------------------------------------------------------
  {
    std::string const source =
        R"({"a":[1,2,3],"b":"x\n","c":true,"d":null,"e":3.5,"f":{"g":[]}})";
    auto first = parse(source);
    CHECK(first.has_value());
    std::string const text = dump(*first);
    CHECK_EQ(text, source);
    auto second = parse(text);
    CHECK(second.has_value());
    CHECK(*first == *second);

    auto ordered = parse(R"({"z":1,"a":2})");
    CHECK(ordered.has_value());
    CHECK_EQ(dump(*ordered), std::string{R"({"a":2,"z":1})"});
  }

  // -------------------------------------------------------------------------
  // dump(): escaping, numbers, invalid UTF-8, discarded
  // -------------------------------------------------------------------------
  {
    CHECK_EQ(dump(value(std::string{"a\"b\\c\n\t\x01"})),
             std::string{"\"a\\\"b\\\\c\\n\\t\\u0001\""});
    CHECK_EQ(dump(value(42)), std::string{"42"});
    CHECK_EQ(dump(value(std::int64_t{-7})), std::string{"-7"});
    CHECK_EQ(dump(value(true)), std::string{"true"});
    CHECK_EQ(dump(value(nullptr)), std::string{"null"});
    CHECK_EQ(dump(value(3.5)), std::string{"3.5"});
    CHECK_EQ(dump(value(1)), std::string{"1"});
    CHECK_EQ(dump(value(1.0)), std::string{"1.0"});
    CHECK_EQ(dump(value(std::string{"\xc3\xa9"})), std::string{"\"\xc3\xa9\""});

    // Invalid UTF-8 is replaced with U+FFFD rather than aborting.
    CHECK_EQ(dump(value(std::string{"\xff"})), std::string{"\"\xef\xbf\xbd\""});

    // A discarded value (nlohmann's error marker) is dumped as null.
    value discarded(value::value_t::discarded);
    CHECK_EQ(dump(discarded), std::string{"null"});
  }

  // -------------------------------------------------------------------------
  // Malformed input: std::expected errors with an offset, never abort
  // -------------------------------------------------------------------------
  {
    auto empty = parse("");
    CHECK(!empty.has_value());
    CHECK_EQ(empty.error().offset, std::size_t{0});
    CHECK(!empty.error().message.empty());

    auto whitespace = parse("   ");
    CHECK(!whitespace.has_value());
    CHECK_EQ(whitespace.error().offset, std::size_t{3});

    auto unterminated = parse("\"abc");
    CHECK(!unterminated.has_value());
    CHECK_EQ(unterminated.error().offset, std::size_t{4});

    auto bad_fraction = parse("1.");
    CHECK(!bad_fraction.has_value());
    CHECK_EQ(bad_fraction.error().offset, std::size_t{2});

    auto bad_number = parse("01");
    CHECK(!bad_number.has_value());
    CHECK_EQ(bad_number.error().offset, std::size_t{1});

    auto trailing = parse("[1,2] x");
    CHECK(!trailing.has_value());
    CHECK_EQ(trailing.error().offset, std::size_t{6});
    CHECK_EQ(std::string_view{"[1,2] x"}[trailing.error().offset], 'x');

    auto trailing_comma = parse(R"({"a":1,})");
    CHECK(!trailing_comma.has_value());
    CHECK_EQ(trailing_comma.error().offset, std::size_t{7});
    CHECK_EQ(std::string_view{R"({"a":1,})"}[trailing_comma.error().offset], '}');

    auto unclosed = parse(R"({"a":1)");
    CHECK(!unclosed.has_value());
    CHECK_EQ(unclosed.error().offset, std::size_t{6});

    auto literal = parse("tru");
    CHECK(!literal.has_value());
    CHECK_EQ(literal.error().offset, std::size_t{3});

    auto surrogate = parse(R"("\ud800")");
    CHECK(!surrogate.has_value());
    CHECK(!surrogate.error().message.empty());

    // Every reported offset has to be inside (or at the end of) the input.
    for (std::string_view const malformed : {"", "   ", "\"abc", "1.", "01", "[1,2] x",
                                             R"({"a":1,})", R"({"a":1)", "tru", R"("\ud800")"}) {
      auto result = parse(malformed);
      CHECK(!result.has_value());
      CHECK(result.error().offset <= malformed.size());
    }
  }

  // -------------------------------------------------------------------------
  // Reflection: nested aggregate -> JSON -> aggregate
  // -------------------------------------------------------------------------
  {
    user original{};
    original.name = "Ada";
    original.id = 7;
    original.active = true;
    original.nickname = "ada";
    original.age = std::nullopt;
    original.points = {{1, 2}, {3, 4}};
    original.scores = {10, 20, 30};
    original.favorite = color::blue;
    original.home = {"Berlin", 10115};

    value encoded = to_json(original);
    CHECK(encoded.is_object());
    CHECK_EQ(encoded["name"].get<std::string>(), std::string{"Ada"});
    CHECK_EQ(encoded["id"].get<std::int64_t>(), std::int64_t{7});
    CHECK(encoded["active"].get<bool>());
    CHECK(encoded["nickname"].is_string());
    CHECK(encoded["age"].is_null());
    CHECK(encoded["points"].is_array());
    CHECK_EQ(encoded["points"].size(), std::size_t{2});
    CHECK_EQ(encoded["points"][1]["y"].get<std::int64_t>(), std::int64_t{4});
    CHECK(encoded["scores"].is_array());
    CHECK_EQ(encoded["scores"].size(), std::size_t{3});
    CHECK_EQ(encoded["favorite"].get<std::string>(), std::string{"blue"});
    CHECK(encoded["home"].is_object());
    CHECK_EQ(encoded["home"]["city"].get<std::string>(), std::string{"Berlin"});
    CHECK_EQ(encoded["home"]["zip"].get<std::int64_t>(), std::int64_t{10115});

    CHECK(roundtrip_user(original));

    auto decoded = from_json<user>(encoded);
    CHECK(decoded.has_value());
    if (decoded) {
      CHECK_EQ(decoded->name, original.name);
      CHECK_EQ(decoded->id, original.id);
      CHECK_EQ(decoded->active, original.active);
      CHECK(decoded->nickname.has_value());
      CHECK_EQ(*decoded->nickname, std::string{"ada"});
      CHECK(!decoded->age.has_value());
      CHECK_EQ(decoded->points.size(), std::size_t{2});
      CHECK_EQ(decoded->points[1].x, 3);
      CHECK_EQ(decoded->scores[2], 30);
      CHECK(decoded->favorite == color::blue);
      CHECK_EQ(decoded->home.city, std::string{"Berlin"});
      CHECK_EQ(decoded->home.zip, 10115);
    }

    // The same trip through text.
    auto via_text = parse_as<user>(dump(encoded));
    CHECK(via_text.has_value());
    if (via_text) {
      CHECK_EQ(via_text->name, std::string{"Ada"});
      CHECK_EQ(via_text->points.size(), std::size_t{2});
      CHECK(via_text->favorite == color::blue);
    }
  }

  // -------------------------------------------------------------------------
  // Aggregates: missing keys keep defaults, unknown keys are ignored
  // -------------------------------------------------------------------------
  {
    auto partial = parse(R"({"name":"Bob","unknown":123,"extra":{"x":[1,2]}})");
    CHECK(partial.has_value());
    auto bob = from_json<user>(*partial);
    CHECK(bob.has_value());
    if (bob) {
      CHECK_EQ(bob->name, std::string{"Bob"});
      CHECK_EQ(bob->id, 0);
      CHECK(!bob->active);
      CHECK(!bob->nickname.has_value());
      CHECK(!bob->age.has_value());
      CHECK(bob->points.empty());
      CHECK_EQ(bob->scores[0], 0);
      CHECK(bob->favorite == color::red);
      CHECK_EQ(bob->home.city, std::string{});
      CHECK_EQ(bob->home.zip, 0);
    }

    auto all_present = parse(R"({"name":"Eve","id":2,"active":false,"nickname":null,
                                 "age":31,"points":[],"scores":[0,0,0],
                                 "favorite":"red","home":{"city":"Rome","zip":1}})");
    CHECK(all_present.has_value());
    auto eve = from_json<user>(*all_present);
    CHECK(eve.has_value());
    if (eve) {
      CHECK_EQ(eve->age.value_or(-1), 31);
      CHECK(!eve->nickname.has_value());
      CHECK(eve->points.empty());
    }
  }

  // -------------------------------------------------------------------------
  // Type mismatches are errors, not aborts
  // -------------------------------------------------------------------------
  {
    CHECK(!from_json<int>(value("text")).has_value());
    CHECK(!from_json<int>(value(true)).has_value());
    CHECK(!from_json<std::string>(value(12)).has_value());
    CHECK(!from_json<bool>(value(1)).has_value());
    CHECK(!from_json<std::vector<int>>(value::object()).has_value());
    CHECK((!from_json<std::array<int, 2>>(value::array()).has_value()));

    auto arr3 = parse("[1,2,3]");
    CHECK(arr3.has_value());
    if (arr3) {
      auto wrong_length = from_json<std::array<int, 2>>(*arr3);
      CHECK(!wrong_length.has_value());
      CHECK(wrong_length.error().message.find("length") != std::string::npos);
    }

    auto fractional = from_json<int>(value(1.5));
    CHECK(!fractional.has_value());
    CHECK(fractional.error().message.find("integer") != std::string::npos);

    auto negative_unsigned = from_json<unsigned>(value(-1));
    CHECK(!negative_unsigned.has_value());
    auto too_big = from_json<std::uint8_t>(value(300));
    CHECK(!too_big.has_value());

    auto unknown_enum = from_json<color>(value("orange"));
    CHECK(!unknown_enum.has_value());
    CHECK(unknown_enum.error().message.find("orange") != std::string::npos);
    auto numeric_enum = from_json<color>(value(1));
    CHECK(!numeric_enum.has_value());

    auto bad_member = parse(R"({"id":"not a number"})");
    CHECK(bad_member.has_value());
    auto bad_user = from_json<user>(*bad_member);
    CHECK(!bad_user.has_value());
    CHECK(!bad_user.error().message.empty());

    auto bad_optional = from_json<std::optional<int>>(value("x"));
    CHECK(!bad_optional.has_value());
  }

  // -------------------------------------------------------------------------
  // Primitive/container conversions
  // -------------------------------------------------------------------------
  {
    CHECK_EQ(dump(to_json(42)), std::string{"42"});
    CHECK_EQ(dump(to_json(true)), std::string{"true"});
    CHECK_EQ(dump(to_json(std::string{"hi"})), std::string{"\"hi\""});
    CHECK_EQ(dump(to_json(std::string_view{"hi"})), std::string{"\"hi\""});
    CHECK_EQ(dump(to_json("hi")), std::string{"\"hi\""});
    CHECK_EQ(dump(to_json(color::green)), std::string{"\"green\""});
    CHECK_EQ(dump(to_json(std::optional<int>{})), std::string{"null"});
    CHECK_EQ(dump(to_json(std::optional<int>{5})), std::string{"5"});
    CHECK_EQ(dump(to_json(std::vector<int>{1, 2})), std::string{"[1,2]"});
    CHECK_EQ(dump(to_json(std::array<int, 2>{3, 4})), std::string{"[3,4]"});
    CHECK_EQ(dump(to_json(3.25)), std::string{"3.25"});
    CHECK_EQ(dump(to_json(std::uint64_t{18446744073709551615u})),
             std::string{"18446744073709551615"});
    CHECK_EQ(dump(to_json(std::int64_t{9007199254740993})), std::string{"9007199254740993"});

    auto green = from_json<color>(value("green"));
    CHECK(green.has_value());
    CHECK(*green == color::green);

    auto number = parse_as<int>("42");
    CHECK(number.has_value());
    CHECK_EQ(*number, 42);

    auto unsigned_max = parse_as<std::uint64_t>("18446744073709551615");
    CHECK(unsigned_max.has_value());
    CHECK_EQ(*unsigned_max, std::uint64_t{18446744073709551615u});

    auto strings = parse_as<std::vector<std::string>>(R"(["a","b"])");
    CHECK(strings.has_value());
    CHECK_EQ(strings->size(), std::size_t{2});
    CHECK_EQ((*strings)[1], std::string{"b"});

    auto scores = parse_as<std::array<int, 3>>("[1,2,3]");
    CHECK(scores.has_value());
    CHECK_EQ((*scores)[2], 3);

    // A std::string_view result keeps pointing into the live document.
    value live = value("hello");
    auto view = from_json<std::string_view>(live);
    CHECK(view.has_value());
    CHECK_EQ(*view, std::string_view{"hello"});
    auto c_string = from_json<const char*>(live);
    CHECK(c_string.has_value());
    CHECK_EQ(std::string{*c_string}, std::string{"hello"});

    // json::value passes through unchanged.
    value raw = value::array();
    raw.push_back(1);
    raw.push_back("two");
    CHECK_EQ(dump(to_json(raw)), std::string{"[1,\"two\"]"});
    auto same = from_json<value>(raw);
    CHECK(same.has_value());
    CHECK(*same == raw);

    CHECK(!parse_as<int>("nope").has_value());
    CHECK(!parse_as<std::vector<int>>("{}").has_value());
    CHECK(!parse_as<user>("[]").has_value());
  }

  return tst::report("json_test");
}
