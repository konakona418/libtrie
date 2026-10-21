#include <array>
#include <cstdint>
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

// Natural "required" rule: every member below except nickname, age and level
// (std::optional, and a member with a default member initializer) is required.
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
  int level = 1;
};

// retries has a default member initializer, host does not.
struct settings {
  int retries = 3;
  std::string host;
};

struct empty {};

static_assert(trie::json::serializable<point>());
static_assert(trie::json::serializable<user>());
static_assert(trie::json::serializable<settings>());

bool mentions(trie::json::error const& e, std::string_view text) {
  return e.message.find(text) != std::string::npos;
}

// Parses a test fixture; a malformed fixture is reported by the checks that
// inspect the returned document (and by validate() failing on it).
trie::json::value document(std::string_view text) {
  auto parsed = trie::json::parse(text);
  return parsed ? *parsed : trie::json::value(nullptr);
}

// The schema of a scalar: {"type": <type>}.
trie::json::value type_schema(std::string_view type) {
  trie::json::value out = trie::json::value::object();
  out["type"] = std::string{type};
  return out;
}

} // namespace

int main() {
  using trie::json::dump;
  using trie::json::schema;
  using trie::json::validate;
  using trie::json::validate_options;
  using trie::json::value;

  // -------------------------------------------------------------------------
  // Scalars: valid values and type/range failures, no path at the root
  // -------------------------------------------------------------------------
  {
    CHECK(validate<int>(value(42)).has_value());
    CHECK(validate<int>(value(-7)).has_value());
    CHECK(validate<int>(value(0)).has_value());
    CHECK(validate<std::int8_t>(value(-128)).has_value());
    CHECK(validate<std::uint8_t>(value(255)).has_value());
    CHECK(validate<std::uint64_t>(value(std::uint64_t{18446744073709551615u})).has_value());
    // integral-valued floats are accepted for integer types
    CHECK(validate<int>(value(3.0)).has_value());
    CHECK(validate<std::uint8_t>(value(255.0)).has_value());
    CHECK(validate<double>(value(3.5)).has_value());
    CHECK(validate<double>(value(3)).has_value());
    CHECK(validate<float>(value(1.5f)).has_value());
    CHECK(validate<bool>(value(true)).has_value());
    CHECK(validate<bool>(value(false)).has_value());
    CHECK(validate<std::string>(value("hi")).has_value());
    CHECK(validate<std::string_view>(value("hi")).has_value());
    CHECK(validate<const char*>(value("hi")).has_value());

    auto text_for_int = validate<int>(value("42"));
    CHECK(!text_for_int.has_value());
    CHECK(mentions(text_for_int.error(), "expected integer"));
    CHECK_EQ(text_for_int.error().offset, std::size_t{0});

    // Default options: reject unknown keys, only naturally-required members.
    validate_options const defaults{};
    CHECK(defaults.reject_unknown);
    CHECK(!defaults.require_all);
    CHECK(validate<int>(value(7), validate_options{}).has_value());

    auto boolean_for_int = validate<int>(value(true));
    CHECK(!boolean_for_int.has_value());
    CHECK(mentions(boolean_for_int.error(), "expected integer"));

    auto fractional = validate<int>(value(1.5));
    CHECK(!fractional.has_value());
    CHECK(mentions(fractional.error(), "number is not an integer"));

    auto negative_unsigned = validate<unsigned>(value(-1));
    CHECK(!negative_unsigned.has_value());
    CHECK(mentions(negative_unsigned.error(), "out of range"));

    auto too_big = validate<std::uint8_t>(value(300));
    CHECK(!too_big.has_value());
    CHECK(mentions(too_big.error(), "integer out of range"));

    auto too_small = validate<std::int8_t>(value(-1000));
    CHECK(!too_small.has_value());
    CHECK(mentions(too_small.error(), "integer out of range"));

    auto float_range = validate<float>(value(1e300));
    CHECK(!float_range.has_value());
    CHECK(mentions(float_range.error(), "number out of range"));

    auto number_for_bool = validate<bool>(value(1));
    CHECK(!number_for_bool.has_value());
    CHECK(mentions(number_for_bool.error(), "expected boolean"));

    auto number_for_string = validate<std::string>(value(12));
    CHECK(!number_for_string.has_value());
    CHECK(mentions(number_for_string.error(), "expected string"));

    auto null_for_string = validate<std::string>(value(nullptr));
    CHECK(!null_for_string.has_value());
    CHECK(mentions(null_for_string.error(), "expected string"));
  }

  // -------------------------------------------------------------------------
  // json::value is always valid, including discarded values
  // -------------------------------------------------------------------------
  {
    CHECK(validate<value>(value(nullptr)).has_value());
    CHECK(validate<value>(value(true)).has_value());
    CHECK(validate<value>(value(1)).has_value());
    CHECK(validate<value>(value("anything")).has_value());
    CHECK(validate<value>(value::array()).has_value());
    CHECK(validate<value>(value::object()).has_value());
    value raw = value::object();
    raw["anything"] = "goes";
    CHECK(validate<value>(raw).has_value());
  }

  // -------------------------------------------------------------------------
  // Nested aggregates: dotted paths point at the offending leaf
  // -------------------------------------------------------------------------
  value const user_doc = document(R"({
    "name": "Ada",
    "id": 7,
    "active": true,
    "nickname": "ada",
    "age": null,
    "points": [{"x": 1, "y": 2}, {"x": 3, "y": 4}],
    "scores": [10, 20, 30],
    "favorite": "blue",
    "home": {"city": "Berlin", "zip": 10115}
  })");
  {
    CHECK(user_doc.is_object());
    CHECK(validate<user>(user_doc).has_value());
    CHECK(validate<point>(document(R"({"x":1,"y":2})")).has_value());

    value bad_leaf = user_doc;
    bad_leaf["home"]["zip"] = "10115";
    auto zip_result = validate<user>(bad_leaf);
    CHECK(!zip_result.has_value());
    CHECK(mentions(zip_result.error(), "home.zip"));
    CHECK(mentions(zip_result.error(), "expected integer"));

    value bad_name = user_doc;
    bad_name["name"] = 5;
    auto name_result = validate<user>(bad_name);
    CHECK(!name_result.has_value());
    CHECK(mentions(name_result.error(), "name"));
    CHECK(mentions(name_result.error(), "expected string"));

    auto object_for_point = validate<point>(value::array());
    CHECK(!object_for_point.has_value());
    CHECK(mentions(object_for_point.error(), "expected object"));
  }

  // -------------------------------------------------------------------------
  // std::optional: null is valid, non-null validates the inner value
  // -------------------------------------------------------------------------
  {
    CHECK(validate<std::optional<int>>(value(nullptr)).has_value());
    CHECK(validate<std::optional<int>>(value(5)).has_value());
    CHECK(validate<std::optional<std::string>>(value(nullptr)).has_value());
    CHECK(validate<std::optional<std::string>>(value("x")).has_value());
    CHECK(validate<std::optional<point>>(value(nullptr)).has_value());
    CHECK(validate<std::optional<point>>(document(R"({"x":1,"y":2})")).has_value());
    CHECK(validate<std::optional<value>>(value(nullptr)).has_value());

    auto bad_inner = validate<std::optional<int>>(value("x"));
    CHECK(!bad_inner.has_value());
    CHECK(mentions(bad_inner.error(), "expected integer"));

    auto bad_point = validate<std::optional<point>>(document(R"({"x":1})"));
    CHECK(!bad_point.has_value());
    CHECK(mentions(bad_point.error(), "y: missing required field"));

    value optional_field = user_doc;
    optional_field["nickname"] = nullptr;
    CHECK(validate<user>(optional_field).has_value());

    optional_field["nickname"] = 5;
    auto nickname_result = validate<user>(optional_field);
    CHECK(!nickname_result.has_value());
    CHECK(mentions(nickname_result.error(), "nickname"));
    CHECK(mentions(nickname_result.error(), "expected string"));

    value age = user_doc;
    age["age"] = "old";
    auto age_result = validate<user>(age);
    CHECK(!age_result.has_value());
    CHECK(mentions(age_result.error(), "age"));
    CHECK(mentions(age_result.error(), "expected integer"));
  }

  // -------------------------------------------------------------------------
  // Enumerations: JSON strings must name an enumerator
  // -------------------------------------------------------------------------
  {
    CHECK(validate<color>(value("red")).has_value());
    CHECK(validate<color>(value("green")).has_value());
    CHECK(validate<color>(value("blue")).has_value());

    auto unknown = validate<color>(value("purple"));
    CHECK(!unknown.has_value());
    CHECK(mentions(unknown.error(), "unknown enumerator 'purple'"));

    auto numeric = validate<color>(value(1));
    CHECK(!numeric.has_value());
    CHECK(mentions(numeric.error(), "expected string"));

    auto nul = validate<color>(value(nullptr));
    CHECK(!nul.has_value());

    value bad_field = user_doc;
    bad_field["favorite"] = "purple";
    auto field_result = validate<user>(bad_field);
    CHECK(!field_result.has_value());
    CHECK(mentions(field_result.error(), "favorite: unknown enumerator 'purple'"));

    bad_field["favorite"] = 2;
    auto numeric_field = validate<user>(bad_field);
    CHECK(!numeric_field.has_value());
    CHECK(mentions(numeric_field.error(), "favorite"));
    CHECK(mentions(numeric_field.error(), "expected string"));
  }

  // -------------------------------------------------------------------------
  // std::vector: array required, element errors carry their index
  // -------------------------------------------------------------------------
  {
    CHECK(validate<std::vector<int>>(value::array()).has_value());
    CHECK(validate<std::vector<int>>(value::array({1, 2, 3})).has_value());
    CHECK(validate<std::vector<std::string>>(value::array({"a", "b"})).has_value());
    CHECK(validate<std::vector<std::optional<int>>>(value::array({1, nullptr, 3})).has_value());

    auto wrong_shape = validate<std::vector<int>>(value::object());
    CHECK(!wrong_shape.has_value());
    CHECK(mentions(wrong_shape.error(), "expected array"));

    auto element = validate<std::vector<int>>(value::array({1, "two", 3}));
    CHECK(!element.has_value());
    CHECK(mentions(element.error(), "[1]"));
    CHECK(mentions(element.error(), "expected integer"));

    auto nested = validate<std::vector<std::vector<int>>>(value::array({value::array({1}), value::array({2, "x"})}));
    CHECK(!nested.has_value());
    CHECK(mentions(nested.error(), "[1][1]"));
    CHECK(mentions(nested.error(), "expected integer"));

    value bad_point = user_doc;
    bad_point["points"][1]["x"] = "three";
    auto point_result = validate<user>(bad_point);
    CHECK(!point_result.has_value());
    CHECK(mentions(point_result.error(), "points[1].x"));
    CHECK(mentions(point_result.error(), "expected integer"));

    value bad_element = user_doc;
    bad_element["points"][0] = 7;
    auto element_result = validate<user>(bad_element);
    CHECK(!element_result.has_value());
    CHECK(mentions(element_result.error(), "points[0]"));
    CHECK(mentions(element_result.error(), "expected object"));
  }

  // -------------------------------------------------------------------------
  // std::array: exact length required
  // -------------------------------------------------------------------------
  {
    CHECK((validate<std::array<int, 3>>(value::array({1, 2, 3})).has_value()));
    CHECK((validate<std::array<int, 0>>(value::array()).has_value()));
    CHECK((validate<std::array<point, 2>>(document(R"([{"x":1,"y":2},{"x":3,"y":4}])")).has_value()));

    auto too_short = validate<std::array<int, 3>>(value::array({1, 2}));
    CHECK(!too_short.has_value());
    CHECK(mentions(too_short.error(), "expected array of length 3"));
    CHECK(mentions(too_short.error(), "got 2"));

    auto too_long = validate<std::array<int, 2>>(value::array({1, 2, 3}));
    CHECK(!too_long.has_value());
    CHECK(mentions(too_long.error(), "expected array of length 2"));

    auto not_array = validate<std::array<int, 3>>(value(nullptr));
    CHECK(!not_array.has_value());
    CHECK(mentions(not_array.error(), "expected array"));

    auto element = validate<std::array<int, 3>>(value::array({1, 2, "three"}));
    CHECK(!element.has_value());
    CHECK(mentions(element.error(), "[2]"));
    CHECK(mentions(element.error(), "expected integer"));

    value bad_scores = user_doc;
    bad_scores["scores"] = value::array({10, 20});
    auto scores_result = validate<user>(bad_scores);
    CHECK(!scores_result.has_value());
    CHECK(mentions(scores_result.error(), "scores"));
    CHECK(mentions(scores_result.error(), "expected array of length 3"));

    bad_scores["scores"] = value::array({10, "twenty", 30});
    auto scores_element = validate<user>(bad_scores);
    CHECK(!scores_element.has_value());
    CHECK(mentions(scores_element.error(), "scores[1]"));
  }

  // -------------------------------------------------------------------------
  // Missing required fields, including nested and vector-of-aggregate members
  // -------------------------------------------------------------------------
  {
    auto missing_y = validate<point>(document(R"({"x":1})"));
    CHECK(!missing_y.has_value());
    CHECK(mentions(missing_y.error(), "y: missing required field"));

    auto missing_x = validate<point>(document(R"({"y":2})"));
    CHECK(!missing_x.has_value());
    CHECK(mentions(missing_x.error(), "x: missing required field"));

    value missing_home = user_doc;
    missing_home.erase("home");
    auto home_result = validate<user>(missing_home);
    CHECK(!home_result.has_value());
    CHECK(mentions(home_result.error(), "home: missing required field"));

    value nested = user_doc;
    nested["home"].erase("zip");
    auto zip_result = validate<user>(nested);
    CHECK(!zip_result.has_value());
    CHECK(mentions(zip_result.error(), "home.zip: missing required field"));

    value point_element = user_doc;
    point_element["points"][0].erase("y");
    auto element_result = validate<user>(point_element);
    CHECK(!element_result.has_value());
    CHECK(mentions(element_result.error(), "points[0].y: missing required field"));
  }

  // -------------------------------------------------------------------------
  // Members with a default member initializer are optional by default
  // -------------------------------------------------------------------------
  {
    CHECK(validate<settings>(document(R"({"host":"api"})")).has_value());

    auto missing_host = validate<settings>(document(R"({"retries":5})"));
    CHECK(!missing_host.has_value());
    CHECK(mentions(missing_host.error(), "host: missing required field"));

    value no_level = user_doc;
    no_level.erase("level");
    CHECK(validate<user>(no_level).has_value());

    value no_optionals = user_doc;
    no_optionals.erase("nickname");
    no_optionals.erase("age");
    CHECK(validate<user>(no_optionals).has_value());
  }

  // -------------------------------------------------------------------------
  // Unknown object keys: rejected by default, accepted on request
  // -------------------------------------------------------------------------
  {
    value extra = user_doc;
    extra["extra"] = 1;
    auto rejected = validate<user>(extra);
    CHECK(!rejected.has_value());
    CHECK(mentions(rejected.error(), "unknown field 'extra'"));

    CHECK(validate<user>(extra, {.reject_unknown = false}).has_value());

    value nested_extra = user_doc;
    nested_extra["home"]["country"] = "DE";
    auto nested_result = validate<user>(nested_extra);
    CHECK(!nested_result.has_value());
    CHECK(mentions(nested_result.error(), "unknown field 'country'"));
    CHECK(mentions(nested_result.error(), "home"));

    value point_extra = user_doc;
    point_extra["points"][0]["z"] = 3;
    auto element_result = validate<user>(point_extra);
    CHECK(!element_result.has_value());
    CHECK(mentions(element_result.error(), "unknown field 'z'"));
    CHECK(mentions(element_result.error(), "points[0]"));

    CHECK(validate<point>(document(R"({"x":1,"y":2,"z":3})"), {.reject_unknown = false}).has_value());
  }

  // -------------------------------------------------------------------------
  // require_all: optional and defaulted members become required
  // -------------------------------------------------------------------------
  {
    value no_optionals = user_doc;
    no_optionals.erase("nickname");
    no_optionals.erase("age");
    CHECK(validate<user>(no_optionals).has_value());

    auto nickname_required = validate<user>(no_optionals, {.require_all = true});
    CHECK(!nickname_required.has_value());
    CHECK(mentions(nickname_required.error(), "nickname: missing required field"));

    value level_only = user_doc;
    level_only.erase("level");
    CHECK(validate<user>(level_only).has_value());
    auto level_required = validate<user>(level_only, {.require_all = true});
    CHECK(!level_required.has_value());
    CHECK(mentions(level_required.error(), "level: missing required field"));

    auto retries_required = validate<settings>(document(R"({"host":"api"})"), {.require_all = true});
    CHECK(!retries_required.has_value());
    CHECK(mentions(retries_required.error(), "retries: missing required field"));

    // require_all does not make unknown keys acceptable.
    value with_extra = user_doc;
    with_extra["extra"] = 1;
    auto both = validate<user>(with_extra, {.require_all = true});
    CHECK(!both.has_value());
    CHECK(mentions(both.error(), "unknown field 'extra'"));
  }

  // -------------------------------------------------------------------------
  // schema(): scalar and container shapes
  // -------------------------------------------------------------------------
  {
    CHECK_EQ(schema<bool>(), type_schema("boolean"));
    CHECK_EQ(schema<int>(), type_schema("integer"));
    CHECK_EQ(schema<std::uint64_t>(), type_schema("integer"));
    CHECK_EQ(schema<double>(), type_schema("number"));
    CHECK_EQ(schema<std::string>(), type_schema("string"));
    CHECK_EQ(schema<std::string_view>(), type_schema("string"));
    CHECK_EQ(schema<const char*>(), type_schema("string"));

    // json::value places no constraint: the empty schema.
    CHECK(schema<value>().is_object());
    CHECK_EQ(schema<value>().size(), std::size_t{0});

    value vector_schema = schema<std::vector<std::string>>();
    CHECK_EQ(vector_schema["type"], value("array"));
    CHECK_EQ(vector_schema["items"], type_schema("string"));

    value nested_vector_schema = schema<std::vector<std::vector<int>>>();
    CHECK_EQ(nested_vector_schema["type"], value("array"));
    CHECK_EQ(nested_vector_schema["items"]["type"], value("array"));
    CHECK_EQ(nested_vector_schema["items"]["items"]["type"], value("integer"));

    value array_schema = schema<std::array<point, 2>>();
    CHECK_EQ(array_schema["type"], value("array"));
    CHECK_EQ(array_schema["minItems"], value(2));
    CHECK_EQ(array_schema["maxItems"], value(2));
    CHECK_EQ(array_schema["items"]["type"], value("object"));
    CHECK_EQ(array_schema["items"]["properties"]["x"]["type"], value("integer"));
    CHECK_EQ(array_schema["items"]["required"], value::array({"x", "y"}));
    CHECK_EQ(array_schema["minItems"].get<int>(), 2);
  }

  // -------------------------------------------------------------------------
  // schema(): aggregates, nesting, required lists and additionalProperties
  // -------------------------------------------------------------------------
  {
    value point_schema = schema<point>();
    CHECK_EQ(point_schema["type"], value("object"));
    CHECK_EQ(point_schema["additionalProperties"], value(false));
    CHECK_EQ(point_schema["required"], value::array({"x", "y"}));
    CHECK_EQ(point_schema["properties"]["x"], type_schema("integer"));
    CHECK_EQ(point_schema["properties"]["y"], type_schema("integer"));
    CHECK_EQ(point_schema["properties"].size(), std::size_t{2});

    value user_schema = schema<user>();
    CHECK_EQ(user_schema["type"], value("object"));
    CHECK_EQ(user_schema["additionalProperties"], value(false));
    CHECK_EQ(user_schema["properties"].size(), std::size_t{10});
    CHECK_EQ(user_schema["properties"]["name"]["type"], value("string"));
    CHECK_EQ(user_schema["properties"]["id"]["type"], value("integer"));
    CHECK_EQ(user_schema["properties"]["active"]["type"], value("boolean"));
    CHECK_EQ(user_schema["properties"]["scores"]["type"], value("array"));
    CHECK_EQ(user_schema["required"],
             value::array({"name", "id", "active", "points", "scores", "favorite", "home"}));

    value home_schema = user_schema["properties"]["home"];
    CHECK_EQ(home_schema["type"], value("object"));
    CHECK_EQ(home_schema["properties"]["city"]["type"], value("string"));
    CHECK_EQ(home_schema["properties"]["zip"]["type"], value("integer"));
    CHECK_EQ(home_schema["required"], value::array({"city", "zip"}));

    value points_schema = user_schema["properties"]["points"];
    CHECK_EQ(points_schema["type"], value("array"));
    CHECK_EQ(points_schema["items"]["type"], value("object"));
    CHECK_EQ(points_schema["items"]["properties"]["x"]["type"], value("integer"));
    CHECK_EQ(points_schema["items"]["required"], value::array({"x", "y"}));
    CHECK_EQ(points_schema["items"]["additionalProperties"], value(false));

    // Members with default member initializers are not in "required".
    value settings_schema = schema<settings>();
    CHECK_EQ(settings_schema["required"], value::array({"host"}));
    CHECK_EQ(settings_schema["properties"].size(), std::size_t{2});
    CHECK_EQ(settings_schema["properties"]["retries"]["type"], value("integer"));

    // An aggregate with no data members still describes an object schema.
    value empty_schema = schema<empty>();
    CHECK_EQ(empty_schema["type"], value("object"));
    CHECK_EQ(empty_schema["properties"], value::object());
    CHECK_EQ(empty_schema["required"], value::array());
    CHECK_EQ(empty_schema["additionalProperties"], value(false));
  }

  // -------------------------------------------------------------------------
  // schema(): enums and optionals
  // -------------------------------------------------------------------------
  {
    value color_schema = schema<color>();
    CHECK_EQ(color_schema["type"], value("string"));
    CHECK_EQ(color_schema["enum"], value::array({"red", "green", "blue"}));
    CHECK(color_schema["enum"].is_array());
    CHECK_EQ(color_schema["enum"].size(), std::size_t{3});

    value optional_int = schema<std::optional<int>>();
    CHECK_EQ(optional_int.size(), std::size_t{1});
    CHECK(!optional_int.contains("type"));
    CHECK_EQ(optional_int["anyOf"].size(), std::size_t{2});
    CHECK_EQ(optional_int["anyOf"][0], type_schema("null"));
    CHECK_EQ(optional_int["anyOf"][1], type_schema("integer"));

    value optional_object = schema<std::optional<point>>();
    CHECK_EQ(optional_object["anyOf"][0]["type"], value("null"));
    CHECK_EQ(optional_object["anyOf"][1]["type"], value("object"));
    CHECK_EQ(optional_object["anyOf"][1]["properties"]["y"]["type"], value("integer"));

    // Optional members inside an aggregate use the same representation.
    value user_schema = schema<user>();
    CHECK_EQ(user_schema["properties"]["nickname"]["anyOf"][0]["type"], value("null"));
    CHECK_EQ(user_schema["properties"]["nickname"]["anyOf"][1]["type"], value("string"));
    CHECK_EQ(user_schema["properties"]["age"]["anyOf"][1]["type"], value("integer"));
    value color_optional = schema<std::optional<color>>();
    CHECK_EQ(color_optional["anyOf"][1]["enum"], value::array({"red", "green", "blue"}));

    value color_vector = schema<std::vector<color>>();
    CHECK_EQ(color_vector["type"], value("array"));
    CHECK_EQ(color_vector["items"]["enum"], value::array({"red", "green", "blue"}));
    CHECK_EQ(color_vector["items"]["type"], value("string"));
  }

  // -------------------------------------------------------------------------
  // schema() agrees with validation on the aggregate's required members
  // -------------------------------------------------------------------------
  {
    value user_schema = schema<user>();
    for (auto const& member : user_schema["required"]) {
      value doc = user_doc;
      doc.erase(member.get<std::string>());
      auto result = validate<user>(doc);
      CHECK(!result.has_value());
      CHECK(mentions(result.error(), "missing required field"));
    }

    // Everything not listed as required stays optional for validate().
    for (auto const& member : {"nickname", "age", "level"}) {
      value doc = user_doc;
      doc.erase(member);
      CHECK(validate<user>(doc).has_value());
    }

    CHECK_EQ(dump(schema<point>()["type"]), std::string{"\"object\""});
  }

  return tst::report("json_schema_test");
}
