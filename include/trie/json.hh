#pragma once

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <meta>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

// nlohmann-json 3.12.0 is vendored under vendor/nlohmann (include <nlohmann/json.hpp>).
//
// JSON_NOEXCEPTION disables the library's own throwing: every exported function
// below either calls parse() with allow_exceptions = false and checks
// is_discarded(), or queries the value with an is_*() predicate before any
// typed accessor. Bad input therefore always travels through std::expected and
// never reaches JSON_THROW (which expands to std::abort when exceptions are
// disabled). dump() uses error_handler_t::replace so invalid UTF-8 cannot
// abort either.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#define JSON_NOEXCEPTION 1
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

namespace trie::json {

using value = nlohmann::json;

// Position information for conversion failures. `offset` is a zero-based byte
// offset into the parsed text for syntax errors; conversion errors (type
// mismatches, out-of-range numbers, ...) set it to 0 because the nlohmann DOM
// no longer carries source positions.
struct error {
  std::size_t offset = 0;
  std::string message{};

  friend bool operator==(error const&, error const&) = default;
};

namespace detail {

template <class>
inline constexpr bool always_false_v = false;

template <class T>
struct is_optional : std::false_type {};
template <class T>
struct is_optional<std::optional<T>> : std::true_type {
  using value_type = T;
};

template <class T>
inline constexpr bool is_optional_v = is_optional<std::remove_cv_t<T>>::value;

template <class T>
struct is_vector : std::false_type {};
template <class T, class Alloc>
struct is_vector<std::vector<T, Alloc>> : std::true_type {
  using value_type = T;
};

template <class T>
inline constexpr bool is_vector_v = is_vector<std::remove_cv_t<T>>::value;

template <class T>
struct is_std_array : std::false_type {};
template <class T, std::size_t N>
struct is_std_array<std::array<T, N>> : std::true_type {
  using value_type = T;
  static constexpr std::size_t size = N;
};

template <class T>
inline constexpr bool is_std_array_v = is_std_array<std::remove_cv_t<T>>::value;

template <class T>
inline constexpr bool is_char_array_v =
    std::is_array_v<T> && std::is_same_v<std::remove_cv_t<std::remove_extent_t<T>>, char>;

// Public non-static data members of an aggregate, consumed directly in
// constant expressions. GCC 16 cannot use arrays of std::meta::info as
// template arguments, hence the consteval accessor instead of a variable.
template <class T>
consteval auto nonstatic_members() {
  return std::define_static_array(
      std::meta::nonstatic_data_members_of(^^T, std::meta::access_context::unprivileged()));
}

// ---------------------------------------------------------------------------
// Error reporting
// ---------------------------------------------------------------------------

inline std::string mismatch_message(std::string_view expected, value const& v) {
  return std::string{"expected "} + std::string{expected} + ", got " + v.type_name();
}

inline error mismatch_error(std::string_view expected, value const& v) {
  return error{0, mismatch_message(expected, v)};
}

template <class T>
inline std::expected<T, error> fail(std::string message) {
  return std::unexpected(error{0, std::move(message)});
}

// ---------------------------------------------------------------------------
// Syntax-error position recovery
// ---------------------------------------------------------------------------

// A no-op SAX handler whose only job is to record where the lexer stopped.
// nlohmann's parse(..., allow_exceptions = false) reports failure as a
// discarded value without a position; re-running the document through
// sax_parse() (which reports errors through this callback instead of throwing)
// recovers the position and the human-readable message.
class error_probe final : public nlohmann::json_sax<value> {
 public:
  using string_t = typename nlohmann::json_sax<value>::string_t;
  using binary_t = typename nlohmann::json_sax<value>::binary_t;
  using number_integer_t = typename nlohmann::json_sax<value>::number_integer_t;
  using number_unsigned_t = typename nlohmann::json_sax<value>::number_unsigned_t;
  using number_float_t = typename nlohmann::json_sax<value>::number_float_t;

  std::size_t position = 0;
  std::string message{};

  bool null() override { return true; }
  bool boolean(bool) override { return true; }
  bool number_integer(number_integer_t) override { return true; }
  bool number_unsigned(number_unsigned_t) override { return true; }
  bool number_float(number_float_t, const string_t&) override { return true; }
  bool string(string_t&) override { return true; }
  bool binary(binary_t&) override { return true; }
  bool start_object(std::size_t) override { return true; }
  bool key(string_t&) override { return true; }
  bool end_object() override { return true; }
  bool start_array(std::size_t) override { return true; }
  bool end_array() override { return true; }

  bool parse_error(std::size_t error_position, std::string const& last_token,
                   nlohmann::detail::exception const& ex) override {
    position = error_position;
    message = ex.what();
    if (message.empty()) {
      message = "invalid JSON";
      if (!last_token.empty()) {
        message += " near '";
        message += last_token;
        message += '\'';
      }
    }
    return false;
  }
};

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

template <class E>
value enum_to_json(E e) {
  template for (constexpr auto enumerator :
                std::define_static_array(std::meta::enumerators_of(^^E))) {
    if (e == [:enumerator:]) return value(std::string{std::meta::identifier_of(enumerator)});
  }
  // Values that do not name an enumerator (e.g. a cast) fall back to the
  // underlying integer so nothing is silently lost.
  return value(static_cast<std::int64_t>(e));
}

template <class E>
std::expected<E, error> enum_from_json(value const& v) {
  if (!v.is_string()) return std::unexpected(mismatch_error("string", v));
  std::string_view const name = v.get_ref<const std::string&>();
  template for (constexpr auto enumerator :
                std::define_static_array(std::meta::enumerators_of(^^E))) {
    if (std::meta::identifier_of(enumerator) == name) return E([:enumerator:]);
  }
  return std::unexpected(error{0, std::string{"unknown enumerator '"} + std::string{name} + "'"});
}

} // namespace detail

// ---------------------------------------------------------------------------
// Compile-time capabilities
// ---------------------------------------------------------------------------

// True when to_json/from_json can handle T: fundamentals, strings, enums,
// json::value itself, std::optional, std::vector, std::array and aggregate
// classes whose (public) non-static data members are all serializable.
//
// Used by the router headers to constrain body parameters and responses, so it
// must stay self-contained (no dependency on trie/detail/reflect.hh).
template <class T>
consteval bool serializable() {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, value>) {
    return true;
  } else if constexpr (std::is_same_v<U, bool> || std::is_integral_v<U> || std::is_floating_point_v<U>) {
    return true;
  } else if constexpr (std::is_same_v<U, std::string> || std::is_same_v<U, std::string_view> ||
                       std::is_same_v<U, const char*> || detail::is_char_array_v<U>) {
    return true;
  } else if constexpr (std::is_enum_v<U>) {
    return true;
  } else if constexpr (detail::is_optional_v<U>) {
    return serializable<typename detail::is_optional<U>::value_type>();
  } else if constexpr (detail::is_vector_v<U>) {
    return serializable<typename detail::is_vector<U>::value_type>();
  } else if constexpr (detail::is_std_array_v<U>) {
    return serializable<typename detail::is_std_array<U>::value_type>();
  } else if constexpr (std::is_class_v<U>) {
    if constexpr (!std::is_aggregate_v<U>) {
      return false;
    } else {
      bool ok = true;
      template for (constexpr auto member : detail::nonstatic_members<U>()) {
        ok = ok && serializable<typename [:std::meta::type_of(member):]>();
      }
      return ok;
    }
  } else {
    return false;
  }
}

// True when T would store a view into the parsed document (string_view,
// const char*, or any aggregate/container holding one). parse_as() rejects such
// types with a static_assert because the document it parses does not outlive
// the call.
template <class T>
consteval bool borrows_parsed_storage() {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, value>) {
    return false;
  } else if constexpr (std::is_same_v<U, std::string_view> || std::is_same_v<U, const char*> ||
                       std::is_same_v<U, char*>) {
    return true;
  } else if constexpr (detail::is_optional_v<U>) {
    return borrows_parsed_storage<typename detail::is_optional<U>::value_type>();
  } else if constexpr (detail::is_vector_v<U>) {
    return borrows_parsed_storage<typename detail::is_vector<U>::value_type>();
  } else if constexpr (detail::is_std_array_v<U>) {
    return borrows_parsed_storage<typename detail::is_std_array<U>::value_type>();
  } else if constexpr (std::is_class_v<U>) {
    if constexpr (!std::is_aggregate_v<U>) {
      return false;
    } else {
      bool borrows = false;
      template for (constexpr auto member : detail::nonstatic_members<U>()) {
        borrows = borrows || borrows_parsed_storage<typename [:std::meta::type_of(member):]>();
      }
      return borrows;
    }
  } else {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Document entry points
// ---------------------------------------------------------------------------

// Parses a complete JSON document. Never throws: syntax errors are returned as
// an error carrying the byte offset where the lexer stopped.
inline std::expected<value, error> parse(std::string_view text) {
  if (text.empty()) return std::unexpected(error{0, "invalid JSON: empty input"});

  value parsed = value::parse(text.begin(), text.end(), nullptr, false);
  if (!parsed.is_discarded()) return parsed;

  detail::error_probe probe;
  value::sax_parse(text.begin(), text.end(), &probe);
  // nlohmann positions are one-based columns; expose a zero-based byte offset.
  std::size_t const offset = probe.position == 0 ? 0 : probe.position - 1;
  return std::unexpected(error{offset, probe.message.empty() ? "invalid JSON" : probe.message});
}

// Compact serialization. Invalid UTF-8 is replaced with U+FFFD instead of
// aborting; a discarded value is rendered as null.
inline std::string dump(value const& v) {
  if (v.is_discarded()) return "null";
  return v.dump(-1, ' ', false, value::error_handler_t::replace);
}

// ---------------------------------------------------------------------------
// C++ -> JSON
// ---------------------------------------------------------------------------

template <class T>
value to_json(T const& v) {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, value>) {
    return v;
  } else if constexpr (std::is_same_v<U, bool>) {
    return value(v);
  } else if constexpr (std::is_integral_v<U>) {
    if constexpr (std::is_signed_v<U>) return value(static_cast<std::int64_t>(v));
    else return value(static_cast<std::uint64_t>(v));
  } else if constexpr (std::is_floating_point_v<U>) {
    return value(static_cast<double>(v));
  } else if constexpr (std::is_same_v<U, std::string>) {
    return value(v);
  } else if constexpr (std::is_same_v<U, std::string_view>) {
    return value(std::string{v});
  } else if constexpr (std::is_same_v<U, const char*>) {
    return v == nullptr ? value(nullptr) : value(v);
  } else if constexpr (detail::is_char_array_v<U>) {
    std::size_t length = 0;
    while (length < std::extent_v<U> && v[length] != '\0') ++length;
    return value(std::string(v, length));
  } else if constexpr (std::is_enum_v<U>) {
    return detail::enum_to_json(v);
  } else if constexpr (detail::is_optional_v<U>) {
    if (!v.has_value()) return value(nullptr);
    return to_json(*v);
  } else if constexpr (detail::is_vector_v<U>) {
    value out = value::array();
    for (auto const& element : v) out.push_back(to_json(element));
    return out;
  } else if constexpr (detail::is_std_array_v<U>) {
    value out = value::array();
    for (auto const& element : v) out.push_back(to_json(element));
    return out;
  } else if constexpr (std::is_class_v<U>) {
    if constexpr (!std::is_aggregate_v<U>) {
      static_assert(detail::always_false_v<U>,
                    "to_json: class types must be aggregates with public non-static data members");
    } else {
      value out = value::object();
      template for (constexpr auto member : detail::nonstatic_members<U>()) {
        out[std::string{std::meta::identifier_of(member)}] = to_json(v.[:member:]);
      }
      return out;
    }
  } else {
    static_assert(detail::always_false_v<U>, "to_json: type is not JSON-serializable");
  }
}

// ---------------------------------------------------------------------------
// JSON -> C++
// ---------------------------------------------------------------------------

template <class T>
std::expected<T, error> from_json(value const& v) {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, value>) {
    return v;
  } else if constexpr (std::is_same_v<U, bool>) {
    if (!v.is_boolean()) return std::unexpected(detail::mismatch_error("boolean", v));
    return v.get<bool>();
  } else if constexpr (std::is_integral_v<U>) {
    if (v.is_number_unsigned()) {
      std::uint64_t const number = v.get<std::uint64_t>();
      if (!std::in_range<U>(number)) return detail::fail<U>("integer out of range");
      return static_cast<U>(number);
    }
    if (v.is_number_integer()) {
      std::int64_t const number = v.get<std::int64_t>();
      if (!std::in_range<U>(number)) return detail::fail<U>("integer out of range");
      return static_cast<U>(number);
    }
    if (v.is_number_float()) {
      double const number = v.get<double>();
      if (!std::isfinite(number) || std::trunc(number) != number)
        return detail::fail<U>("number is not an integer");
      if (number < static_cast<double>(std::numeric_limits<std::int64_t>::min()) ||
          number > static_cast<double>(std::numeric_limits<std::int64_t>::max()))
        return detail::fail<U>("integer out of range");
      auto const integer = static_cast<std::int64_t>(number);
      if (!std::in_range<U>(integer)) return detail::fail<U>("integer out of range");
      return static_cast<U>(integer);
    }
    return std::unexpected(detail::mismatch_error("integer", v));
  } else if constexpr (std::is_floating_point_v<U>) {
    double number = 0.0;
    if (v.is_number_unsigned()) number = static_cast<double>(v.get<std::uint64_t>());
    else if (v.is_number_integer()) number = static_cast<double>(v.get<std::int64_t>());
    else if (v.is_number_float()) number = v.get<double>();
    else return std::unexpected(detail::mismatch_error("number", v));
    U const converted = static_cast<U>(number);
    if (std::isfinite(number) && !std::isfinite(converted))
      return detail::fail<U>("number out of range");
    return converted;
  } else if constexpr (std::is_same_v<U, std::string>) {
    if (!v.is_string()) return std::unexpected(detail::mismatch_error("string", v));
    return v.get<std::string>();
  } else if constexpr (std::is_same_v<U, std::string_view>) {
    if (!v.is_string()) return std::unexpected(detail::mismatch_error("string", v));
    return std::string_view{v.get_ref<const std::string&>()};
  } else if constexpr (std::is_same_v<U, const char*>) {
    if (!v.is_string()) return std::unexpected(detail::mismatch_error("string", v));
    return v.get_ref<const std::string&>().c_str();
  } else if constexpr (std::is_enum_v<U>) {
    return detail::enum_from_json<U>(v);
  } else if constexpr (detail::is_optional_v<U>) {
    if (v.is_null()) return U{};
    using inner_type = typename detail::is_optional<U>::value_type;
    auto inner = from_json<inner_type>(v);
    if (!inner) return std::unexpected(inner.error());
    return U{std::move(*inner)};
  } else if constexpr (detail::is_vector_v<U>) {
    if (!v.is_array()) return std::unexpected(detail::mismatch_error("array", v));
    U out{};
    for (auto const& element : v) {
      auto converted = from_json<typename detail::is_vector<U>::value_type>(element);
      if (!converted) return std::unexpected(converted.error());
      out.push_back(std::move(*converted));
    }
    return out;
  } else if constexpr (detail::is_std_array_v<U>) {
    constexpr std::size_t size = detail::is_std_array<U>::size;
    if (!v.is_array()) return std::unexpected(detail::mismatch_error("array", v));
    if (v.size() != size)
      return detail::fail<U>(std::string{"expected array of length "} + std::to_string(size) + ", got " +
                             std::to_string(v.size()));
    U out{};
    for (std::size_t i = 0; i < size; ++i) {
      auto converted = from_json<typename detail::is_std_array<U>::value_type>(v[i]);
      if (!converted) return std::unexpected(converted.error());
      out[i] = std::move(*converted);
    }
    return out;
  } else if constexpr (std::is_class_v<U>) {
    if constexpr (!std::is_aggregate_v<U>) {
      static_assert(detail::always_false_v<U>,
                    "from_json: class types must be aggregates with public non-static data members");
    } else {
      static_assert(std::is_default_constructible_v<U>,
                    "from_json: aggregate types must be default-constructible");
      if (!v.is_object()) return std::unexpected(detail::mismatch_error("object", v));
      U out{};
      for (auto it = v.begin(); it != v.end(); ++it) {
        std::string_view const key = it.key();
        bool matched = false;
        template for (constexpr auto member : detail::nonstatic_members<U>()) {
          using member_type = typename [:std::meta::type_of(member):];
          if constexpr (std::is_array_v<member_type>) {
            static_assert(detail::always_false_v<member_type>,
                          "from_json: raw array data members are not supported; use std::array");
          } else if constexpr (!std::is_assignable_v<member_type&, member_type&&>) {
            static_assert(detail::always_false_v<member_type>,
                          "from_json: data members must be assignable");
          } else {
            if (!matched && key == std::meta::identifier_of(member)) {
              auto converted = from_json<member_type>(*it);
              if (!converted) return std::unexpected(converted.error());
              out.[:member:] = std::move(*converted);
              matched = true;
            }
          }
        }
      }
      return out;
    }
  } else {
    static_assert(detail::always_false_v<U>, "from_json: type is not JSON-deserializable");
  }
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

// Options for validate<T>().
struct validate_options {
  // Reject object keys that do not name a public non-static data member of the
  // reflected aggregate type.
  bool reject_unknown = true;
  // Treat every aggregate member as required, including std::optional members
  // and members with a default member initializer. When false (the default) a
  // member is only required when it has no default member initializer and is
  // not a std::optional.
  bool require_all = false;
};

namespace detail {

inline std::string join_path(std::string_view base, std::string_view key) {
  std::string out{base};
  if (!out.empty()) out.push_back('.');
  out += key;
  return out;
}

inline std::string index_path(std::string_view base, std::size_t index) {
  std::string out{base};
  out.push_back('[');
  out += std::to_string(index);
  out.push_back(']');
  return out;
}

// Prefixes `message` with the location `path`; a root-level failure keeps the
// bare message. Errors never carry a source offset because validation works on
// an already parsed document.
inline std::unexpected<error> validation_error(std::string_view path, std::string message) {
  if (!path.empty()) {
    message.insert(0, ": ");
    message.insert(0, path);
  }
  return std::unexpected(error{0, std::move(message)});
}

// Validates `v` as a value of type T, reporting failures relative to `path`
// (empty at the root, then "member", "member.member", "items[3]", ...).
//
// Scalar validation delegates to from_json(), so the accepted-value rules
// (integral-valued floats for integers, range checks, enumerator names, ...)
// are exactly the conversion rules exposed by the rest of this header.
template <class T>
std::expected<void, error> validate_impl(value const& v, validate_options options, std::string_view path) {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, value>) {
    return {};
  } else if constexpr (std::is_same_v<U, bool> || std::is_integral_v<U> || std::is_floating_point_v<U> ||
                       std::is_same_v<U, std::string> || std::is_same_v<U, std::string_view> ||
                       std::is_same_v<U, const char*>) {
    auto converted = from_json<U>(v);
    if (!converted) return validation_error(path, converted.error().message);
    return {};
  } else if constexpr (std::is_enum_v<U>) {
    auto converted = enum_from_json<U>(v);
    if (!converted) return validation_error(path, converted.error().message);
    return {};
  } else if constexpr (is_optional_v<U>) {
    if (v.is_null()) return {};
    using inner_type = typename is_optional<U>::value_type;
    return validate_impl<inner_type>(v, options, path);
  } else if constexpr (is_vector_v<U>) {
    if (!v.is_array()) return validation_error(path, mismatch_message("array", v));
    using element_type = typename is_vector<U>::value_type;
    for (std::size_t i = 0; i < v.size(); ++i) {
      auto checked = validate_impl<element_type>(v[i], options, index_path(path, i));
      if (!checked) return checked;
    }
    return {};
  } else if constexpr (is_std_array_v<U>) {
    constexpr std::size_t size = is_std_array<U>::size;
    if (!v.is_array()) return validation_error(path, mismatch_message("array", v));
    if (v.size() != size)
      return validation_error(path, std::string{"expected array of length "} + std::to_string(size) + ", got " +
                                        std::to_string(v.size()));
    using element_type = typename is_std_array<U>::value_type;
    for (std::size_t i = 0; i < size; ++i) {
      auto checked = validate_impl<element_type>(v[i], options, index_path(path, i));
      if (!checked) return checked;
    }
    return {};
  } else if constexpr (std::is_class_v<U>) {
    if constexpr (!std::is_aggregate_v<U>) {
      static_assert(always_false_v<U>,
                    "validate: class types must be aggregates with public non-static data members");
    } else {
      if (!v.is_object()) return validation_error(path, mismatch_message("object", v));

      for (auto it = v.begin(); it != v.end(); ++it) {
        std::string_view const key = it.key();
        bool matched = false;
        template for (constexpr auto member : nonstatic_members<U>()) {
          using member_type = typename [:std::meta::type_of(member):];
          if constexpr (std::is_array_v<member_type>) {
            static_assert(always_false_v<member_type>,
                          "validate: raw array data members are not supported; use std::array");
          } else {
            if (!matched && key == std::meta::identifier_of(member)) {
              auto checked = validate_impl<member_type>(*it, options, join_path(path, key));
              if (!checked) return checked;
              matched = true;
            }
          }
        }
        if (!matched && options.reject_unknown)
          return validation_error(path, std::string{"unknown field '"} + std::string{key} + "'");
      }

      // report a missing required field, using the field path so the message
      // points at exactly where the value is absent.
      template for (constexpr auto member : nonstatic_members<U>()) {
        using member_type = typename [:std::meta::type_of(member):];
        constexpr bool naturally_required =
            !std::meta::has_default_member_initializer(member) && !is_optional_v<member_type>;
        std::string_view const name = std::meta::identifier_of(member);
        if (!v.contains(name) && (options.require_all || naturally_required))
          return validation_error(join_path(path, name), "missing required field");
      }
      return {};
    }
  } else {
    static_assert(always_false_v<U>, "validate: type is not JSON-validatable");
  }
}

// ---------------------------------------------------------------------------
// Schema generation
// ---------------------------------------------------------------------------

inline value schema_type(std::string_view type) {
  value out = value::object();
  out["type"] = std::string{type};
  return out;
}

// A JSON-Schema (draft-07-ish) description of T. Objects list every member
// under "properties", forbid unknown keys via "additionalProperties": false and
// advertise the same naturally-required members that validate<T>() enforces
// with its default options: no default member initializer and not std::optional.
template <class T>
value schema_impl() {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, value>) {
    // json::value accepts anything; the empty schema is the draft-07 spelling.
    return value::object();
  } else if constexpr (std::is_same_v<U, bool>) {
    return schema_type("boolean");
  } else if constexpr (std::is_integral_v<U>) {
    return schema_type("integer");
  } else if constexpr (std::is_floating_point_v<U>) {
    return schema_type("number");
  } else if constexpr (std::is_same_v<U, std::string> || std::is_same_v<U, std::string_view> ||
                       std::is_same_v<U, const char*>) {
    return schema_type("string");
  } else if constexpr (std::is_enum_v<U>) {
    value out = schema_type("string");
    value names = value::array();
    template for (constexpr auto enumerator : std::define_static_array(std::meta::enumerators_of(^^U))) {
      names.push_back(std::string{std::meta::identifier_of(enumerator)});
    }
    out["enum"] = std::move(names);
    return out;
  } else if constexpr (is_optional_v<U>) {
    using inner_type = typename is_optional<U>::value_type;
    value alternatives = value::array();
    alternatives.push_back(schema_type("null"));
    alternatives.push_back(schema_impl<inner_type>());
    value out = value::object();
    out["anyOf"] = std::move(alternatives);
    return out;
  } else if constexpr (is_vector_v<U>) {
    value out = schema_type("array");
    out["items"] = schema_impl<typename is_vector<U>::value_type>();
    return out;
  } else if constexpr (is_std_array_v<U>) {
    constexpr std::size_t size = is_std_array<U>::size;
    value out = schema_type("array");
    out["items"] = schema_impl<typename is_std_array<U>::value_type>();
    out["minItems"] = size;
    out["maxItems"] = size;
    return out;
  } else if constexpr (std::is_class_v<U>) {
    if constexpr (!std::is_aggregate_v<U>) {
      static_assert(always_false_v<U>,
                    "schema: class types must be aggregates with public non-static data members");
    } else {
      value properties = value::object();
      value required = value::array();
      template for (constexpr auto member : nonstatic_members<U>()) {
        using member_type = typename [:std::meta::type_of(member):];
        if constexpr (std::is_array_v<member_type>) {
          static_assert(always_false_v<member_type>,
                        "schema: raw array data members are not supported; use std::array");
        } else {
          std::string const name{std::meta::identifier_of(member)};
          properties[name] = schema_impl<member_type>();
          constexpr bool naturally_required =
              !std::meta::has_default_member_initializer(member) && !is_optional_v<member_type>;
          if (naturally_required) required.push_back(name);
        }
      }
      value out = schema_type("object");
      out["properties"] = std::move(properties);
      out["required"] = std::move(required);
      out["additionalProperties"] = false;
      return out;
    }
  } else {
    static_assert(always_false_v<U>, "schema: type is not JSON-serializable");
  }
}

} // namespace detail

// Validates `v` as a T without converting it. Failures are reported through
// std::expected; their message carries the dotted/indexed path of the offending
// value ("address.zip: expected string", "items[2].name: missing required
// field", "color: unknown enumerator 'purple'", ...).
template <class T>
std::expected<void, error> validate(value const& v, validate_options options = {}) {
  return detail::validate_impl<std::remove_cvref_t<T>>(v, options, std::string_view{});
}

// Generates a JSON-Schema-like description of T: an object schema with
// "properties", "required" and "additionalProperties": false for aggregates,
// "type": "array" with "items" (and "minItems"/"maxItems" for std::array), an
// "enum" of enumerator names, and "anyOf": [null, T] for std::optional.
template <class T>
value schema() {
  return detail::schema_impl<std::remove_cvref_t<T>>();
}

// ---------------------------------------------------------------------------
// One-shot convenience
// ---------------------------------------------------------------------------

template <class T>
std::expected<T, error> parse_as(std::string_view text) {
  static_assert(!borrows_parsed_storage<T>(),
                "parse_as: T would hold views into the parsed document; use from_json with a live value");
  auto parsed = parse(text);
  if (!parsed) return std::unexpected(parsed.error());
  return from_json<T>(*parsed);
}

} // namespace trie::json
