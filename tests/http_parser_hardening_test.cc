// Hardening, mutation-fuzz and request-smuggling tests for
// trie::http::request_parser.
//
// request_parser::parse is a pure incremental function: callers append bytes to
// a buffer and retry until it reports complete or error. These tests pin the
// invariants a caller relies on, probe adversarial and ambiguity-exploiting
// inputs, and deliberately document places where the parser is currently
// permissive. Nothing here changes the parser; hardening gaps are marked
// "Documented gap" and reported separately rather than silently ignored.

#include "trie/http/parser.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "harness.hh"

using trie::http::parse_error;
using trie::http::parse_status;
using trie::http::parsed_request;
using trie::http::parser_limits;
using trie::http::request_parser;

namespace {

// Convenience owner for a parser plus its output parameters, so each test case
// can just call parse(wire) and inspect request/error/consumed.
struct parser_fixture {
  explicit parser_fixture(parser_limits limits = {}) : parser(limits) {}

  parse_status parse(std::string_view wire) {
    error = {};
    consumed = 0;
    return parser.parse(wire, request, error, consumed);
  }

  request_parser parser;
  parsed_request request{};
  parse_error error{};
  std::size_t consumed = 0;
};

// Every status the parser is allowed to report as an error. Anything else means
// a caller could not map the failure onto a sane HTTP response.
bool sane_error_status(int status) {
  switch (status) {
    case 400:
      return true; // bad request
    case 413:
      return true; // payload too large
    case 414:
      return true; // uri too long
    case 431:
      return true; // request header fields too large
    case 501:
      return true; // not implemented
    case 505:
      return true; // http version not supported
    default:
      return false;
  }
}

void print_escaped(std::string_view bytes, std::size_t limit = 96) {
  std::printf("\"");
  for (std::size_t i = 0; i < bytes.size() && i < limit; ++i) {
    auto c = static_cast<unsigned char>(bytes[i]);
    switch (c) {
      case '\r':
        std::printf("\\r");
        break;
      case '\n':
        std::printf("\\n");
        break;
      case '\0':
        std::printf("\\0");
        break;
      case '"':
        std::printf("\\\"");
        break;
      case '\\':
        std::printf("\\\\");
        break;
      default:
        if (c >= 0x20 && c < 0x7f) {
          std::printf("%c", static_cast<char>(c));
        } else {
          std::printf("\\x%02x", c);
        }
    }
  }
  if (bytes.size() > limit) std::printf("...(%zu bytes)", bytes.size());
  std::printf("\"");
}

std::size_t fuzz_payloads = 0;
std::size_t fuzz_prefixes = 0;
int fuzz_failures = 0;

void fuzz_fail(
  char const* what,
  std::uint32_t seed,
  std::size_t payload,
  std::size_t prefix,
  std::string const& detail,
  std::string_view wire
) {
  ++fuzz_failures;
  if (fuzz_failures > 10) return; // keep diagnostic output bounded
  std::printf("FUZZ FAIL [%s] seed=%u payload=%zu prefix=%zu: %s wire=", what, seed, payload, prefix, detail.c_str());
  print_escaped(wire);
  std::printf("\n");
}

// Invariants the incremental parser must uphold for any buffer, valid or not:
//  - consumed never exceeds the buffer size;
//  - incomplete/error always report consumed == 0;
//  - error always carries a sane HTTP status and a message;
//  - complete reports consumed > 0, re-parsing the remainder terminates in a
//    known state, re-parsing exactly `consumed` bytes is idempotent, and
//    stopping one byte short is never already complete.
bool check_invariants(request_parser const& parser, std::string_view buffer, std::string& detail) {
  ++fuzz_prefixes;

  parsed_request request{};
  parse_error error{};
  std::size_t consumed = 0;
  auto status = parser.parse(buffer, request, error, consumed);

  if (consumed > buffer.size()) {
    detail = "consumed > buffer.size()";
    return false;
  }

  if (status == parse_status::incomplete) {
    if (consumed != 0) {
      detail = "incomplete with consumed != 0";
      return false;
    }
    return true;
  }

  if (status == parse_status::error) {
    if (consumed != 0) {
      detail = "error with consumed != 0";
      return false;
    }
    if (!sane_error_status(error.status)) {
      detail = "error.status outside sane set: " + std::to_string(error.status);
      return false;
    }
    if (error.message.empty()) {
      detail = "error without message";
      return false;
    }
    return true;
  }

  // complete
  if (consumed == 0) {
    detail = "complete with consumed == 0";
    return false;
  }

  // Re-parsing the remainder must not crash and must stay in range.
  parsed_request rest_request{};
  parse_error rest_error{};
  std::size_t rest_consumed = 0;
  (void) parser.parse(buffer.substr(consumed), rest_request, rest_error, rest_consumed);
  if (rest_consumed > buffer.size() - consumed) {
    detail = "remainder parse consumed out of range";
    return false;
  }

  // The prefix that ends one byte before `consumed` must not already complete.
  parsed_request short_request{};
  parse_error short_error{};
  std::size_t short_consumed = 0;
  auto short_status = parser.parse(buffer.substr(0, consumed - 1), short_request, short_error, short_consumed);
  if (short_status == parse_status::complete) {
    detail = "prefix of consumed boundary is already complete";
    return false;
  }

  // Re-parsing exactly the consumed bytes must reproduce the same result.
  parsed_request exact_request{};
  parse_error exact_error{};
  std::size_t exact_consumed = 0;
  auto exact_status = parser.parse(buffer.substr(0, consumed), exact_request, exact_error, exact_consumed);
  if (exact_status != parse_status::complete || exact_consumed != consumed) {
    detail = "parse of consumed prefix is not idempotent";
    return false;
  }
  return true;
}

bool check_determinism(request_parser const& parser, std::string_view buffer, std::string& detail) {
  parsed_request a{};
  parsed_request b{};
  parse_error error_a{};
  parse_error error_b{};
  std::size_t consumed_a = 0;
  std::size_t consumed_b = 0;
  auto status_a = parser.parse(buffer, a, error_a, consumed_a);
  auto status_b = parser.parse(buffer, b, error_b, consumed_b);
  if (status_a != status_b || consumed_a != consumed_b) {
    detail = "parse status/consumed is not deterministic";
    return false;
  }
  if (status_a == parse_status::error && error_a.status != error_b.status) {
    detail = "error status is not deterministic";
    return false;
  }
  if (
    status_a == parse_status::complete &&
    (a.m != b.m || a.target != b.target || a.headers != b.headers || a.body != b.body || a.keep_alive != b.keep_alive)
  ) {
    detail = "complete parse output is not deterministic";
    return false;
  }
  return true;
}

// Random payload biased towards the bytes that matter to an HTTP parser:
// CR, LF, NUL and assorted binary, with protocol tokens sprinkled in so real
// header structure appears too.
std::string random_payload(std::mt19937& rng) {
  std::uniform_int_distribution<std::size_t> length_dist(0, 2048);
  std::uniform_int_distribution<int> byte_dist(0, 255);
  std::uniform_int_distribution<int> kind_dist(0, 99);
  static constexpr std::array<std::string_view, 8> tokens =
    {"\r\n", "\r\n\r\n", "GET ", "/", "HTTP/1.1", "Content-Length: ", "Transfer-Encoding: chunked", "Host: x"};

  std::size_t length = length_dist(rng);
  std::string payload(length, '\0');
  for (std::size_t i = 0; i < length; ++i) {
    int kind = kind_dist(rng);
    if (kind < 12) {
      payload[i] = '\r';
    } else if (kind < 24) {
      payload[i] = '\n';
    } else if (kind < 30) {
      payload[i] = '\0';
    } else {
      payload[i] = static_cast<char>(byte_dist(rng));
    }
  }

  int token_count = kind_dist(rng) % 8;
  for (int t = 0; t < token_count && length > 0; ++t) {
    auto token = tokens[static_cast<std::size_t>(kind_dist(rng)) % tokens.size()];
    std::size_t at = std::uniform_int_distribution<std::size_t>(0, length - 1)(rng);
    for (std::size_t k = 0; k < token.size() && at + k < length; ++k) payload[at + k] = token[k];
  }
  return payload;
}

// A valid request is used as the mutation seed for the second fuzz pass.
std::string mutate_valid_request(std::mt19937& rng, std::string wire) {
  std::uniform_int_distribution<std::size_t> position(0, wire.size() - 1);
  std::uniform_int_distribution<int> kind_dist(0, 99);
  std::size_t mutations = 1 + static_cast<std::size_t>(kind_dist(rng) % 8);
  for (std::size_t m = 0; m < mutations; ++m) {
    std::size_t at = position(rng);
    int kind = kind_dist(rng);
    char replacement = '\0';
    if (kind < 15) {
      replacement = '\r';
    } else if (kind < 30) {
      replacement = '\n';
    } else if (kind < 40) {
      replacement = '\0';
    } else if (kind < 50) {
      replacement = ' ';
    } else if (kind < 60) {
      replacement = ':';
    } else if (kind < 70) {
      replacement = '/';
    } else if (kind < 85) {
      replacement = static_cast<char>('A' + kind_dist(rng) % 26);
    } else {
      replacement = static_cast<char>(kind_dist(rng) % 256);
    }
    wire[at] = replacement;
  }
  // Occasionally truncate so the header block/body boundary is cut mid-stream.
  if (kind_dist(rng) % 4 == 0) {
    std::size_t cut = std::uniform_int_distribution<std::size_t>(0, wire.size())(rng);
    wire.resize(cut);
  }
  return wire;
}

} // namespace

int main() {
  // -------------------------------------------------------------------------
  // 1. Request smuggling: Transfer-Encoding / Content-Length handling
  // -------------------------------------------------------------------------
  {
    parser_fixture f{};

    // Chunked is not implemented at all; the parser refuses the transfer
    // coding instead of silently treating the chunk stream as body.
    CHECK_EQ(
      f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
      parse_status::error
    );
    CHECK_EQ(f.error.status, 501);

    // TE + CL in either order is rejected, so a front-end/back-end pair cannot
    // desynchronise on the body length.
    CHECK_EQ(
      f.parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello"),
      parse_status::error
    );
    CHECK_EQ(f.error.status, 501);
    CHECK_EQ(
      f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nhello"),
      parse_status::error
    );
    CHECK_EQ(f.error.status, 501);

    // Every non-identity transfer coding is unsupported, singly or in a list.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 501);
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 501);
    CHECK_EQ(
      f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n"),
      parse_status::error
    );
    CHECK_EQ(f.error.status, 501);

    // Trailing/leading OWS is trimmed before the identity comparison, so
    // whitespace cannot smuggle a coding past the check.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding:   chunked  \r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 501);
  }
  {
    parser_fixture f{};

    // Hardened: any Transfer-Encoding is rejected (obsolete "identity"
    // included); TE + Content-Length is a request-smuggling vector.
    CHECK_EQ(
      f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nhello"),
      parse_status::error
    );
    CHECK_EQ(f.error.status, 400);

    // Identity matching is case-insensitive and is still rejected.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nTransfer-Encoding: Identity\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
  }
  {
    parser_fixture f{};

    // Conflicting duplicate Content-Length is rejected: classic CL.CL
    // desynchronisation.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\ncontent-length: 6\r\n\r\nhello"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Identical duplicate Content-Length is accepted (RFC 9110 allows treating
    // an identical repeated field as a single value).
    CHECK_EQ(
      f.parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"),
      parse_status::complete
    );
    CHECK_EQ(f.request.body, std::string{"hello"});

    // Duplicate Content-Length values must match textually: "5" vs "05" is
    // rejected (strict CL.CL defence).
    CHECK_EQ(
      f.parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 05\r\n\r\nhello"),
      parse_status::error
    );
    CHECK_EQ(f.error.status, 400);
  }
  {
    parser_fixture f{};
    auto expect_error = [&](std::string_view wire, int status) {
      auto got = f.parse(wire);
      if (got != parse_status::error || f.error.status != status) {
        std::printf(
          "  Content-Length case: expected error %d, got status %d (http %d) for wire=",
          status,
          static_cast<int>(got),
          f.error.status
        );
        print_escaped(wire);
        std::printf("\n");
      }
      CHECK_EQ(got, parse_status::error);
      CHECK_EQ(f.error.status, status);
    };

    // Malformed Content-Length values are 400. from_chars rejects a leading
    // sign, embedded separators, decimals, hex and an empty value; out-of-range
    // digit strings fail with result_out_of_range.
    expect_error("POST /x HTTP/1.1\r\nContent-Length: +5\r\n\r\nhello", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: 5,5\r\n\r\n", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: 5 5\r\n\r\n", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: 5.0\r\n\r\n", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: \r\n\r\n", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n", 400);
    expect_error("POST /x HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n", 400);

    // OWS around the value is trimmed (legal field-value padding), so " 5"
    // and "5 " are accepted as a Content-Length of 5. Documented current
    // behaviour; the field value itself is what RFC 9112 allows to be padded.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length:  5\r\n\r\nhello"), parse_status::complete);
    CHECK_EQ(f.request.body, std::string{"hello"});
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length:\t5\r\n\r\nhello"), parse_status::complete);
    CHECK_EQ(f.request.body, std::string{"hello"});

    // SIZE_MAX parses (from_chars succeeds) and is then rejected as too large:
    // 413, not 400.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 413);
  }

  // -------------------------------------------------------------------------
  // 2. Line endings, CR, NUL and obs-fold
  // -------------------------------------------------------------------------
  {
    parser_fixture f{};

    // Bare-LF line endings are rejected immediately as malformed headers.
    CHECK_EQ(f.parse("GET / HTTP/1.1\nHost: x\n\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("GET / HTTP/1.1\nHost: x\n\nGET /again HTTP/1.1"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nHost: x\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    parser_limits tight{};
    tight.max_header_bytes = 8;
    parser_fixture g{tight};
    CHECK_EQ(g.parse("GET / HTTP/1.1\nHost: x\n\n"), parse_status::error);
    CHECK_EQ(g.error.status, 400);
  }
  {
    parser_fixture f{};

    // Hardened: bare CR in a header value is rejected.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX-Test: a\rb\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Hardened: bare CR in a header name is rejected.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX\rY: v\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Hardened: NUL in a header value is rejected.
    std::string nul_value = "GET / HTTP/1.1\r\nX-Test: a";
    nul_value.push_back('\0');
    nul_value += "b\r\n\r\n";
    CHECK_EQ(f.parse(nul_value), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Hardened: NUL in a header name is rejected.
    std::string nul_name = "GET / HTTP/1.1\r\nX";
    nul_name.push_back('\0');
    nul_name += "Y: v\r\n\r\n";
    CHECK_EQ(f.parse(nul_name), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Hardened: NUL in the request target is rejected.
    std::string nul_target = "GET /a";
    nul_target.push_back('\0');
    nul_target += "b HTTP/1.1\r\n\r\n";
    CHECK_EQ(f.parse(nul_target), parse_status::error);
    CHECK_EQ(f.error.status, 400);
  }
  {
    parser_fixture f{};

    // obs-fold continuation lines are rejected (no colon, or a space in the
    // name), which is the safe behaviour for request smuggling.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX-Test: a\r\n b\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX-Test: a\r\n X-Next: b\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Whitespace before the colon is a malformed header name.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX-Test : v\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX\tTest: v\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Empty header name, missing colon and empty value.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\n: value\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nBad Header\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX-Empty:\r\n\r\n"), parse_status::complete);
    CHECK_EQ(f.request.header("X-Empty"), std::string_view{});
  }

  // -------------------------------------------------------------------------
  // 3. Header-block and body limits
  // -------------------------------------------------------------------------
  {
    parser_limits limits{};
    limits.max_header_bytes = 4096;
    parser_fixture f{limits};

    // Many headers inside the byte cap are accepted; there is no separate
    // header-count limit, only the total byte cap.
    std::string many = "GET / HTTP/1.1\r\n";
    for (int i = 0; i < 200; ++i) {
      many += "X-";
      many += std::to_string(i);
      many += ": v\r\n";
    }
    many += "\r\n";
    CHECK(many.size() < limits.max_header_bytes);
    CHECK_EQ(f.parse(many), parse_status::complete);
    CHECK_EQ(f.request.headers.size(), std::size_t{200});

    // The same header block over a small cap is 431.
    parser_limits small{};
    small.max_header_bytes = 128;
    parser_fixture g{small};
    CHECK_EQ(g.parse(many), parse_status::error);
    CHECK_EQ(g.error.status, 431);
  }
  {
    // Complete head exactly at the cap is accepted; one byte over is 431.
    std::string_view wire = "GET / HTTP/1.1\r\n\r\n";
    parser_limits exact{};
    exact.max_header_bytes = wire.size();
    parser_fixture f{exact};
    CHECK_EQ(f.parse(wire), parse_status::complete);

    parser_limits one_short{};
    one_short.max_header_bytes = wire.size() - 1;
    parser_fixture g{one_short};
    CHECK_EQ(g.parse(wire), parse_status::error);
    CHECK_EQ(g.error.status, 431);
  }
  {
    // Without CRLFCRLF the header block is bounded by max_header_bytes:
    // exactly at the cap -> incomplete; one byte over -> 431.
    parser_limits tight{};
    tight.max_header_bytes = 16;
    parser_fixture f{tight};
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\n"), parse_status::incomplete); // exactly 16 bytes
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nX"), parse_status::error);     // 17 bytes
    CHECK_EQ(f.error.status, 431);
  }
  {
    parser_limits limits{};
    limits.max_body_bytes = 4;
    parser_fixture f{limits};

    // Body exactly at the cap is accepted; one over is 413.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd"), parse_status::complete);
    CHECK_EQ(f.request.body, std::string{"abcd"});
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde"), parse_status::error);
    CHECK_EQ(f.error.status, 413);

    // The oversized body is rejected as soon as the headers are in, before the
    // body bytes are buffered.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 413);
  }
  {
    parser_fixture f{};
    // Default 1 MiB body cap boundaries.
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 1048576\r\n\r\n"), parse_status::incomplete);
    CHECK_EQ(f.parse("POST /x HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 413);
  }
  {
    parser_limits limits{};
    limits.max_target_bytes = 8;
    parser_fixture f{limits};

    // Target exactly at the cap is accepted; one over is 414.
    CHECK_EQ(f.parse("GET /1234567 HTTP/1.1\r\n\r\n"), parse_status::complete);
    CHECK_EQ(f.request.target, std::string{"/1234567"});
    CHECK_EQ(f.parse("GET /12345678 HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 414);
  }
  {
    // Default 8 KiB target cap boundaries (the head stays under the 16 KiB cap).
    parser_fixture f{};
    std::string exact_target = "/";
    exact_target.append(8191, 'a'); // 8192 bytes
    std::string wire = "GET ";
    wire += exact_target;
    wire += " HTTP/1.1\r\n\r\n";
    CHECK_EQ(f.parse(wire), parse_status::complete);
    CHECK_EQ(f.request.target.size(), std::size_t{8192});

    std::string long_target = exact_target;
    long_target.push_back('a'); // 8193 bytes
    wire = "GET ";
    wire += long_target;
    wire += " HTTP/1.1\r\n\r\n";
    CHECK_EQ(f.parse(wire), parse_status::error);
    CHECK_EQ(f.error.status, 414);
  }

  // -------------------------------------------------------------------------
  // 4. Method / target / version edge cases
  // -------------------------------------------------------------------------
  {
    parser_fixture f{};

    // Methods are matched case-sensitively against the fixed table: "get" is
    // an unknown method -> 501, not 400.
    CHECK_EQ(f.parse("get / HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 501);
    CHECK_EQ(f.parse("Get / HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 501);

    // Unknown methods are 501, including extensions like CONNECT (which is not
    // in the supported table).
    CHECK_EQ(f.parse("BREW / HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 501);
    CHECK_EQ(f.parse("CONNECT host:443 HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 501);

    // Every supported method parses.
    for (std::string_view method : {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}) {
      std::string wire = std::string{method} + " / HTTP/1.1\r\n\r\n";
      CHECK_EQ(f.parse(wire), parse_status::complete);
    }
  }
  {
    parser_fixture f{};

    // Unsupported HTTP/* versions are 505.
    for (std::string_view version : {"HTTP/9.9", "HTTP/2.0", "HTTP/1.2", "HTTP/0.9", "HTTP/1.10"}) {
      std::string wire = "GET / " + std::string{version} + "\r\n\r\n";
      CHECK_EQ(f.parse(wire), parse_status::error);
      CHECK_EQ(f.error.status, 505);
    }

    // Malformed version tokens (lowercase, trailing space) are 400.
    for (std::string_view version : {"http/1.1", "HTTP/1.1 "}) {
      std::string wire = "GET / " + std::string{version} + "\r\n\r\n";
      CHECK_EQ(f.parse(wire), parse_status::error);
      CHECK_EQ(f.error.status, 400);
    }

    // Missing version token -> 400.
    CHECK_EQ(f.parse("GET / \r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Only one space in the request line -> malformed request line, 400.
    CHECK_EQ(f.parse("GET /\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Extra spaces around the target/version -> 400.
    CHECK_EQ(f.parse("GET /x  HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
  }
  {
    parser_fixture f{};

    // Absolute-form is rejected: only origin-form targets starting with '/' are
    // accepted (documented current behaviour; RFC 9112 permits absolute-form
    // for requests to proxies).
    CHECK_EQ(f.parse("GET http://host/path HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Asterisk-form (OPTIONS *) is rejected; current behaviour is 400 even
    // though RFC 9110 defines it for server-wide OPTIONS.
    CHECK_EQ(f.parse("OPTIONS * HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Empty target, leading whitespace and tab separators are malformed.
    CHECK_EQ(f.parse("GET  HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    // A leading space makes the method text empty -> 400.
    CHECK_EQ(f.parse(" GET / HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
    CHECK_EQ(f.parse("GET\t/ HTTP/1.1\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);

    // Origin-form targets are preserved verbatim, including path, query and
    // percent-encoding.
    CHECK_EQ(f.parse("GET /a/b?c=d&e=%20 HTTP/1.1\r\n\r\n"), parse_status::complete);
    CHECK_EQ(f.request.target, std::string{"/a/b?c=d&e=%20"});
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\n\r\n"), parse_status::complete);
    CHECK_EQ(f.request.target, std::string{"/"});

    // An empty header block (CRLFCRLF with no request line) is malformed.
    CHECK_EQ(f.parse("\r\n\r\n"), parse_status::error);
    CHECK_EQ(f.error.status, 400);
  }
  {
    parser_fixture f{};
    // Documented current behaviour: the parser does not require a Host header
    // on HTTP/1.1; the server transports enforce that later.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\n\r\n"), parse_status::complete);
    CHECK_EQ(f.request.headers.size(), std::size_t{0});
  }

  // -------------------------------------------------------------------------
  // 5. Connection semantics / pipelining / consumed boundaries
  // -------------------------------------------------------------------------
  {
    parser_fixture f{};

    CHECK_EQ(f.parse("GET / HTTP/1.1\r\n\r\n"), parse_status::complete);
    CHECK(f.request.keep_alive);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nConnection: close\r\n\r\n"), parse_status::complete);
    CHECK(!f.request.keep_alive);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nConnection: Close\r\n\r\n"), parse_status::complete);
    CHECK(!f.request.keep_alive);
    // close wins over keep-alive in the same field.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nConnection: keep-alive, close\r\n\r\n"), parse_status::complete);
    CHECK(!f.request.keep_alive);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n"), parse_status::complete);
    CHECK(f.request.keep_alive);

    // HTTP/1.0 defaults to close; an explicit keep-alive token opts in.
    CHECK_EQ(f.parse("GET / HTTP/1.0\r\n\r\n"), parse_status::complete);
    CHECK(!f.request.keep_alive);
    CHECK_EQ(f.parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"), parse_status::complete);
    CHECK(f.request.keep_alive);
    CHECK_EQ(f.parse("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n"), parse_status::complete);
    CHECK(f.request.keep_alive);
    CHECK_EQ(f.parse("GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n"), parse_status::complete);
    CHECK(!f.request.keep_alive);
  }
  {
    parser_fixture f{};
    std::string_view wire = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
                            "POST /b HTTP/1.1\r\nContent-Length: 3\r\n\r\nxyz"
                            "GET /c HTTP/1.1\r\n\r\n";

    // Only the first message is consumed.
    CHECK_EQ(f.parse(wire), parse_status::complete);
    CHECK_EQ(f.request.target, std::string{"/a"});
    std::size_t first = f.consumed;
    CHECK_EQ(first, std::string_view{"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"}.size());

    // The remainder is a clean pipeline boundary, including a body-bearing
    // request followed immediately by another request.
    std::string_view rest = wire.substr(first);
    CHECK_EQ(f.parse(rest), parse_status::complete);
    CHECK_EQ(f.request.target, std::string{"/b"});
    CHECK_EQ(f.request.body, std::string{"xyz"});
    rest = rest.substr(f.consumed);
    CHECK_EQ(f.parse(rest), parse_status::complete);
    CHECK_EQ(f.request.target, std::string{"/c"});
    CHECK_EQ(f.consumed, rest.size());

    // Parsing is pure: the same buffer yields the same message boundaries.
    CHECK_EQ(f.parse(wire), parse_status::complete);
    CHECK_EQ(f.request.target, std::string{"/a"});
    CHECK_EQ(f.consumed, first);

    // Garbage after a valid request is only discovered by the next parse, and
    // only once it forms a complete (terminated) header block. A partial
    // fragment such as "@@@" stays incomplete because the parser cannot tell it
    // apart from a message that is still arriving.
    parser_fixture g{};
    std::string_view trailing_garbage = "GET / HTTP/1.1\r\n\r\n@@\r\n\r\n";
    CHECK_EQ(g.parse(trailing_garbage), parse_status::complete);
    CHECK_EQ(g.parse(trailing_garbage.substr(g.consumed)), parse_status::error);
    CHECK_EQ(g.error.status, 400);
    CHECK_EQ(g.parse("GET / HTTP/1.1\r\n\r\n@@@"), parse_status::complete);
    CHECK_EQ(g.parse("@@@"), parse_status::incomplete);
  }
  {
    parser_fixture f{};
    // Remaining bytes shorter than a full head stay incomplete, never advance.
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\n\r"), parse_status::incomplete);
    CHECK_EQ(f.consumed, std::size_t{0});
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\n\r\nX"), parse_status::complete);
    CHECK_EQ(f.parse("GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab"), parse_status::incomplete);
    CHECK_EQ(f.consumed, std::size_t{0});
  }

  // -------------------------------------------------------------------------
  // 6. Chunked bodies / Expect
  // -------------------------------------------------------------------------
  {
    parser_fixture f{};

    // Expect: 100-continue is ignored by the parser: the request is parsed
    // with its body immediately. The caller is responsible for interim
    // responses (server transports currently send none). Documented current
    // behaviour.
    std::string wire = "POST /x HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello";
    CHECK_EQ(f.parse(wire), parse_status::complete);
    CHECK_EQ(f.request.body, std::string{"hello"});
    CHECK_EQ(f.request.header("Expect"), std::string_view{"100-continue"});
    CHECK(f.request.keep_alive);
    CHECK_EQ(f.consumed, wire.size());

    // No chunked support: without Transfer-Encoding the parser stops at the
    // header terminator and leaves the chunk stream in the buffer, where it is
    // treated as the next pipelined message and fails as malformed.
    parser_fixture g{};
    std::string_view chunked_body = "POST /x HTTP/1.1\r\nHost: x\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    CHECK_EQ(g.parse(chunked_body), parse_status::complete);
    CHECK(g.request.body.empty());
    CHECK_EQ(g.consumed, std::string_view{"POST /x HTTP/1.1\r\nHost: x\r\n\r\n"}.size());
    CHECK_EQ(g.parse(chunked_body.substr(g.consumed)), parse_status::error);
    CHECK_EQ(g.error.status, 400);
  }

  // -------------------------------------------------------------------------
  // 7. Deterministic prefix fuzz over a known adversarial corpus
  // -------------------------------------------------------------------------
  {
    static constexpr std::array<std::string_view, 16> corpus = {
      "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
      "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
      "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
      "POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
      "POST /x HTTP/1.1\r\nContent-Length: +5\r\n\r\n",
      "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
      "GET / HTTP/9.9\r\n\r\n",
      "OPTIONS * HTTP/1.1\r\n\r\n",
      "GET http://host/path HTTP/1.1\r\n\r\n",
      "GET / HTTP/1.1\r\nX-Test: a\rb\r\n\r\n",
      "GET / HTTP/1.1\r\nX-Test: a\r\n b\r\n\r\n",
      "GET / HTTP/1.1\nHost: x\n\n",
      "GET / HTTP/1.1\r\n\r\n",
      "GET / HTTP/1.1\r\nBad Header\r\n\r\n",
      "GET / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
      "GET  HTTP/1.1\r\n\r\n",
    };

    request_parser parser{};
    for (std::size_t index = 0; index < corpus.size(); ++index) {
      std::string_view wire = corpus[index];
      for (std::size_t prefix = 0; prefix <= wire.size(); ++prefix) {
        std::string_view buffer = wire.substr(0, prefix);
        std::string detail;
        if (!check_invariants(parser, buffer, detail)) fuzz_fail("corpus-prefix", 0, index, prefix, detail, buffer);
      }
      std::string detail;
      if (!check_determinism(parser, wire, detail))
        fuzz_fail("corpus-determinism", 0, index, wire.size(), detail, wire);
    }
  }

  // -------------------------------------------------------------------------
  // 8. Random-byte mutation fuzz: 20 seeds x 200 payloads up to 2 KiB
  // -------------------------------------------------------------------------
  {
    request_parser parser{};
    for (std::uint32_t seed = 0; seed < 20; ++seed) {
      std::mt19937 rng(seed * 2654435761u + 12345u);
      for (std::size_t index = 0; index < 200; ++index) {
        std::string payload = random_payload(rng);
        ++fuzz_payloads;
        for (std::size_t prefix = 0; prefix <= payload.size(); ++prefix) {
          std::string_view buffer = payload;
          buffer = buffer.substr(0, prefix);
          std::string detail;
          if (!check_invariants(parser, buffer, detail))
            fuzz_fail("random-prefix", seed, index, prefix, detail, buffer);
        }
        std::string detail;
        if (!check_determinism(parser, payload, detail))
          fuzz_fail("random-determinism", seed, index, payload.size(), detail, payload);
      }
    }
  }

  // -------------------------------------------------------------------------
  // 9. Valid-request mutation fuzz: 20 seeds x 50 mutated valid requests
  // -------------------------------------------------------------------------
  {
    static constexpr std::array<std::string_view, 5> valid_requests = {
      "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
      "POST /echo HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
      "GET /a/b?c=d HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
      "PUT /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
      "HEAD / HTTP/1.1\r\nX-Test: yes\r\n\r\n",
    };

    request_parser parser{};
    parser_fixture sanity{};
    for (std::string_view wire : valid_requests) CHECK_EQ(sanity.parse(wire), parse_status::complete);

    for (std::uint32_t seed = 0; seed < 20; ++seed) {
      std::mt19937 rng(seed * 2246822519u + 98765u);
      for (std::size_t index = 0; index < 50; ++index) {
        std::string mutated = mutate_valid_request(rng, std::string{valid_requests[index % valid_requests.size()]});
        ++fuzz_payloads;
        for (std::size_t prefix = 0; prefix <= mutated.size(); ++prefix) {
          std::string_view buffer = mutated;
          buffer = buffer.substr(0, prefix);
          std::string detail;
          if (!check_invariants(parser, buffer, detail))
            fuzz_fail("mutation-prefix", seed, index, prefix, detail, buffer);
        }
        std::string detail;
        if (!check_determinism(parser, mutated, detail))
          fuzz_fail("mutation-determinism", seed, index, mutated.size(), detail, mutated);
      }
    }
  }

  std::printf(
    "fuzz: %zu payloads, %zu prefix parses, %d invariant failures\n",
    fuzz_payloads,
    fuzz_prefixes,
    fuzz_failures
  );
  CHECK_EQ(fuzz_failures, 0);

  return tst::report("http_parser_hardening_test");
}
