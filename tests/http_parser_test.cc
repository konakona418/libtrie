#include "trie/http/parser.hh"
#include "trie/http/serializer.hh"

#include <string>
#include <string_view>

#include "harness.hh"

using trie::http::parse_status;
using trie::http::parsed_request;
using trie::http::parse_error;
using trie::http::request_parser;

int main() {
  {
    request_parser parser{};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;
    std::string_view wire = "GET /users/42?q=1 HTTP/1.1\r\nHost: example\r\nX-Test: yes\r\n\r\n";
    CHECK_EQ(parser.parse(wire, request, error, consumed), parse_status::complete);
    CHECK_EQ(request.m, trie::method::get);
    CHECK_EQ(request.target, std::string{"/users/42?q=1"});
    CHECK(request.keep_alive);
    CHECK_EQ(request.headers.size(), std::size_t{2});
    CHECK_EQ(request.header("host"), std::string_view{"example"});
    CHECK_EQ(request.header("X-TEST"), std::string_view{"yes"});
    CHECK_EQ(consumed, wire.size());
    CHECK(request.body.empty());
  }
  {
    request_parser parser{};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;
    std::string_view wire = "GET /partial HTTP/1.1\r\nHost: example\r\n";
    CHECK_EQ(parser.parse(wire, request, error, consumed), parse_status::incomplete);
    CHECK_EQ(parser.parse(wire.substr(0, 10), request, error, consumed), parse_status::incomplete);
  }
  {
    request_parser parser{};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;
    std::string_view wire = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    CHECK_EQ(parser.parse(wire, request, error, consumed), parse_status::complete);
    CHECK_EQ(request.m, trie::method::post);
    CHECK_EQ(request.body, std::string{"hello"});
    CHECK_EQ(consumed, wire.size());
  }
  {
    // Partial body: headers complete but body truncated.
    request_parser parser{};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;
    std::string_view wire = "POST /echo HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
    CHECK_EQ(parser.parse(wire, request, error, consumed), parse_status::incomplete);
  }
  {
    // Pipelined requests: only the first request is consumed.
    request_parser parser{};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;
    std::string_view wire =
        "GET /a HTTP/1.1\r\n\r\n"
        "GET /b HTTP/1.1\r\n\r\n";
    CHECK_EQ(parser.parse(wire, request, error, consumed), parse_status::complete);
    CHECK_EQ(request.target, std::string{"/a"});
    CHECK_EQ(consumed, std::string_view{"GET /a HTTP/1.1\r\n\r\n"}.size());
  }
  {
    // HTTP/1.0 default is close; explicit keep-alive is honoured.
    request_parser parser{};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;
    CHECK_EQ(parser.parse("GET / HTTP/1.0\r\n\r\n", request, error, consumed), parse_status::complete);
    CHECK(!request.keep_alive);
    CHECK_EQ(parser.parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", request, error, consumed),
             parse_status::complete);
    CHECK(request.keep_alive);
    CHECK_EQ(parser.parse("GET / HTTP/1.1\r\nConnection: close\r\n\r\n", request, error, consumed),
             parse_status::complete);
    CHECK(!request.keep_alive);
  }
  {
    request_parser parser{};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;
    CHECK_EQ(parser.parse("BROKEN\r\n\r\n", request, error, consumed), parse_status::error);
    CHECK_EQ(error.status, 400);
    CHECK_EQ(parser.parse("GET nope HTTP/1.1\r\n\r\n", request, error, consumed), parse_status::error);
    CHECK_EQ(error.status, 400);
    CHECK_EQ(parser.parse("GET / HTTP/9.9\r\n\r\n", request, error, consumed), parse_status::error);
    CHECK_EQ(error.status, 505);
    CHECK_EQ(parser.parse("BREW / HTTP/1.1\r\n\r\n", request, error, consumed), parse_status::error);
    CHECK_EQ(error.status, 501);
    CHECK_EQ(parser.parse("GET / HTTP/1.1\r\nBad Header\r\n\r\n", request, error, consumed), parse_status::error);
    CHECK_EQ(error.status, 400);
  }
  {
    // Limits.
    trie::http::parser_limits limits{};
    limits.max_header_bytes = 64;
    limits.max_body_bytes = 4;
    limits.max_target_bytes = 8;

    request_parser parser{limits};
    parsed_request request{};
    parse_error error{};
    std::size_t consumed = 0;

    CHECK_EQ(parser.parse("GET / HTTP/1.1\r\nX-Long: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
                          request, error, consumed),
             parse_status::error);
    CHECK_EQ(error.status, 431);
    CHECK_EQ(parser.parse("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", request, error, consumed),
             parse_status::error);
    CHECK_EQ(error.status, 413);
    CHECK_EQ(parser.parse("GET /a-very-long-target HTTP/1.1\r\n\r\n", request, error, consumed), parse_status::error);
    CHECK_EQ(error.status, 414);
  }
  {
    // Serializer basics.
    trie::http::response response{};
    response.status_code = 200;
    response.body = "hello";
    response.set_header("Content-Type", "text/plain");
    response.set_header("Content-Length", "999"); // ignored, generated instead
    auto wire = trie::http::serialize_response(response, true, false);
    CHECK(wire.starts_with("HTTP/1.1 200 OK\r\n"));
    CHECK(wire.find("Content-Length: 5\r\n") != std::string::npos);
    CHECK(wire.find("Content-Length: 999") == std::string::npos);
    CHECK(wire.find("Connection: close") == std::string::npos);
    CHECK(wire.ends_with("\r\n\r\nhello"));

    auto closing = trie::http::serialize_response(response, false, false);
    CHECK(closing.find("Connection: close\r\n") != std::string::npos);

    auto head = trie::http::serialize_response(response, true, true);
    CHECK(head.ends_with("\r\n\r\n"));
    CHECK(head.find("Content-Length: 5\r\n") != std::string::npos);
  }
  return tst::report("http_parser_test");
}
