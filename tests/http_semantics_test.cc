// HTTP semantics tests: status/reason phrase coverage, response header
// injection defense, HEAD -> GET fallback, and automatic OPTIONS.
#include "trie/trie.hh"

#include <string>
#include <string_view>

#include "harness.hh"

namespace {

using trie::http::serialize_response;

struct semantics_api {
  [[=trie::get("/thing")]] std::string thing(trie::http::response& response) {
    response.set_header("X-Thing", "yes");
    return "thing-body";
  }

  [[=trie::get("/mixed")]] std::string mixed_get() { return "mixed-get"; }

  [[=trie::post("/mixed")]] std::string mixed_post([[=trie::body]] std::string_view body) {
    return std::string(body);
  }

  [[=trie::post("/submit")]] std::string submit() { return "submitted"; }

  [[=trie::put("/put-only")]] std::string put_only() { return "put"; }

  // Explicit HEAD and GET handlers for the same path: HEAD must win.
  [[=trie::get("/both")]] std::string both_get() { return "get-body"; }

  [[=trie::head("/both")]] void both_head(trie::http::response& response) {
    response.set_header("X-Handler", "head");
    response.body = "head-body";
  }

  // Lets a test observe which method the handler was dispatched as.
  [[=trie::get("/seen-method")]] std::string seen_method(trie::http::request_view const& request) {
    return std::string(trie::http::method_name(request.m));
  }

  [[=trie::get("/capability")]] std::string capability_get() { return "auto"; }

  [[=trie::options("/capability")]] trie::http::status capability_options(trie::http::response& response) {
    response.set_header("X-Options", "explicit");
    return trie::http::status::accepted;
  }
};

struct status_case {
  trie::http::status code;
  std::string_view phrase;
};

// One entry per enumerator: reason_phrase must know every officially added code.
constexpr status_case status_cases[] = {
    {trie::http::status::ok, "OK"},
    {trie::http::status::created, "Created"},
    {trie::http::status::accepted, "Accepted"},
    {trie::http::status::no_content, "No Content"},
    {trie::http::status::bad_request, "Bad Request"},
    {trie::http::status::unauthorized, "Unauthorized"},
    {trie::http::status::forbidden, "Forbidden"},
    {trie::http::status::not_found, "Not Found"},
    {trie::http::status::method_not_allowed, "Method Not Allowed"},
    {trie::http::status::request_timeout, "Request Timeout"},
    {trie::http::status::conflict, "Conflict"},
    {trie::http::status::payload_too_large, "Payload Too Large"},
    {trie::http::status::uri_too_long, "URI Too Long"},
    {trie::http::status::unprocessable_content, "Unprocessable Content"},
    {trie::http::status::too_many_requests, "Too Many Requests"},
    {trie::http::status::request_header_fields_too_large, "Request Header Fields Too Large"},
    {trie::http::status::internal_server_error, "Internal Server Error"},
    {trie::http::status::not_implemented, "Not Implemented"},
    {trie::http::status::bad_gateway, "Bad Gateway"},
    {trie::http::status::service_unavailable, "Service Unavailable"},
    {trie::http::status::gateway_timeout, "Gateway Timeout"},
    {trie::http::status::http_version_not_supported, "HTTP Version Not Supported"},
};

void test_reason_phrases() {
  for (auto const& entry : status_cases) {
    int code = static_cast<int>(entry.code);
    CHECK_EQ(trie::http::reason_phrase(code), entry.phrase);
    CHECK(trie::http::reason_phrase(code) != std::string_view{"Unknown"});
  }
  // The newly added codes must keep their canonical numeric values.
  CHECK_EQ(static_cast<int>(trie::http::status::forbidden), 403);
  CHECK_EQ(static_cast<int>(trie::http::status::request_timeout), 408);
  CHECK_EQ(static_cast<int>(trie::http::status::unprocessable_content), 422);
  CHECK_EQ(static_cast<int>(trie::http::status::too_many_requests), 429);
  CHECK_EQ(static_cast<int>(trie::http::status::bad_gateway), 502);
  CHECK_EQ(static_cast<int>(trie::http::status::service_unavailable), 503);
  CHECK_EQ(static_cast<int>(trie::http::status::gateway_timeout), 504);
  // Unknown codes still fall back to a placeholder rather than an empty phrase.
  CHECK_EQ(trie::http::reason_phrase(599), std::string_view{"Unknown"});
}

void test_header_injection() {
  {
    trie::http::response response{};
    response.body = "hello";
    response.set_header("Content-Type", "text/plain");
    // The injected CRLF would otherwise split into a second header line.
    response.set_header("X-Test", "ok\r\nInjected: yes");
    auto wire = serialize_response(response, true, false);
    auto header_block = wire.substr(0, wire.find("\r\n\r\n"));
    CHECK(header_block.find("Injected") == std::string_view::npos);
    CHECK(header_block.find("X-Test") == std::string_view::npos);
    CHECK(header_block.find("Content-Type: text/plain\r\n") != std::string_view::npos);
    // Header block is intact and the body still follows it.
    CHECK(wire.ends_with("\r\n\r\nhello"));
    CHECK_EQ(header_block.find("\r\nInjected"), std::string_view::npos);
  }
  {
    // Valid values and names are still emitted (positive control).
    trie::http::response response{};
    response.body = "x";
    response.set_header("X-Test", "ok");
    response.set_header("X-Token-Chars", "!#$%&'*+-.^_`|~");
    auto wire = serialize_response(response, true, false);
    CHECK(wire.find("X-Test: ok\r\n") != std::string::npos);
    CHECK(wire.find("X-Token-Chars: !#$%&'*+-.^_`|~\r\n") != std::string::npos);
  }
  {
    // Header names must be non-empty RFC 7230 tokens.
    trie::http::response response{};
    response.body = "x";
    response.set_header("", "empty-name");
    response.set_header("Bad Name", "space");
    response.set_header("Bad:Name", "colon");
    response.set_header("Bad\r\nName", "crlf");
    response.set_header("Bad/Name", "slash");
    response.set_header("X-Good", "kept");
    auto wire = serialize_response(response, true, false);
    CHECK(wire.find("empty-name") == std::string::npos);
    CHECK(wire.find("Bad Name") == std::string::npos);
    CHECK(wire.find("Bad:Name") == std::string::npos);
    CHECK(wire.find("Bad\r\nName") == std::string::npos);
    CHECK(wire.find("Bad/Name") == std::string::npos);
    CHECK(wire.find("X-Good: kept\r\n") != std::string::npos);
  }
  {
    // Header values must not contain CR, LF or NUL.
    trie::http::response response{};
    response.body = "x";
    response.set_header("X-LF", "a\nb");
    response.set_header("X-CR", "a\rb");
    response.set_header("X-NUL", std::string{"a\0b", 3});
    response.set_header("X-Ok", "a\tb");
    auto wire = serialize_response(response, true, false);
    CHECK(wire.find("X-LF") == std::string::npos);
    CHECK(wire.find("X-CR") == std::string::npos);
    CHECK(wire.find("X-NUL") == std::string::npos);
    CHECK(wire.find("X-Ok: a\tb\r\n") != std::string::npos);
  }
  {
    // Generated Content-Length / Connection win over user-supplied ones.
    trie::http::response response{};
    response.body = "hello";
    response.set_header("Content-Length", "999");
    response.set_header("Connection", "keep-alive");
    auto wire = serialize_response(response, true, false);
    CHECK(wire.find("Content-Length: 5\r\n") != std::string::npos);
    CHECK(wire.find("Content-Length: 999") == std::string::npos);
    CHECK(wire.find("Connection:") == std::string::npos);
    auto closing = serialize_response(response, false, false);
    CHECK(closing.find("Connection: close\r\n") != std::string::npos);
  }
  {
    // HEAD responses keep the GET Content-Length but omit the body.
    trie::http::response response{};
    response.body = "hello";
    auto head = serialize_response(response, true, true);
    CHECK(head.ends_with("\r\n\r\n"));
    CHECK(head.find("Content-Length: 5\r\n") != std::string::npos);
    CHECK(head.find("hello") == std::string::npos);
    auto full = serialize_response(response, true, false);
    CHECK(full.ends_with("\r\n\r\nhello"));
  }
}

void test_head_fallback(trie::server<semantics_api>& srv) {
  {
    auto get = srv.dispatch(trie::method::get, "/thing");
    auto head = srv.dispatch(trie::method::head, "/thing");
    CHECK_EQ(get.status_code, 200);
    CHECK_EQ(head.status_code, 200);
    // dispatch keeps the GET body; the listener suppresses it at serialization.
    CHECK_EQ(head.body, get.body);
    CHECK_EQ(head.header("x-thing"), std::string_view{"yes"});
    auto wire = serialize_response(head, true, true);
    CHECK(wire.find("thing-body") == std::string::npos);
    CHECK(wire.find("Content-Length: 10\r\n") != std::string::npos);
  }
  {
    // The GET handler observes a GET request, per RFC 9110 (HEAD == GET minus body).
    auto head = srv.dispatch(trie::method::head, "/seen-method");
    CHECK_EQ(head.status_code, 200);
    CHECK_EQ(head.body, std::string{"GET"});
  }
  {
    // A GET + POST path falls back to the GET handler for HEAD.
    auto head = srv.dispatch(trie::method::head, "/mixed");
    CHECK_EQ(head.status_code, 200);
    CHECK_EQ(head.body, std::string{"mixed-get"});
  }
  {
    // No GET route: HEAD on a POST-only path is 405, not a fallback.
    auto head = srv.dispatch(trie::method::head, "/submit");
    CHECK_EQ(head.status_code, 405);
    CHECK_EQ(head.header("allow"), std::string_view{"POST"});
  }
  {
    auto head = srv.dispatch(trie::method::head, "/put-only");
    CHECK_EQ(head.status_code, 405);
    CHECK_EQ(head.header("allow"), std::string_view{"PUT"});
  }
  {
    auto head = srv.dispatch(trie::method::head, "/nothing/here");
    CHECK_EQ(head.status_code, 404);
  }
  {
    // An explicit HEAD route wins over the GET fallback.
    auto head = srv.dispatch(trie::method::head, "/both");
    CHECK_EQ(head.status_code, 200);
    CHECK_EQ(head.header("x-handler"), std::string_view{"head"});
    CHECK_EQ(head.body, std::string{"head-body"});
    auto get = srv.dispatch(trie::method::get, "/both");
    CHECK_EQ(get.body, std::string{"get-body"});
  }
}

void test_options(trie::server<semantics_api>& srv) {
  {
    // GET + POST: automatic OPTIONS, HEAD implied by GET, no duplicates.
    auto options = srv.dispatch(trie::method::options, "/mixed");
    CHECK_EQ(options.status_code, 204);
    CHECK_EQ(options.body, std::string{});
    CHECK_EQ(options.header("allow"), std::string_view{"GET, HEAD, POST"});
  }
  {
    // GET-only path: HEAD is advertised even without an explicit HEAD route.
    auto options = srv.dispatch(trie::method::options, "/thing");
    CHECK_EQ(options.status_code, 204);
    CHECK_EQ(options.header("allow"), std::string_view{"GET, HEAD"});
  }
  {
    // POST-only path.
    auto options = srv.dispatch(trie::method::options, "/submit");
    CHECK_EQ(options.status_code, 204);
    CHECK_EQ(options.header("allow"), std::string_view{"POST"});
  }
  {
    // Unknown path: 404, not a capability answer.
    auto options = srv.dispatch(trie::method::options, "/missing");
    CHECK_EQ(options.status_code, 404);
    CHECK(options.header("allow").empty());
  }
  {
    // An explicit OPTIONS route keeps priority over the automatic 204.
    auto options = srv.dispatch(trie::method::options, "/capability");
    CHECK_EQ(options.status_code, 202);
    CHECK_EQ(options.header("x-options"), std::string_view{"explicit"});
    // The automatic response would have set Allow; the explicit handler did not.
    CHECK(options.header("allow").empty());
  }
  {
    // Registered OPTIONS appears in Allow for other methods on the same path,
    // while HEAD is still implied by GET and listed exactly once.
    auto del = srv.dispatch(trie::method::del, "/capability");
    CHECK_EQ(del.status_code, 405);
    CHECK_EQ(del.header("allow"), std::string_view{"GET, HEAD, OPTIONS"});
  }
}

void test_method_not_allowed(trie::server<semantics_api>& srv) {
  {
    auto get = srv.dispatch(trie::method::get, "/submit");
    CHECK_EQ(get.status_code, 405);
    CHECK_EQ(get.header("allow"), std::string_view{"POST"});
  }
  {
    auto post = srv.dispatch(trie::method::post, "/thing");
    CHECK_EQ(post.status_code, 405);
    CHECK_EQ(post.header("allow"), std::string_view{"GET, HEAD"});
  }
  {
    auto put = srv.dispatch(trie::method::put, "/mixed");
    CHECK_EQ(put.status_code, 405);
    CHECK_EQ(put.header("allow"), std::string_view{"GET, HEAD, POST"});
  }
  {
    // Explicit HEAD + GET on the same path: HEAD must not be listed twice.
    auto post = srv.dispatch(trie::method::post, "/both");
    CHECK_EQ(post.status_code, 405);
    CHECK_EQ(post.header("allow"), std::string_view{"GET, HEAD"});
  }
  {
    auto unknown = srv.dispatch(trie::method::get, "/no/such/path");
    CHECK_EQ(unknown.status_code, 404);
    CHECK_EQ(unknown.body, std::string{"not found"});
  }
}

} // namespace

int main() {
  test_reason_phrases();
  test_header_injection();

  trie::server<semantics_api> srv;
  test_head_fallback(srv);
  test_options(srv);
  test_method_not_allowed(srv);

  return tst::report("http_semantics_test");
}
