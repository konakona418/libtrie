# libtrie

基于 C++26 反射（P2996 + P3394 annotations + P1306 expansion statements）的 HTTP 框架：

- **编译期路由**：handler 上的 `[[=trie::get("/users/{id}")]]` 注解在编译期变成一棵 trie，
  匹配过程是一条静态嵌套调用链，不遍历运行时表。
- **HTTP/1.1 传输层**：C++20 coroutine + epoll 实现，单线程事件循环，每条连接一个 coroutine。
- **JSON**：基于 vendored nlohmann-json，并用反射在聚合类型和 JSON 之间自动转换。
- **类型安全客户端**：由同一份反射信息生成 method / path / 参数 / 返回类型，编译期校验。

## 环境要求

- **GCC 16 或更新版本**（使用 `-freflection`）。
- CMake ≥ 3.23。
- **Linux**（HTTP transport 基于 epoll；路由/JSON/客户端本身是平台无关的）。
- 不支持系统 clang：stock clang 没有实现反射。clangd 同样无法解析这些语法，
  编辑器里会有误报；请以 `cmake --preset dev` 的编译结果为准。

## 构建与测试

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev

# 启动示例服务
./build/dev/examples/trie_http_server 8080
curl http://127.0.0.1:8080/hello
curl -X POST -H 'Content-Type: application/json' \
     -d '{"name":"a","age":1}' http://127.0.0.1:8080/person
```

## 快速开始

### 路由 + HTTP server

```cpp
#include "trie/trie.hh"

struct person {
  std::string name;
  int age = 0;
};

struct users_api {
  [[=trie::get("/users/{id}")]]
  int get_user(int id) { return id * 2; }

  // 请求体反序列化成 person，返回值序列化成 JSON（Content-Type: application/json）。
  [[=trie::post("/person")]]
  person bump_age([[=trie::body]] person value) {
    value.age += 1;
    return value;
  }

  [[=trie::get("/search")]]
  std::string search([[=trie::query("q")]] std::string_view q,
                     [[=trie::query("limit")]] std::optional<int> limit);
};

int main() {
  trie::server<users_api> router;
  trie::http::serve(router, trie::http::endpoint{"127.0.0.1", 8080});   // 阻塞
}
```

需要控制生命周期（例如测试里用 0 端口、从别的线程 `stop()`）时直接用 `listener`：

```cpp
trie::http::listener<trie::server<users_api>> server{router, {"127.0.0.1", 0}};
std::thread thread{[&] { server.run(); }};
// ... server.port() 是实际绑定的端口 ...
server.stop();
thread.join();
```

多个 controller 直接作为模板参数组合：`trie::server<users_api, admin_api>`。
同一个 `(method, path)` 重复注册是编译错误。

### JSON

```cpp
#include "trie/trie.hh"

struct person {
  std::string name;
  int age = 0;
  std::optional<std::string> nickname;
  std::vector<std::string> tags;
};

// 反射驱动：聚合类型的 public 非静态成员 -> JSON object
trie::json::value document = trie::json::to_json(person{"a", 1, std::nullopt, {"x"}});
std::string text = trie::json::dump(document);

// 解析 + 反序列化（失败返回 std::expected，不抛异常）
auto parsed = trie::json::parse_as<person>(text);
if (parsed) { /* parsed->name ... */ }

// 通用 JSON
auto value = trie::json::parse(R"({"ok":true})");
if (value) { bool ok = (*value)["ok"].get<bool>(); }
```

- `trie::json::value` 就是 `nlohmann::json`，可以直接用 nlohmann API。
- JSON 响应由返回类型决定：返回 `trie::json::value` 或任意可序列化聚合/容器/枚举 →
  `Content-Type: application/json`；返回字符串/数值/void/`http::status` 走文本/状态规则。
- `trie::body` 参数支持：`std::string` / `std::string_view`（原始 body）、`trie::json::value`
  以及任意可反序列化聚合类型（JSON），解析失败 → 400，handler 不会被调用。
- `parse_as<T>` 会拒绝包含 `string_view`/`const char*` 的类型（避免悬垂视图）。

### 类型安全客户端

```cpp
struct loopback_transport {
  trie::server<users_api>* server;
  std::expected<trie::http::response, trie::client_error> send(trie::http::request request) {
    std::vector<trie::http::header_view> scratch;
    for (auto const& h : request.headers) scratch.push_back({h.first, h.second});
    return server->dispatch(
        trie::http::request_view::from_target(request.m, request.target, scratch, request.body));
  }
};

trie::client<users_api, loopback_transport> client{loopback_transport{&server}};

auto user = client.call<^^users_api::get_user>(21);        // expected<int, client_error>
auto person = client.call<^^users_api::bump_age>(p);       // expected<person, client_error>
```

- 实参必须严格对应 handler 的非 context 参数，个数/类型编译期校验。
- query/header 注解同时驱动请求构造；路径参数自动百分号编码；JSON body/返回值自动编解码。
- 返回 `std::expected<T, trie::client_error>`：2xx 成功，否则 `client_error{status, body}`。
- Transport 只要求：

```cpp
template <class T>
concept transport = requires(T& t, trie::http::request request) {
  { t.send(std::move(request)) } -> std::same_as<std::expected<trie::http::response, trie::client_error>>;
};
```

## 参数注入规则

| 参数写法 | 来源 |
| --- | --- |
| `trie::http::request_view const&` | 当前请求 |
| `trie::http::response&` | 待填写的响应 |
| `int id` / `std::string_view name` | 路径参数，按 `{placeholder}` 顺序 |
| `[[=trie::query("q")]] std::string_view q` | query 参数（自动百分号解码） |
| `[[=trie::query("limit")]] std::optional<int> limit` | 可选 query 参数，缺失时为 `nullopt` |
| `[[=trie::header("X-Token")]] std::string_view token` | 请求头（大小写不敏感，自动解码） |
| `[[=trie::body]] std::string_view body` | 原始请求体 |
| `[[=trie::body]] person body` | JSON 请求体（反序列化为 `person`） |

路径/query/header 支持：整型、浮点、`bool`、`std::string`、`std::string_view` 及 `std::optional<T>`。
路径参数个数必须与 `{placeholder}` 个数一致，否则编译期 `static_assert`。

## 返回值规则

| 返回类型 | 行为 |
| --- | --- |
| `void` | handler 自行填写 `response` |
| `std::string` / `std::string_view` / `const char*` | 文本响应体 |
| 整型 / 浮点 / `bool` | 转文本响应体 |
| `trie::http::status` | 设置状态码 |
| `trie::json::value` | JSON 响应体 |
| 可序列化聚合/容器/枚举 | 反射转 JSON 响应体 |

## HTTP transport

- HTTP/1.1：keep-alive、pipelining（顺序处理）、HEAD（只发头部）、`Content-Length`。
- 请求限制：header 16 KiB、body 1 MiB、target 8 KiB；路径最多 32 段，单段 24 字节。
- 状态码：404 / 405（带 `Allow`）/ 400 / 413 / 414 / 431 / 501 / 505。
- 单线程 epoll 事件循环，每条连接一个 coroutine；`listener::stop()` 可从其他线程调用。
  不支持 TLS、HTTP/2、chunked 请求体。
- `serve(router, endpoint)` 是阻塞封装；`listener` 提供 `valid()/error_code()/port()/run()/stop()`。

## 设计

```
编辑期               编译期                                   运行期
annotations  ──►  members_of / annotations_of  ──►  trie 节点数组（NTTP）
                                                      │
                                                      ├─ 每个节点一个模板实例
                                                      └─ template for 展开子节点 → 静态嵌套调用
                                                                 │
                                                      handler 参数由 parameters_of + type_of 推导

socket ──► epoll ──► connection coroutine ──► http parser ──► request_view
                                                              │
                                                    server<...>::dispatch
                                                              │
                                          response ──► serializer ──► socket
```

- 路由注解类型必须 structural：路径/名称存进 `std::array<char, N>`，**不能用 `const char*`**
  （两个编译器都无法 reflect 指向字符串字面量的指针）。
- 注解返回类型是 `const route`，比较时先 `remove_const`。
- 反射返回的 `std::vector` 不能存进 `constexpr` 变量；内部统一用 `define_static_array` 或
  `consteval` 查询函数。
- `-fno-exceptions` / `-fno-rtti` 下可用；反射错误是编译期硬错误。
- handler 必须是 public（`access_context::unprivileged()`）且至少有一个路由注解。
- 编译期会裁掉未使用的方法和该方法的路径子树。

## 目录

```
include/trie/
  annotations.hh        route / method / query / header / body 注解
  http.hh               request_view / request / response
  json.hh               trie::json（nlohmann 适配 + 反射 to_json/from_json）
  server.hh             server<Controllers...>：404/405 与请求分派
  client.hh             client<Api, Transport>：类型安全客户端
  trie.hh               总入口
  detail/reflect.hh     反射元数据、参数分类、static_assert 校验
  detail/trie.hh        编译期 trie、静态 dispatch、参数转换
  detail/url.hh         百分号编解码
  http/parser.hh        增量 HTTP/1.1 请求解析
  http/serializer.hh    响应序列化
  http/event_loop.hh    epoll 事件循环 + task / io awaiter
  http/listener.hh      listener / connection coroutine / serve()
vendor/nlohmann/        nlohmann-json 3.12.0（MIT）
tests/                  8 个无需第三方框架的测试（含真实 socket 集成测试）
examples/basic.cc       纯路由 + loopback 客户端
examples/http_server.cc coroutine/epoll 服务端 + JSON 示例
```

## 第三方

- [nlohmann/json](https://github.com/nlohmann/json) 3.12.0，MIT，位于 `vendor/nlohmann/`。
  通过 `-Ivendor/nlohmann` 引入；`trie/json.hh` 会定义 `JSON_NOEXCEPTION` 后再包含它。

## 当前限制

- 只有服务端 transport；类型安全客户端自带 transport concept（示例用 loopback）。
- 单线程事件循环；没有 TLS / HTTP/2 / chunked 请求体 / 超时与连接数上限。
- 没有 JSON 到 schema 的校验、没有 multipart、没有 streaming body。
- 路径参数与 query/header 参数不支持枚举、自定义类型（JSON body 支持枚举）。
- 路由模板上限 95 字符、路径 32 段、handler 参数 12 个。
- 编译期成本随路由数增长；未使用方法和路径子树会被裁剪。实测 24 条 GET 路由约 2.5 s，
  28 条覆盖 7 个方法的路由约 3 s（GCC 16.2，`-O0`；含 nlohmann 头文件后略有增加）。
