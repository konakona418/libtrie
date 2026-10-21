# libtrie

基于 C++26 反射（P2996 + P3394 annotations + P1306 expansion statements）的 HTTP 路由库。
路由表在编译期由被注解的成员函数生成，匹配过程是一条**静态嵌套调用链**，不遍历运行时表。
同时提供由同一份反射信息驱动的**类型安全客户端**。

当前版本只包含纯路由核心（无 socket / HTTP 报文解析），transport 由使用方或后续版本提供。

## 环境要求

- **GCC 16 或更新版本**（使用 `-freflection`）。
- CMake ≥ 3.23。
- 不支持系统 clang：stock clang 没有实现反射。clangd 同样无法解析这些语法，
  编辑器里会有误报；请以 `cmake --preset dev` 的编译结果为准。

## 构建与测试

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
./build/dev/examples/trie_basic
```

## 快速开始

```cpp
#include "trie/trie.hh"

struct users_api {
  // 路由注解。路径里的 {name} 是路径参数，按位置对应 handler 的 path 参数。
  [[=trie::get("/users/{id}")]]
  int get_user(int id) { return id * 2; }

  [[=trie::post("/users")]]
  void create_user([[=trie::body]] std::string_view body, trie::http::response& response) {
    response.set_status(trie::http::status::created);
    response.body.assign(body.data(), body.size());
  }

  [[=trie::get("/search")]]
  std::string search([[=trie::query("q")]] std::string_view q,
                     [[=trie::query("limit")]] std::optional<int> limit);
};

int main() {
  trie::server<users_api> server;                       // 编译期组合所有 controller
  auto response = server.dispatch(trie::method::get, "/users/21");
  // response.status_code == 200, response.body == "42"
}
```

多个 controller 直接作为模板参数组合：`trie::server<users_api, admin_api>`。
同一个 `(method, path)` 重复注册是编译错误。

### 参数注入规则

| 参数写法 | 来源 |
| --- | --- |
| `trie::http::request_view const&` | 当前请求 |
| `trie::http::response&` | 待填写的响应 |
| `int id` / `std::string_view name` | 路径参数，按 `{placeholder}` 顺序 |
| `[[=trie::query("q")]] std::string_view q` | query 参数（自动百分号解码） |
| `[[=trie::query("limit")]] std::optional<int> limit` | 可选 query 参数，缺失时为 `nullopt` |
| `[[=trie::header("X-Token")]] std::string_view token` | 请求头（大小写不敏感，自动解码） |
| `[[=trie::body]] std::string_view body` | 请求体 |

支持的参数值类型：整型、浮点、`bool`、`std::string`、`std::string_view` 及其
`std::optional<T>`。路径参数个数必须与 `{placeholder}` 个数一致，否则编译期 `static_assert`。

缺少必需的 query/header 参数或数值解析失败 → `400 Bad Request`，handler 不会被调用。

### 返回值规则

| 返回类型 | 行为 |
| --- | --- |
| `void` | handler 自行填写 `response` |
| `std::string` / `std::string_view` / `const char*` | 写入响应体 |
| 整型 / 浮点 / `bool` | 转文本写入响应体 |
| `trie::http::status` | 设置状态码 |

### 状态码

- 路径匹配但方法不匹配 → `405` + `Allow` 头
- 无匹配 → `404`
- 参数转换 / 百分号解码失败 → `400`
- 路径超过 32 段、单个段超过 24 字节、路径模板超过 95 字符 → `400` 或编译错误

## 类型安全客户端

客户端从 handler 的反射拿到 method、路径模板和签名，调用参数与返回类型在编译期校验：

```cpp
trie::client<users_api, transport_t> client{transport};

auto user = client.call<^^users_api::get_user>(21);       // std::expected<int, trie::client_error>
auto page = client.call<^^users_api::search>(std::string_view{"hello world"},
                                             std::optional<int>{5});
```

- 实参必须严格对应 handler 的非 context 参数（`request` / `response` 不传），个数和类型都会 `static_assert`。
- query/header 注解同时用于请求构造：`limit={5}`、`X-Token: ...`；路径参数自动百分号编码。
- 返回 `std::expected<T, trie::client_error>`：2xx 视为成功，否则 `client_error{status, body}`。
  返回 `std::string_view`/`const char*` 的 handler 在客户端侧映射为 `std::string`。
- Transport 只需满足：

```cpp
template <class T>
concept transport = requires(T& t, trie::http::request request) {
  { t.send(std::move(request)) } -> std::same_as<std::expected<trie::http::response, trie::client_error>>;
};
```

`tests/client_test.cc` 里的 `loopback_transport` 演示了客户端直接打到 `trie::server` 的端到端用法。

## 设计

```
编辑期               编译期                                  运行期
annotations  ──►  members_of / annotations_of  ──►  trie 节点数组（NTTP）
                                                      │
                                                      ├─ 每个节点一个模板实例
                                                      └─ template for 展开子节点 → 静态嵌套调用
                                                                 │
                                                      handler 参数由 parameters_of + type_of 推导
```

- 路由注解类型必须 structural：路径/名称存进 `std::array<char, N>`，**不能用 `const char*`**
  （两个编译器都无法 reflect 指向字符串字面量的指针）。
- 注解返回类型是 `const route`，比较时先 `remove_const`。
- 反射返回的 `std::vector` 不能存进 `constexpr` 变量；内部统一用 `define_static_array` 或
  `consteval` 查询函数。
- `-fno-exceptions` / `-fno-rtti` 下可用；反射错误是编译期硬错误。
- handler 必须是 public（`access_context::unprivileged()`）且至少有一个路由注解。

## 目录

```
include/trie/
  annotations.hh       route / method / query / header / body 注解
  http.hh              request_view / request / response
  server.hh            server<Controllers...>：404/405 与请求分派
  client.hh            client<Api, Transport>：类型安全客户端
  trie.hh              总入口
  detail/reflect.hh    反射元数据、参数分类、static_assert 校验
  detail/trie.hh       编译期 trie、静态 dispatch、参数转换
  detail/url.hh        百分号编解码
tests/                 单元测试（无需第三方框架）
examples/basic.cc      纯路由 + loopback 客户端示例
```

## 当前限制

- 无 HTTP transport（socket / HTTP/1.1 解析留待后续）；`http::request_view` 由调用方构造。
- 无 JSON。
- 路径参数与 query/header 参数不支持枚举、自定义类型；需要时扩展 `detail::parse_value` 与
  `detail::value_to_text`。
- 路由模板上限 95 字符、路径 32 段、handler 参数 12 个（常量在 `annotations.hh` /
  `detail/reflect.hh` / `server.hh` 中）。
- 编译期成本随路由数增长：每个 trie 节点、每个实际用到的方法各生成一个模板实例；
  未使用的方法和该方法的路径子树会在编译期被裁掉。实测 24 条 GET 路由约 2.5 s，
  28 条覆盖 7 个方法的路由约 3 s（GCC 16.2，`-O0`）。适合中小规模 API。
