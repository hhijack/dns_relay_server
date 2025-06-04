# dns_relay_server

这是一个简单的 DNS 中继服务器，支持 Windows 平台。你可以通过配置文件设置本地静态 DNS 映射（A记录和PTR记录），对于未匹配的查询将转发至外部 DNS 服务器（默认为阿里云公共DNS：223.5.5.5）。

## ? 功能特性

- **本地 DNS 解析**
    - 支持 A 记录（正向解析）
    - 支持 PTR 记录（反向解析）
    - 对于 IP 为 `0.0.0.0` 的 A 记录返回 NXDOMAIN 响应
- **外部 DNS 转发**
    - 未在本地表中找到记录时，自动转发给指定的外部 DNS 服务器
    - 支持重试机制和超时控制
- **多线程处理请求**
    - 每个 DNS 请求由独立线程处理
- **支持标准 DNS 查询类型**
    - A (1)
    - AAAA (28)
    - PTR (12)
    - 其他类型会转发

---

## ? 配置文件说明

### 1. 配置文件路径

默认从程序同目录下的 [dnsrelay.txt](file://F:\c_clion\c_project\dns_relay_server\dnsrelay.txt) 加载规则。

> 可以通过命令行参数指定其他路径：
```bash
dns_relay_server.exe /path/to/dnsrelay.txt
```


### 2. 配置格式

#### 标准 A 记录格式：
```
IP地址 域名
```


示例：
```txt
127.0.0.1 example.com
0.0.0.0 blockedsite.com
```


#### 扩展格式（支持 PTR 和 A 记录）：
```
RecordType=Key, Domain=Value
```


示例：
```txt
# 标准 A 记录
A=114.255.40.66, Domain=www.bupt.com.cn

# PTR 记录
PTR=1.0.0.127.in-addr.arpa, Domain=localhost
```


> 注：
> - 以 `#` 开头的行为注释
> - 必须使用逗号分隔键值对
> - 支持大小写敏感的 RecordType（如 `A`, `PTR`）

---

## ?? 编译构建

本项目使用 CMake 构建系统：

```bash
mkdir build && cd build
cmake ..
cmake --build .
```


### 构建选项
- `-DCMAKE_BUILD_TYPE=Debug` —— Debug 版本（默认）
- `-DCMAKE_BUILD_TYPE=Release` —— Release 版本

### 支持编译器
- MinGW (GCC)
- MSVC (Visual Studio)

### 构建后行为
- 自动复制 [dnsrelay.txt](file://F:\c_clion\c_project\dns_relay_server\dnsrelay.txt) 到构建目录

---

## ? 运行环境准备

### 系统要求（Windows）

- **操作系统**: Windows 系统
- **依赖库**:
    - Winsock (`ws2_32.lib`)
    - pthreads（若使用 MinGW 或 winpthreads）

### 网络配置注意事项

- **需要绑定 UDP 端口 53**，需管理员权限运行
- 关闭占用 53 端口的服务（如 Windows DNS Client）
- 确保防火墙允许该端口通信

---

## ? 启动服务

```bash
dns_relay_server.exe
```


### 查看日志输出

启动后会显示类似如下信息：
```
DNS Relay Server running on port 53...
Loaded from file: Type=A, Key=114.255.40.66, Value=www.bupt.com.cn
Loaded from file: Type=PTR, Key=1.0.0.127.in-addr.arpa, Value=localhost
```


---

## ? 测试方法

使用 [nslookup](file://F:\c_clion\c_project\dns_relay_server\cmake-build-debug\nslookup) 测试 DNS 解析：
```bash
nslookup example.com 127.0.0.1
nslookup 1.0.0.127.in-addr.arpa 127.0.0.1
```


查看日志确认是否成功响应或转发。

---

## ? 停止服务

按下 `Ctrl+C` 即可停止服务。

---

## ? 常见问题排查

### 端口被占用
```bash
netstat -ano | findstr :53
```

如果发现有进程占用了 53 端口，请先停止相关服务。

### 查询无响应
- 确认配置文件格式正确
- 检查是否绑定了正确的网卡地址（INADDR_ANY）
- 使用 [nslookup](file://F:\c_clion\c_project\dns_relay_server\cmake-build-debug\nslookup) 指定 127.0.0.1 测试
- 日志输出中查看是否出现 SERVFAIL/NXDOMAIN 错误

---

## ? 源码结构说明

| 文件 | 说明 |
|------|------|
| [main.c](file://F:\c_clion\c_project\dns_relay_server\main.c) | **主程序入口文件**。负责初始化 Winsock、加载 DNS 映射表、创建监听 socket、绑定到 UDP 端口 53，并进入循环接收 DNS 请求。每次接收到请求后，会为每个请求创建一个线程来处理。主要逻辑包括：socket 初始化、权限检查、错误处理和多线程调度。 |
| [request_handler.c](file://F:\c_clion\c_project\dns_relay_server\request_handler.c) | **DNS 请求处理核心逻辑**。包含 [handle_request()](file://F:\c_clion\c_project\dns_relay_server\request_handler.h#L14-L14) 函数，该函数运行在独立线程中，解析客户端发来的 DNS 查询请求，判断是 A 记录还是 PTR 记录查询，从本地缓存查找或转发给外部 DNS 服务器，最终构造响应返回给客户端。它调用了多个模块的功能，如协议解析、本地缓存查找、转发等。 |
| [dns_protocol.c](file://F:\c_clion\c_project\dns_relay_server\dns_protocol.c) | **DNS 协议解析与响应构造模块**。实现 DNS 协议字段的解析、域名提取、构造标准 DNS 响应报文（A记录、PTR记录、NODATA、NXDOMAIN、SERVFAIL 等）。关键函数如 [extract_domain_from_query()](file://F:\c_clion\c_project\dns_relay_server\dns_protocol.h#L25-L27) 提取域名，[send_local_a_response()](file://F:\c_clion\c_project\dns_relay_server\dns_protocol.h#L37-L40) 构造本地 A 记录响应，[send_ptr_response()](file://F:\c_clion\c_project\dns_relay_server\dns_protocol.h#L42-L45) 构造 PTR 响应等。 |
| [dns_cache.c](file://F:\c_clion\c_project\dns_relay_server\dns_cache.c) | **DNS 缓存管理模块**。用于加载配置文件 [dnsrelay.txt](file://F:\c_clion\c_project\dns_relay_server\dnsrelay.txt) 中定义的 DNS 映射规则，支持两种格式：标准 A 记录格式（IP + 域名）和扩展格式（`RecordType=Key, Domain=Value`），并提供 [find_in_dns_table()](file://F:\c_clion\c_project\dns_relay_server\dns_cache.h#L14-L14) 方法供其他模块查询本地映射。 |
| [forwarder.c](file://F:\c_clion\c_project\dns_relay_server\forwarder.c) | **DNS 转发模块**。当请求的域名未在本地缓存找到时，此模块将 DNS 请求转发给指定的外部 DNS 服务器（默认为阿里云公共 DNS：223.5.5.5），并等待响应结果。支持重试机制和超时控制，并将结果回传给原始客户端。 |
| [common.h](file://F:\c_clion\c_project\dns_relay_server\common.h) | **全局头文件**。定义了跨平台宏、常量、数据结构（如 [DNSEntry](file://F:\c_clion\c_project\dns_relay_server\dns_cache.h#L7-L11), [RequestInfo](file://F:\c_clion\c_project\dns_relay_server\request_handler.h#L6-L12), [DNSHeader](file://F:\c_clion\c_project\dns_relay_server\dns_protocol.h#L6-L13), [DNSQuestionTail](file://F:\c_clion\c_project\dns_relay_server\dns_protocol.h#L16-L19) 等）、平台兼容性适配（如 SOCKET 类型、关闭 SOCKET 的宏等），以及一些通用宏定义（如最大条目数、缓冲区大小等）。 |

---

### 文件依赖关系图
```
main.c
├── common.h
├── dns_cache.h
├── request_handler.h
├── dns_protocol.h

request_handler.c
├── common.h
├── dns_cache.h
├── dns_protocol.h
├── forwarder.h

dns_protocol.c
├── common.h

dns_cache.c
├── common.h

forwarder.c
├── common.h
├── dns_protocol.h
```
---

## ? 示例输出日志

```
DNS Relay Server running on port 53...
Loaded from file: Type=A, Key=114.255.40.66, Value=www.bupt.com.cn
Received query for domain: example.com (ID: 12345) from 127.0.0.1:54321
Locally resolving example.com to 127.0.0.1 (ID: 12345)
Received query for domain: 1.0.0.127.in-addr.arpa (ID: 2) from 127.0.0.1:54322 
Locally resolving 1.0.0.127.in-addr.arpa to localhost (ID: 2)
Received query for domain: unknown.com (ID: 3) from 127.0.0.1:54323
Domain not found locally, forwarding AAAA query: unknown.com
Forwarded to DNS server: 223.5.5.5
Forwarded external response (ID: 3) to 127.0.0.1:54323
```


---

## ? 注意事项

- 需要管理员权限才能绑定 53 端口
- 如需修改外部 DNS 地址，请修改 `common.h` 中的 `EXTERNAL_DNS_SERVER`
- 服务器为单线程模型，每请求开启一个线程处理

---

## ? 建议操作流程

1. 修改 `dnsrelay.txt` 添加自己的映射规则
2. 管理员身份打开 CMD，进入构建目录
3. 启动服务：
   ```bash
   dns_relay_server.exe
   ```

4. 使用 nslookup 测试
5. 查看终端输出判断是否正常工作
