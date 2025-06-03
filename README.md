# dns_relay_server
这是一个简单的 DNS 中继服务器程序，支持在 Windows 平台上运行。它可以从本地配置文件中加载域名与 IP 的映射，并根据请求返回本地定义的解析结果或转发到外部 DNS 服务器。

## ? 准备工作

### 1. 编译环境要求

- **Windows 系统**
- 支持 C99 或更高版本的编译器（例如：MinGW、MSYS2、Visual Studio）
- 需要链接 Winsock 库 (`ws2_32.lib`)
- 如果使用 pthreads，请确保已安装 [pthreads-win32](https://sourceware.org/pthreads-win32/) 或使用 MinGW 自带的 pthread 支持

### 2. 依赖库

- Winsock (`WS2_32.lib`)
- pthread（线程支持）

### 3. 配置文件

程序会尝试从当前目录下读取名为 [dnsrelay.txt](file://F:\c_clion\c_project\dns_relay_server\cmake-build-debug\dnsrelay.txt) 的配置文件。每行格式如下：

```
IP地址 域名
```


**示例：**

```txt
# dnsrelay.txt 示例内容
127.0.0.1 example.com
0.0.0.0 blockedsite.com
192.168.1.100 internal.local
```


> 注意：以 `#` 开头的行为注释行；空行将被忽略。

## ?? 编译步骤（MinGW 示例）

```bash
gcc main.c -o dns_relay_server -lws2_32 -lpthread
```


如果你使用的是 MSVC，则需要确保正确设置运行时库并包含 pthread 支持（或者替换为 Windows 原生线程 API）。

## ?? 运行程序

由于程序绑定到 DNS 标准端口 `53`，你需要以管理员权限运行：

```bash
dns_relay_server.exe
```


> 在 Windows 上，非管理员用户无法绑定到特权端口（如 53），因此必须右键点击终端选择“以管理员身份运行”。

## ? 功能说明

- 若请求的域名存在于 [dnsrelay.txt](file://F:\c_clion\c_project\dns_relay_server\cmake-build-debug\dnsrelay.txt) 中：
    - 如果 IP 为 `0.0.0.0`，则返回 NXDOMAIN 错误响应。
    - 否则返回对应的 A 记录。
- 否则请求会被转发到阿里云公共 DNS 服务器 `223.5.5.5`，并将结果回传给客户端。

## ? 注意事项

- 需要管理员权限运行以绑定端口 53。
- 若需修改外部 DNS 地址，请修改代码中的宏 `EXTERNAL_DNS_SERVER`。
- 本程序为单线程处理每个请求（通过 pthread 创建子线程处理）。

## ? 示例输出

```
DNS Relay Server running on port 53...
Loaded from file: IP=127.0.0.1, Domain=example.com
Received query for domain: example.com (ID: 12345) from 127.0.0.1:54321
Locally resolving example.com to 127.0.0.1 (ID: 12345)
Sent local A record response (IP: 127.0.0.1) for ID 12345 to 127.0.0.1:54321
```


---

如有问题，请检查防火墙是否阻止 UDP 端口 53 的通信，或查看是否有其他 DNS 服务（如 Windows 自带的 DNS Client）占用了该端口。