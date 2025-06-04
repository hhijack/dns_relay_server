# dns_relay_server
这是一个简单的 DNS 中继服务器程序，支持在 Windows 平台上运行。它可以从本地配置文件中加载域名与 IP 的映射，并根据请求返回本地定义的解析结果或转发到外部 DNS 服务器。

## 准备工作

### 1. 编译环境要求

- **Windows 系统**
- 支持 C99 或更高版本的编译器（例如：MinGW、MSYS2、Visual Studio）
- 需要链接 Winsock 库 (`ws2_32.lib`)
- 如果使用 pthreads，请确保已安装 [pthreads-win32](https://sourceware.org/pthreads-win32/) 或使用 MinGW 自带的 pthread 支持

### 2. 依赖库

- Winsock (`WS2_32.lib`)
- pthread（线程支持）

### 3. 配置文件

程序会从当前目录读取`dnsrelay.txt`配置文件，支持两种格式：

1. 标准格式：
```
IP地址 域名
```

2. 扩展格式(支持PTR记录)：
```
RecordType=Key, Domain=Value
```

**示例：**
```txt
# 标准A记录
127.0.0.1 example.com
0.0.0.0 blockedsite.com

# PTR记录
PTR=1.0.0.127.in-addr.arpa, Domain=localhost
A=114.255.40.66, Domain=www.bupt.com.cn
```

> 注意：
> - 以`#`开头的行为注释行
> - 空行将被忽略
> - PTR记录格式为`PTR=IP.in-addr.arpa, Domain=域名`

## 构建步骤

使用CMake构建：

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

构建选项：
- `-DCMAKE_BUILD_TYPE=Debug` 调试版本(默认)
- `-DCMAKE_BUILD_TYPE=Release` 发布版本

支持编译器：
- MinGW (GCC)
- MSVC (Visual Studio)

## 运行程序

### 1. 运行前准备
1. 确保已创建`dnsrelay.txt`配置文件并放在程序同目录下
2. 关闭可能占用53端口的服务(如Windows DNS Client服务)
3. 确保防火墙允许UDP 53端口的通信

### 2. 启动服务器
由于程序绑定到DNS标准端口`53`，需要以管理员权限运行：

```bash
dns_relay_server.exe
```

或者指定配置文件路径：
```bash
dns_relay_server.exe /path/to/dnsrelay.txt
```

> 在Windows上，非管理员用户无法绑定到特权端口(如53)，因此必须：
> 1. 右键点击终端选择"以管理员身份运行"
> 2. 或者在快捷方式属性中设置"以管理员身份运行"

### 3. 验证服务
1. 检查程序输出是否显示"DNS Relay Server running on port 53..."
2. 使用nslookup测试：
```bash
nslookup example.com 127.0.0.1
nslookup 1.0.0.127.in-addr.arpa 127.0.0.1
```
3. 检查程序日志是否显示正确处理了查询

### 4. 停止服务
按Ctrl+C终止程序运行

### 常见问题
1. 端口占用错误：
   - 运行`netstat -ano | findstr :53`检查端口占用
   - 停止占用53端口的服务

2. 查询无响应：
   - 检查防火墙设置
   - 确认配置文件格式正确
   - 检查程序是否有错误输出

## 功能说明

- 本地静态DNS查询：
  - 支持A记录和PTR记录查询
  - 如果IP为0.0.0.0，返回NXDOMAIN错误响应
  - 否则返回对应的A/PTR记录
- 外部DNS查询转发：
  - 未找到本地记录时转发到223.5.5.5
  - 在响应中添加上游服务器信息
- 配置文件支持标准格式和扩展格式

## 注意事项

- 需要管理员权限运行以绑定端口 53。
- 若需修改外部 DNS 地址，请修改代码中的宏 `EXTERNAL_DNS_SERVER`。
- 本程序为单线程处理每个请求（通过 pthread 创建子线程处理）。

## 示例输出

```
DNS Relay Server running on port 53...
Loaded from file: IP=127.0.0.1, Domain=example.com
Loaded from file: IP=1.0.0.127.in-addr.arpa, Domain=localhost
Received query for domain: example.com (ID: 12345) from 127.0.0.1:54321
Locally resolving example.com to 127.0.0.1 (ID: 12345)
Received query for domain: 1.0.0.127.in-addr.arpa (ID: 2) from 127.0.0.1:54322 
Locally resolving 1.0.0.127.in-addr.arpa to localhost (ID: 2)
Received query for domain: unknown.com (ID: 3) from 127.0.0.1:54323
Domain not found locally, forwarding to external DNS: unknown.com
Added upstream server info: 223.5.5.5
Forwarded external response for ID 3 to 127.0.0.1:54323
```


---

如有问题，请检查防火墙是否阻止 UDP 端口 53 的通信，或查看是否有其他 DNS 服务（如 Windows 自带的 DNS Client）占用了该端口。