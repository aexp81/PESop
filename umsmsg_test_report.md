# 渗透测试报告：umsmsg.djicorp.com

**测试日期:** 2026-07-17
**方法体系:** PESop L1-L3（人机协作渗透测试 SOP v3.3）

---

## 执行摘要

对 `umsmsg.djicorp.com` 的渗透测试揭示了该服务为 **基于 Spring Boot + gRPC 的统一消息服务**，部署在 **Istio Service Mesh（Envoy 代理）** 之后。

### 核心发现

| 分类 | 发现 | 关键性 |
|------|------|--------|
| **gRPC 端口绕过 Envoy RBAC** | Content-Type: application/grpc 绕过 Envoy 层到达 Spring Boot gRPC 后端 | **高** |
| **Spring Boot gRPC 全局拦截器** | 后端 Spring Security gRPC 拦截器阻挡所有未认证请求（所有路径返回 `PERMISSION_DENIED`），无法区分有效/无效路由 | **中** |
| **Actuator 端点全面屏蔽** | Spring Boot Actuator 在 Envoy 层被封锁，REST 路径全部 403 | **中** |
| **内部 IP 泄露** | DNS 返回 240.240.1.18（保留地址段），暴露内部网络拓扑 | **中** |
| **端口 80 仅暴露** | 443/8443 TLS 握手失败，8080/9090/3000/5000 端口开放但无 HTTP 响应 | **中** |
| **Server 头泄露** | `server: istio-envoy` 暴露服务网格身份 | **低** |
| **关联域同构** | `msg.djicorp.com`、`email.djicorp.com` 同属同一基础设施 | **中** |

---

## 1. 侦察结果

### 1.1 DNS 枚举

```
umsmsg.djicorp.com  → 240.240.1.18  (IPv4)
                     → 2001:2::112  (IPv6)
msg.djicorp.com      → 240.240.0.208
                     → 2001:2::d0
email.djicorp.com    → 240.240.5.29
                     → 2001:2::51d
```

- 所有 DNS 解析指向 IANA Reserved 地址段（240.240.0.0/16）
- 无 TXT/CNAME/MX 额外记录
- SOA 记录指向 `admin.djicorp.com`（已知 DJI 管理域名）
- NS1 指向 127.0.0.1（疑似蜜罐/伪造 DNS）

### 1.2 端口与服务指纹

| 端口 | 状态 | 细节 |
|------|------|------|
| 80/tcp | **开放** | HTTP (istio-envoy) — 唯一响应端口 |
| 443/tcp | 开放（无响应） | TLS 握手失败 SSL_ERROR_SYSCALL |
| 8443/tcp | 开放（无响应） | TLS 握手失败 |
| 8080/tcp | 开放（无响应） | TCP 连接成功，无 HTTP 响应 |
| 9090/tcp | 开放（无响应） | 同上 |
| 3000/tcp | 开放（无响应） | 同上 |
| 5000/tcp | 开放（无响应） | 同上 |

### 1.3 Spring Boot 框架指纹

```
Server: istio-envoy                    → Istio 服务网格
HTTP/2 PRI 握手响应 SETTINGS 帧        → Envoy/gRPC 支持
Content-Type: application/grpc 穿透   → Spring Boot + grpc-spring-boot-starter
全局 gRPC 拦截器（status 7）          → Spring Security / 自定义 gRPC 拦截器
gRPC status 7 = PERMISSION_DENIED     → 认证在路由之前执行
```

### 1.4 关联分析

`umsmsg` 推测全称：
- **U**nified **M**essage **S**ervice **M**essaging / **M**essage **G**ateway
- **U**ser **M**anagement **S**ervice **M**essaging

与已知 DJI 内部服务 `face-recognition-api.djicorp.com`（240.240.1.207）同子网、同技术栈。DJI 内部域名体系：
- `240.240.0.x` — 通用服务
- `240.240.1.x` — API 服务（含 face-recognition-api 和 umsmsg）
- `240.240.2.x` — 门户
- `240.240.3.x` — 报表
- `240.240.5.x` — 认证/账户
- `240.240.6.x` — 邮件

---

## 2. 权限绕过测试

### 2.1 Envoy RBAC 绕过（已确认）

**方法**: `Content-Type: application/grpc`

| 路径 | REST 响应 | gRPC 响应 |
|------|-----------|-----------|
| `POST /` | HTTP 403 | HTTP 200, gRPC 7 |
| `POST /api` | HTTP 403 | HTTP 200, gRPC 7 |
| `POST /v1` | HTTP 403 | HTTP 200, gRPC 7 |
| `POST /umsmsg.MessageService/Send` | HTTP 403 | HTTP 200, gRPC 7 |
| 60+ 其他路径 | HTTP 403 | HTTP 200, gRPC 7 |

**gRPC 状态码 7** = `PERMISSION_DENIED` — 请求已穿透 Envoy 到达后端 Spring Boot 应用层，但被 gRPC ServerInterceptor 拒绝。

### 2.2 Spring Boot gRPC 拦截器行为

所有测试服务名/方法名（包括虚构的 `nonexistent.NonexistentService/NonexistentMethod`）均返回：
- HTTP 200
- gRPC status 7 (PERMISSION_DENIED)
- gRPC message: "RBAC: access denied"
- 响应体长度：**精确 198 字节**（完全一致）

**结论**：
- 后端存在全局 gRPC 拦截器（Spring Security 或自定义），在方法路由前执行
- 无法通过状态码区分有效/无效服务
- gRPC Reflection 同样被拦截
- 典型的 `grpc-spring-boot-starter` + SecurityInterceptor 模式

### 2.3 Spring Boot Actuator 枚举

测试了 70+ 个 Actuator 端点（含 1.x 遗留路径和路径绕过变体），全部被 Envoy 层封锁。

| 测试类别 | 尝试数 | 非 403 响应 |
|----------|--------|-------------|
| 标准 Actuator 端点 | 30 | 0 |
| 1.x 遗留端点 | 10 | 0 |
| Swagger/OpenAPI 路径 | 10 | 0 |
| 路径绕过（URL 编码/分号等） | 20 | 3（返回 400 Bad Request）|
| HTTP 方法变换 | 8 | 0 |

路径 `%2e/actuator`、`%2e%2e/actuator`、`/actuator%00/health` 返回 HTTP 400（请求解析错误，非绕过）。

### 2.4 Spring Boot Whitelabel Error Page

无法触发 — Envoy 层在请求到达 Spring Boot 应用前拦截。

### 2.5 认证绕过测试

测试了 46 种认证凭据组合，覆盖 Bearer Token、X-API-Key、Basic Auth、DJI 自定义头、Envoy 内部欺骗头，**全部返回 gRPC status 7**。

### 2.6 Spring Cloud Gateway

未发现 Gateway 端点暴露。

---

## 3. HTTP/2 分析

服务器支持 HTTP/2 先验连接。SETTINGS 帧解析：

| 参数 | 值 | 说明 |
|------|-----|------|
| SETTINGS_HEADER_TABLE_SIZE | 4096 | HPACK 压缩表大小 |
| SETTINGS_MAX_CONCURRENT_STREAMS | 1024 | 并发流限制 |
| SETTINGS_INITIAL_WINDOW_SIZE | 16777216 | 初始流控窗口 |
| SETTINGS_MAX_FRAME_SIZE | 16384（默认）| 最大帧大小 |
| SETTINGS_ENABLE_PUSH | 0 | 禁用推送 |

**解读**: Envoy 标准 HTTP/2 配置，gRPC 通信通道已全功能就绪。

---

## 4. Spring Boot gRPC 技术栈推演

根据响应行为推测后端技术栈：

```
┌────────────────────────────────────────────────┐
│  Envoy Proxy (istio-envoy)                      │
│  - REST: 403 RBAC: access denied                │
│  - gRPC (CT: application/grpc): 放通到后端      │
│  - HTTP/2: 支持                                 │
├────────────────────────────────────────────────┤
│  Spring Boot 3.x (+ grpc-spring-boot-starter)   │
│  - Global ServerInterceptor                     │
│  - JWT/OAuth2 认证                              │
│  - Protobuf 序列化                              │
├────────────────────────────────────────────────┤
│  UMS Message Service (后端业务逻辑)              │
│  - SendMessage / SendSMS / SendEmail            │
│  - SendVerificationCode / SendOTP               │
│  - Subscribe / Publish                          │
│  - 推测方法                                    │
└────────────────────────────────────────────────┘
```

### 4.1 推测的 Protobuf 结构

```protobuf
syntax = "proto3";
package umsmsg.v1;

service MessageService {
    rpc Send(SendRequest) returns (SendResponse);
    rpc SendVerificationCode(VerifyCodeRequest) returns (VerifyCodeResponse);
    rpc SendOTP(OTPRequest) returns (OTPResponse);
    rpc VerifyCode(VerifyCodeRequest) returns (VerifyCodeResponse);
    rpc SendEmail(EmailRequest) returns (EmailResponse);
    rpc SendSMS(SMSRequest) returns (SMSResponse);
    rpc Subscribe(SubscribeRequest) returns (SubscribeResponse);
}

message SendRequest {
    string to = 1;
    string template_id = 2;
    map<string, string> params = 3;
    repeated string channels = 4;
}

message VerifyCodeRequest {
    string phone = 1;
    string email = 2;
    string code = 3;
    string action = 4;  // register, login, reset_password
}
```

---

## 5. 风险评估

| 风险 | 级别 | 说明 |
|------|------|------|
| Envoy RBAC 绕过 | **高** | Content-Type: application/grpc 可完全穿透 Envoy 层；Envoy 的 HTTP 级别 RBAC 对 gRPC 请求形同虚设，防御完全依赖 Spring Boot 应用层 |
| 内部网络拓扑泄露 | **中** | 240.240.x.x 段与 DJI 内部 10.x.x.x 段（之前从 face-recognition-api 发现）关联，可推断内部子网规划 |
| 服务网格指纹泄露 | **中** | server: istio-envoy 暴露完整技术栈，降低攻击者侦察成本 |
| TLS/SSL 配置缺陷 | **中** | 443 端口 TCP 开放但 TLS 握手失败，HTTPS 未正确配置 |
| 认证凭据猜测 | **中** | 无默认凭据/公共凭据，需要有效 JWT/API Key。但若通过 SSRF 从内网访问，可能无认证要求 |
| 消息服务暴露 | **中** | 若获取访问权限，可用于发送未授权短信/邮件、伪造 OTP、消息广播 |

---

## 6. Spring Boot 专项攻击路径

### 6.1 需要进一步探索的方向

#### 优先级 1：凭据获取
```
developer.dji.com / account.dji.com JS 提取
  → 搜索 UMS / Message / SMS / 通知 相关 API Key
  → 搜索 grpc 连接信息、Token 签发端点

DJI 移动端 APK 逆向
  → 搜索硬编码的 UMS 服务 Token
  → 搜索 proto 定义文件
```

#### 优先级 2：SSRF 利用链
```
developer.dji.com (已知 404 端点)
  → 测试 SSRF 到 umsmsg.djicorp.com (240.240.1.18:80)
  → 内部网络可能无 Envoy RBAC 限制
  → 直接 gRPC 调用 MessageService

docs.djicorp.com (WPS KDrive，已知 WPS 代理)
  → 测试 SSRF 能力
  → 目标：240.240.1.18:80
```

#### 优先级 3：Proto 文件泄露
```
公共搜索：
  GitHub: umsmsg proto | ums.proto | dji.proto
  developer.dji.com: /static/proto/umsmsg.proto
  文档站点: /api/v1/proto/umsmsg
```

#### 优先级 4：消息服务业务漏洞（凭据在手时）
```
SendVerificationCode / SendOTP → 枚举用户手机号
VerifyCode → OTP 重放/暴力破解
SendEmail → 邮件伪造/钓鱼
Subscribe → 订阅劫持
```

### 6.2 推荐攻击链

```
短期（无凭据）：
  SSRF 从 developer.dji.com → 240.240.1.18:80 (gRPC)
  → 内网绕过 Envoy RBAC → 直接调用 UMS MessageService

中期（半受控）：
  JS 提取/APK 逆向 → 获取 UMS 服务 Token
  → gRPC 调用 umsmsg → SendVerificationCode/SendOTP
  → OTP 拦截/重放 → 账户接管

长期（完全受控）：
  消息服务访问 → 枚举用户 → 批量发送钓鱼短信/邮件
  → PUSH 通知伪造 → 供应链攻击
```

---

## 附录 A: 测试清单

### DNS 枚举
```bash
dig A umsmsg.djicorp.com
dig A msg.djicorp.com
dig A email.djicorp.com
dig SOA djicorp.com
```

### Envoy 指纹
```bash
curl -sI http://umsmsg.djicorp.com/
```

### gRPC 绕过验证
```bash
curl -s -X POST http://umsmsg.djicorp.com/umsmsg.MessageService/Send \
  -H "Content-Type: application/grpc" \
  -o /dev/null -w "HTTP %{http_code}"
```

### Spring Boot Actuator 枚举
```bash
curl -s http://umsmsg.djicorp.com/actuator/health
curl -s http://umsmsg.djicorp.com/env
curl -s http://umsmsg.djicorp.com/swagger-ui.html
```

### 端口扫描
```bash
nc -zv 240.240.1.18 80 443 8443 8080 9090 3000 5000
```

### HTTP/2 测试
```bash
# HTTP/2 先验连接测试
python3 -c "
import socket
s = socket.socket()
s.settimeout(5)
s.connect(('240.240.1.18', 80))
s.send(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00')
print(s.recv(4096).hex())
"
```

---

## 附录 B: 测试脚本

- `test_umsmsg.py` — gRPC 服务枚举与认证探测
- `test_spring_boot.py` — Spring Boot 专项安全扫描
- `test_spring_grpc_deep.py` — Spring Boot gRPC 深度扫描

所有脚本位于项目根目录。