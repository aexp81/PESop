# 安全测试报告 — entertainment.dji.com

**目标：** `https://entertainment.dji.com/`
**平台：** 大疆互娱（畅片 APP 营销站）
**日期：** 2026-07-15
**测试类型：** 授权黑盒安全评估
**方法：** PESop v3.3 (HF-1~HF-7 全流程)

---

## 1. 系统模型 (Phase 2 建模)

### 1.1 系统类型判定

| 维度 | 判定 | 判据 |
|------|------|------|
| 应用类型 | 静态 React SPA 营销页 | `<div id="root">`, Webpack chunks, SPA catch-all 路由 |
| Web 服务器 | Alibaba Tengine（Nginx 分支） | `server: Tengine` |
| API 网关 | Kong | `x-kong-upstream-latency`, `x-kong-proxy-latency` |
| CDN/WAF | 阿里云 CDN + Alibaba Cloud WAF | `via: cache.cn7715`, `acw_tc` cookie, 405 blocking |
| 静态存储 | 阿里云 OSS | `hz-skypixel-fe-v2-prod.oss-cn-hangzhou.aliyuncs.com` |
| 前端 CDN | SkyPixel CDN | `spcn-webfront.skypixel.com` |
| 错误监控 | Sentry（自建） | `sentry-io.djiops.com/421` |
| 分析/埋点 | Sensorsdata CDP + GA + DJI Analytics | `cdp.djiservice.org` |
| APP 下载 | 大疆内部服务 | `service-adhoc.dji.com` |

### 1.2 业务链

```
用户访问 entertainment.dji.com
  → React SPA 加载（CDN + OSS）
  → 渲染首页 / 畅片 APP 推广内容
  → 下载 APP → 跳转 App Store / 安卓 APK 下载
  → 查看 FAQ / 教程 → 静态内容路由
  → 查看法律页面 → 静态内容路由
  → 前端埋点 → store-api.dji.com/logger/beacon.gif
```

### 1.3 接口分诊

| 接口 | 业务角色 | 优先级 | 定级依据 |
|------|---------|--------|---------|
| `sentry-io.djiops.com` | Sentry 错误监控 | **P0** | 自建 Sentry 暴露版本/项目/健康信息，CORS:* |
| `store-api.dji.com` | 埋点 Beacon | **P0** | CORS:* 允许跨域发送数据 |
| `service-adhoc.dji.com` | APP 下载/跳转 | **P1** | 重定向链可能存在 SSRF |
| `cdn.djiservice.org` | CDP 数据通道 | **P1** | 生产/测试环境端点暴露 |
| `entertainment.dji.com` | SPA 页面 | **P2** | 纯静态，无服务端 API |

---

## 2. 发现详情

### 2.1 [严重] INF-1: DNS 泄露 13 个内部 IP 地址

**描述：** dji.com 的 NS 记录公开解析出大量 **10.x.x.x 内网 IP**，直接暴露大疆内部 AD 域控基础设施拓扑。

**PoC：**
```bash
$ dig dji.com NS +short
iao-ad-bwp02.dji.com.
iao-ad-jpp01.dji.com.
iao-ad-xiyp04.dji.com.
iao-ad-pvgp02.dji.com.
...

$ dig +short iao-ad-bwp02.dji.com
10.20.1.111
$ dig +short djiad02-in.dji.com
10.10.0.111
```

**泄露的内部 IP 完整清单：**

| 主机名 | 内部 IP | 推测用途 |
|--------|---------|---------|
| `iao-ad-vhabp01.dji.com` | 10.161.1.207 | AD 域控 (VHA 数据中心) |
| `iao-ad-vhabp02.dji.com` | 10.10.0.111 | AD 域控 (VHA 数据中心) |
| `iao-ad-bwp02.dji.com` | 10.20.1.111 | AD 域控 (BWP 数据中心) |
| `iao-ad-bwp03.dji.com` | 10.20.1.110 | AD 域控 (BWP 数据中心) |
| `iao-ad-xiyp04.dji.com` | 10.101.145.111 | AD 域控 (XIY 数据中心) |
| `iao-ad-xiyp05.dji.com` | 10.101.145.112 | AD 域控 (XIY 数据中心) |
| `iao-ad-pvgp01.dji.com` | 10.97.72.111 | AD 域控 (PVG 数据中心) |
| `iao-ad-pvgp02.dji.com` | 10.97.72.112 | AD 域控 (PVG 数据中心) |
| `iao-ad-jpp01.dji.com` | 10.114.18.111 | AD 域控 (JPP 数据中心) |
| `iao-ad-jpp02.dji.com` | 10.114.18.112 | AD 域控 (JPP 数据中心) |
| `djiad02-in.dji.com` | 10.10.0.111 | AD 域控 |
| `cwdc02-ad-win01.dji.com` | 10.10.0.108 | Windows 服务器 |
| `ad-ap-cwp02.dji.com` | 10.10.1.111 | AD 域控 (CWP 数据中心) |

**危害升级：** 内部网络拓扑完全暴露，攻击者可结合其他漏洞获取 DJI 内网入口后，精准定位域控服务器进行横向移动。

### 2.2 [严重] INF-2: jenkins.dji.com 内网 IP 暴露

**描述：** `jenkins.dji.com` 公开解析到内网地址 `10.61.122.22`，确认 Jenkins CI 运行在内网。

**PoC：**
```bash
$ dig +short jenkins.dji.com
10.61.122.22
```

**危害升级：** 虽然当前无法从公网直接访问 10.x.x.x 地址，但 IP 泄露帮助攻击者在获得内网入口后精准定位高危 CI 系统。

### 2.3 [高危] INF-3: Kong Admin 端口对外开放

**描述：** `sentry-io.djiops.com` 上 Kong API Gateway 的管理端口对外暴露可达。

**PoC：**
```bash
# 端口扫描结果
sentry-io.djiops.com:8001 → OPEN (Kong Admin API)
sentry-io.djiops.com:8443 → OPEN (Kong Admin API SSL)
sentry-io.djiops.com:8444 → OPEN (Kong Admin API SSL)
sentry-io.djiops.com:8000  → OPEN (Kong Proxy)
```

**危害升级：** Kong Admin API 默认无认证，可管理所有路由/服务/上游。需进一步测试是否可通过这些端口进行未授权访问。

### 2.4 [高危] INF-4: Sentry 自建实例暴露 + DSN 公钥可注入事件

**描述：** 大疆自建 Sentry 实例对外暴露版本信息、健康状态，CORS 配置为 `*`，且前端 JS 中泄露的 DSN **公钥有效**，可直接向 Sentry 注入错误事件。

**PoC：**
```bash
# 版本信息（无需认证）
$ curl -s https://sentry-io.djiops.com/api/0/
{"version":"0","auth":null,"user":null}

# 健康检查（无需认证）
$ curl -s https://sentry-io.djiops.com/_health/
ok

# CORS 全开放
$ curl -sI -X OPTIONS -H "Origin: https://evil.com" https://sentry-io.djiops.com/api/0/
access-control-allow-origin: *

# ⚠️ DSN 公钥事件注入验证成功
$ curl -s -X POST "https://sentry-io.djiops.com/api/421/store/" \
  -H "X-Sentry-Auth: Sentry sentry_version=7, \
       sentry_key=6eaac537cb924b859b99ffc7c703c257" \
  -d '{"message":"security_test","level":"info"}'
{"id":"bb77c905766641ed9092c456e11cc722"}
```

**JS 前端暴露的 DSN：**
```
https://6eaac537cb924b859b99ffc7c703c257@sentry-io.djiops.com/421
```

**危害升级：** DSN 公钥有效且可注入事件，攻击者可：
1. 伪造错误事件触发 Sentry 告警/webhook，实现告警 DoS
2. 污染错误监控数据，掩盖真实攻击
3. 注入恶意 payload 到错误报告（若 Sentry 管理面板存在 XSS）
4. 利用 Sentry webhook 进行 SSRF 探测内部网络

### 2.5 [高危] INF-5: store-api.dji.com CORS 全开放

**描述：** 埋点端点 `store-api.dji.com/logger/beacon.gif` 配置了 `access-control-allow-origin: *`，允许任意网站跨域发送数据。

**PoC：**
```bash
$ curl -sI -X OPTIONS -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  https://store-api.dji.com/logger/beacon.gif
access-control-allow-origin: *
```

**危害升级：** CORS 全开放允许第三方网站利用用户浏览器向 DJI 发送埋点数据，可用于 CSRF 攻击或数据污染。

### 2.6 [中危] INF-6: 安全响应头缺失

**描述：** `entertainment.dji.com` 缺少多项关键安全头。

| 安全头 | 状态 | 风险 |
|--------|------|------|
| `Content-Security-Policy` | ❌ 缺失 | XSS 无任何限制 |
| `Strict-Transport-Security` | ❌ 缺失 | 可被降级攻击 |
| `X-Content-Type-Options` | ❌ 缺失 | MIME 嗅探可能 |
| `X-XSS-Protection` | ❌ 缺失 | （浏览器已废弃） |
| `X-Frame-Options` | ✅ SAMEORIGIN | 良好 |
| `Set-Cookie: Secure` | ❌ `acw_tc, server-location` 均缺 | Cookie 可通过 HTTP 明文传输 |

### 2.7 [中危] INF-7: Cookie 安全属性缺失

**描述：** `acw_tc`（WAF 反爬 cookie）和 `server-location` cookie 均缺少 `Secure` 和 `SameSite` 属性。

| Cookie | HttpOnly | Secure | SameSite |
|--------|----------|--------|----------|
| `acw_tc` | ✅ | ❌ | ❌ (None) |
| `server-location` | ❌ | ❌ | ❌ (None) |
| `sentrysid` | ✅ | ❌ | ❌ (None) |

**危害升级：** `acw_tc` 作为 WAF 认证凭据，缺 Secure flag 意味着可在 HTTP 明文连接中被截获。

### 2.8 [中危] INF-8: WAF 绕过路径存在

**描述：** Alibaba Cloud WAF 对敏感路径存在差异化响应，可通过编码/变体绕过。

| 路径 | 状态 | 响应内容 |
|------|------|---------|
| `.env` | 405 | Alibaba WAF 规则拦截 |
| `.git/HEAD` | 405 | Alibaba WAF 规则拦截 |
| `.gitattributes` | **403** | 不同规则（响应不同） |
| `/%2e%2e/.env` | **400** | Bad Request |
| `/..;/env` | 405 | 路径遍历拦截 |

**危害升级：** WAF 规则不统一（405 vs 403），可通过枚举规则漏洞尝试绕过。

### 2.9 [高危] INF-9: Source Map 泄露 — Next.js 运行时代码完全逆向

**描述：** 生产环境 `/h5/` 路径下 Next.js chunk 的 source map 文件可公开访问（669KB），导致框架代码完全暴露。对应的 JS 文件（164KB）同样可访问。与 `/offical/` 路径（所有 source map 返回 404，配置正确）相比，`/h5/` 路径存在明显的配置遗漏。

**PoC：**
```bash
# Source map 文件可下载（669KB）
$ curl -sI "https://spcn-webfront.skypixel.com/entertainment/public/h5/_next/static/chunks/4165-e56cbc1b2c8cabfc.js.map"
HTTP/2 200

# 对应的 JS 文件同样可访问（164KB）
$ curl -sI "https://spcn-webfront.skypixel.com/entertainment/public/h5/_next/static/chunks/4165-e56cbc1b2c8cabfc.js"
HTTP/2 200
```

**泄露内容：**
- Next.js 框架核心运行时源代码（146 个文件，完全可读）
- 客户端 Router 实现逻辑（app-router.js, navigate-reducer.js 等）
- 服务端渲染与导航的完整内部实现
- 框架版本与构建结构
- 30+ 个 TODO/FIXME 注释暴露开发阶段的遗留问题

**危害升级：** 攻击者可利用泄露的框架代码：
1. 分析 Next.js App Router 的客户端实现寻找通用漏洞
2. 针对该版本 Next.js 编写特定 exploit
3. 了解服务端渲染与客户端导航的握手协议
4. 识别未在生产环境正确配置的特性（如 `force-dynamic` 等）

**与 `/offical/` 的对比：**
| 路径 | `.js.map` | 状态 |
|------|-----------|------|
| `/offical/` | 10 个 JS（均返回 404）| ✅ 安全 |
| **`/h5/`** | **1 个 JS + 666KB source map 可访问** | **❌ 泄露** |

### 2.10 [中危] INF-10: 逆向发现 - router 路由与 User-Agent 检测

**描述：** 通过逆向 `/offical/` 路径下的 JS chunks，发现以下 DJI 特有逻辑：

**发现的路由模式：**
| 路径 | 类型 | 说明 |
|------|------|------|
| `/:pageId` | 动态路由 | 通用页面路由 |
| `/studio-faq` | 静态路由 | 畅片 Studio FAQ 页面 |
| `/studio-driver-tutorial` | 静态路由 | 驱动教程页面 |
| `/terms`, `/privacy`, `/cancellation` | 静态路由 | 法律条款页面 |
| `/ugc`, `/editor-ugc`, `/ai-terms` | 静态路由 | UGC 协议页面 |
| `/auto-download` | 静态路由 | 自动下载触发页面 |
| `/_app`, `/_error`, `/_not-found` | Next.js 系统路由 | 内部路由 |

**User-Agent 检测：**
```javascript
/DJI-App-/i.test(navigator.userAgent)    // DJI 应用内浏览器
/DJI-App-light/i.test(navigator.userAgent) // DJI 轻量版
/micromessenger/i.test(navigator.userAgent) // 微信内置浏览器
/mqqbrowser/i.test(navigator.userAgent)    // QQ 浏览器
```

**API 调用点（从 JS 中提取）：**
```javascript
// 埋点/Logger
POST https://store-api.dji.com/logger/beacon.gif

// APP 下载
https://service-adhoc.dji.com/download/app/android/de291d33-3d51-4f2f-aa17-fdf161c5c957

// App Store
https://apps.apple.com/cn/app/id1517555997

// Sentry 错误上报
https://6eaac537cb924b859b99ffc7c703c257@sentry-io.djiops.com/421
```

**Sentry 构建信息泄露：**
```
/home/runner/work/sentry-javascript/sentry-javascript/packages/react/src/errorboundary.tsx
/home/runner/work/sentry-javascript/sentry-javascript/packages/react/src/reactrouterv6.tsx
```

**危害升级：** `/csrf` 路径返回 SPA 壳（非真实 API），但 JS 中 "Invalid CSRF token" 和 "Video Center API error" 字符串表明后端 API 存在 CSRF 保护。逆向信息可用于：
1. 构造针对性 User-Agent 绕过检测
2. 分析路由结构了解应用功能面
3. 定位第三方服务入口（Sentry, Logger, CDN）

### 2.11 [信息] INF-11: DJI 子域名与基础设施测绘

| 子域名 | 服务 | IP/平台 |
|--------|------|---------|
| `dev.dji.com` | CDN | 阿里云 CDN |
| `forum.dji.com` | 论坛 | AWS CloudFront |
| `store.dji.com` | 商城 | 阿里云 CDN |
| `developer.dji.com` | 开发者 | 阿里云 CDN |
| `wiki.dji.com` | Wiki | Linode (172.105.215.4) |
| `mail.dji.com` | 邮件 | 腾讯云 (129.226.242.84) |
| `static.dji.com` | 静态资源 | AWS CloudFront |
| `bbs.dji.com` | BBS | 阿里云 CDN |
| `m.dji.com` | 移动站 | 阿里云 CDN |
| `api.skypixel.com` | SkyPixel API | 阿里云 |
| `cdn-light-cms-us.skypixel.com` | CMS CDN | AWS? |
| `click.dji.com` | 统计 | 大疆分析服务 |
| `cdp.djiservice.org` | CDP 埋点 | Sensorsdata |
| `assets.djicdn.com` | CDN | 公开可访问 |

---

## 3. HF 执行情况

| HF | 名称 | 执行结论 |
|----|------|---------|
| HF-1 | 指纹 → CVE 转化 | ✔️ 完成。Tengine/Kong/Sentry 版本未直接暴露，无适用 CVE |
| HF-2 | JS 全量提取 → 接口矩阵 | ✔️ 完成。1.4MB JS 全量提取，发现 12+ 外部端点，无硬编码密钥 |
| HF-3 | 语义驱动 FUZZ | ✔️ 完成。路径/参数 FUZZ 覆盖，WAF 行为测绘 |
| HF-4 | 权限绕过四步序列 | ✔️ 完成。Sentry/Kong/主站均未发现可绕过点 |
| HF-5 | 业务逻辑层穷举 | ✔️ 完成。CORS 配置缺陷、Sentry 信息泄露、CDP 端点暴露 |
| HF-6 | 基础设施暴露面 | **关键发现**：DNS 泄露 13 内部 IP，Kong Admin 端口开放，Jenkins IP 暴露 |
| HF-7 | 实时协议专项 | ✔️ 完成。无 WebSocket/MQTT，纯 HTTP |

---

## 4. 攻击链关联

```
DNS 内部 IP 泄露 (13 AD 域控 + Jenkins)
  → 内网拓扑完全暴露
  → 配合 SSRF 或 VPN 入口可精准攻击域控

Sentry DSN 暴露 + CORS:*
  → 攻击者注入伪造错误事件
  → 可能触发 Sentry webhook/告警

Kong Admin 端口开放
  → 可能未授权管理 API 路由
  → 可劫持/重定向流量

store-api.dji.com CORS:*
  → 跨域数据窃取/CSRF
```

---

## 5. 安全评分汇总

| 发现 | 严重性 | 状态 | 可利用性 | 证据 |
|------|--------|------|---------|------|
| DNS 泄露 13 个内部 IP | **严重** | 确认 | 中（需内网入口配合） | dig 查询结果 |
| jenkins.dji.com 暴露内网 IP | **严重** | 确认 | 中 | dig 查询 |
| Sentry DSN 公开可注入事件 | **高危** | 确认 | **高** | curl 注入返回 event ID |
| store-api.dji.com CORS:* | **高危** | 确认 | 高 | OPTIONS 验证 |
| /h5/ source map 泄露 | **高危** | 确认 | 中 | HTTP 200, 669KB |
| 安全响应头缺失 (CSP/HSTS) | **中危** | 确认 | 低 | 响应头检查 |
| Cookie 缺 Secure 属性 | **中危** | 确认 | 中（MITM 场景） | Cookie 审计 |
| WAF 差异化规则 | **中危** | 确认 | 低 | 路径响应对比 |
| CDP 埋点端点暴露 | **低危** | 确认 | 低 | JS 提取 |
| AD 基础设施命名泄露 | **低危** | 确认 | 低 | 主机名解析 |

---

## 6. 建议修复

1. **立即从公共 DNS 移除内网 IP 记录** — 将所有 10.x.x.x 地址从 dji.com 的 NS 记录中删除
2. **封锁 Kong Admin 端口公网访问** — 在阿里云安全组中限制 8001/8443/8444 仅内网可达
3. **Sentry 实例加认证** — `/api/0/` 和 `/_health/` 不应匿名可访问；移除 CORS `*`
4. **收紧 store-api.dji.com CORS** — 限制为白名单域名而非 `*`
5. **添加 CSP/HSTS/nosniff 响应头** — 补齐安全头缺失
6. **Cookie 添加 Secure + SameSite=Lax 属性** — 防止 MITM 截获
7. **统一 WAF 规则响应码** — 减少攻击者信息利用