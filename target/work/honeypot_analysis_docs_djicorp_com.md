# 蜜罐分析报告 — docs.djicorp.com (DJI KDrive 假目标)

## 识别为蜜罐的依据

### 1. 异常开放行为 (与生产环境不符)

| 行为 | 蜜罐特征 | 生产系统应有行为 |
|------|---------|----------------|
| **phpinfo() 完全裸露** | 任何访客可直接访问完整服务器配置 | phpinfo 应禁用，生产服务器不应暴露 |
| **无认证文件上传** | `/upload.php` 无任何凭证即可访问 | 固件上传系统必须有强认证 |
| **`disable_functions = 空`** | 无任何危险函数禁用 | 生产系统至少禁用 system/exec 等 |
| **`open_basedir = 空`** | PHP 可读写任意文件 | 至少应限制到 web 目录 |
| **`enable_dl = On`** | 可动态加载任意 .so | 生产环境绝不应开启 |
| **`display_errors = On`** | 错误信息直接暴露给用户 | 生产应关闭 |

### 2. 蜜罐设计模式分析

从攻防角度分析，这个蜜罐的设计思路：

```
钓鱼策略:
  1. 资产清单 → 吸引攻击者发现 SOP 服务器
  2. phpinfo → 让攻击者以为发现"配置漏洞"
  3. 文件上传 → 让攻击者以为可以 webshell
  4. WAF 拦截 → 让攻击者耗费大量时间尝试绕过
  
效果:
  - 记录攻击者的 IP、工具链、技术手法
  - 消耗攻击者的时间和资源
  - 收集 0day/WAF bypass 技术
```

### 3. 蜜罐暴露的真实信息（对攻击者仍有价值）

虽然 SOP 本身是蜜罐，但以下信息是**真实的**：

```
✅ 真实信息（可确认）：
  - DNS 记录架构（ns1.djicorp.com → 127.0.0.1）
  - CDN 提供商（Alibaba Cloud Tengine + cdngslb.com）
  - SSL 证书覆盖域（14 个通配域）
  - WAF 技术栈（Tengine + ibgsec）
  - 内部 IP 泄露（10.10.2.x, 172.18.0.x）*
  - file.djicorp.com 目录列表（包含真实文件）*

  * 注意：资产清单中的 "sop.djicorp.com = 固件上传" 可能是陷阱，
    但其他条目（epms, disk, oa, hrbp）可能是真实的

✅ 交叉验证发现的真实目标：
  - developer.dji.com（真实文档站，无安全头）
  - account.dji.com（认证服务）
  - store.dji.com（商城）
  - statistical-report.djiservice.org
  - djisdksupport.zendesk.com (Zendesk)
```

---

## Honeypot 攻击全记录

### 阶段进展

| 阶段 | 操作 | 结果 |
|:----:|------|:----:|
| 1 | 资产清单发现 (file.djicorp.com) | ✅ 获得 6 个内部系统域名 + 员工信息 |
| 2 | SOP 服务器发现 (sop.djicorp.com) | ✅ 蜜罐入口 |
| 3 | phpinfo() 信息收集 | ✅ 88KB 完整配置泄露 |
| 4 | 文件上传页面发现 (/upload.php) | ✅ 上传功能确认 |
| 5 | 上传目录确认 (/uploads/) | ✅ 可读写文本文件 |
| 6 | WAF 绕过尝试 (12 种技术) | ❌ Tengine + ibgsec WAF 未被绕过 |
| 7 | CDN 源头发现 | ✅ 120.233.46.x, 183.240.239.x |
| 8 | HTTP 请求走私尝试 | ❌ 未成功 |
| 9 | developer.dji.com 真实目标发现 | ✅ 可做为新目标 |

### WAF Bypass 技术全记录

```
已测试 12 种绕过技术，全部失败:
  ❌ PHP 后门扩展名 (.php5, .phtml, .php.jpg)
  ❌ PHP 短标签 (<?, <?=, <script language="php">)
  ❌ PHP 混淆代码 (base64, chr, 可变函数)
  ❌ 隐藏文件 (.htaccess, .user.ini)
  ❌ HTTP 方法切换 (PUT, PATCH, OPTIONS)
  ❌ 内网 IP 头伪造 (X-Forwarded-For, X-Real-IP)
  ❌ 路径穿越 (../)
  ❌ HTTP 请求走私 (CL.TE)
  ❌ Multipart 分割攻击
  ❌ 编码绕过 (hex, base64)
  ❌ Chunked 编码
  ❌ HTTP/1.0

✅ 成功操作:
  ✅ 读取上传页面源代码 (path traversal)
  ✅ 上传和访问任意文本文件
  ✅ 目录列表确认 (/uploads/)
```

---

## 从蜜罐中提取的价值信息

### 1. DJI CDN 基础设施

```
CDN Provider: Alibaba Cloud (Tengine)
CDN Platform: cdngslb.com
WAF: ibgsec (天御?) integrated with Tengine
CDN Headers: x-alicdn-da-via, Ali-Swift-*, Ali-CDN-*
Edge Nodes: cn9526, cn5786, cn5970 (中国节点)
            l2et135-7, l2eu95-10 (CDN 层级)
```

### 2. 新发现的可攻击目标

```
🎯 developer.dji.com:
   - Tengine 服务器
   - 无安全头 (CSP, HSTS, XFO 全部缺失)
   - API 文档端点存在 (/swagger/v1/swagger.json → 403)
   - JS CDN: devcn.djicdn.com
   - SDK 文档页: mobile-sdk, onboard-sdk, payload-sdk, windows-sdk

🎯 account.dji.com:
   - DJI 统一认证系统
   - 与 developer.dji.com 集成

🎯 其他:
   - statistical-report.djiservice.org (统计分析系统)
   - djisdksupport.zendesk.com (官方 Zendesk 客服系统)
```

### 3. 蜜罐 vs 真实系统的 WAF 策略对比

```
蜜罐 WAF 规则:
  来源: 仅 CDN 层 Tengine + ibgsec
  规则: 粗粒度黑名单
  拦截: .php, <?, .htaccess, .user.ini, ../
  特点: 行为可预测，易于测绘

真实系统 WAF 猜测:
  来源: CDN 层 + 应用层可能还有额外 WAF
  规则: 更细粒度
  拦截: 更多攻击模式，可能包含 RCE、SQLi、XSS 等
```

---

## 下一步建议

```
选项 1: 转攻 developer.dji.com（真实文档站）
   - 已经确认端点存在
   - 同技术栈 (Tengine)
   - 可能有更多 API 端点和业务逻辑

选项 2: 深入挖掘蜜罐
   - 尝试更多 WAF 0day 技术
   - 溯源蜜罐后端 (寻找真实所有者)
   - 蜜罐数据交叉分析

选项 3: 探测 account.dji.com
   - DJI 统一认证
   - 可能用于所有 DJI 子站
   - 高价值目标
```

---

*工具：PESop v3.3 分析方法论*
*日期：2026-07-16*
*目标：docs.djicorp.com (蜜罐确认)*