# L3 · 经验库（增长层）

> 每个项目收尾回灌。只增不删。反复出现的模式 → 提炼进 L1/L2。
> 这是整套 SOP 的复利发动机。
> 版本 v1.2 · 2026-06-30。沉淀区暂空——等第一个实战项目回灌，不预填编造。

## 回灌模板（每个项目复制一段填）

```
### [2026-07-01] · dreamcoder.djicorp.com（DJI 大疆）
- AI 漏报：本次 AI 没主动想到的点 →
  - OAuth/SSO 服务端侧未做指纹识别（发现 `iam-migrate` 路径后满足于"自建 SSO"结论，没有查 `/.well-known/oauth-authorization-server`、`/oauth/token` 等标准端点行为差异来判断具体实现）
  - JS 被 CDN 拦截后没有尝试多种绕过方式（如分析 CSS 中的资源引用路径、通过 Kong 走不同路径模式、检查不同 CDN 域名规则差异）
  - 没有区分 SPA fallback（固定 1928 bytes）和真实 404（0 bytes）的细粒度差异
  - 没有利用 `X-Kong-Upstream-Latency` 等响应头延迟差异来判断端点存活
  - 没有检查 SSO 子域名（如 `api.gcac.djicorp.com`）
  - 没有从 SSO 的 `chunk-vendors.js`（2.1MB）中提取完整 API 路由表
- 业务逻辑漏报：技术指纹跑了、但漏掉的业务逻辑洞 →
  - OAuth CSRF（state 仅为 base64 编码的 JSON，无随机 nonce，可被攻击者构造）
  - OAuth 开放重定向（login 端点 redirect_url 无输入校验，接受 `javascript:`/`data:`/任意URL）
- 谎报/误报（含 CVE 幻觉）：确认未带 PoC、脑补漏洞、夸大评级、报无源 CVE →
  - (无)
- 有效新招：这次好用的打法/提问方式 →
  - "从响应头 X-Kong-Upstream-Latency 的微秒级差异判断端点是否真实存活"
  - "OAuth state 字段的 base64 解码分析 —— 发现仅含 redirect_url 无 CSRF nonce"
  - "SSO 页面 config.js 中硬编码的 secretKey 发现"
- 命中的攻击链：哪些组合出了高危 →
  - OAuth CSRF + 开放重定向 = 登录劫持攻击链
  - SSO 配置泄漏 + callback 端点参数校验泄漏 = 攻击面扩大
- 待提炼：是否该进 L1/L2 →
  - 是：侦察阶段需要补充对 OAuth/SSO 类系统专项指纹识别的强制项
  - 是：JS 全量强制项需要补充 CDN/WAF 拦截时的绕过策略清单
```

---

## 经验沉淀区（按主题累积）

### AI 漏报模式

**OAuth/SSO 系统不做服务端指纹识别**
- 症状：发现 `/.well-known/` 或 `/oauth/` 路径后，仅满足于识别出"这是自建 SSO"，不继续查标准 OAuth 端点的响应差异来判断具体实现（是 Keycloak？Dex？ORY Hydra？Spring Security OAuth？还是某国产 IDP？）
- 损失：丧失针对特定实现查 CVE 的机会
- 对治（进 L2）：侦察阶段强制 OAuth/SSO 系统的服务端指纹识别

**JS 被 CDN/WAF 拦截后只试 2-3 种绕过方式就放弃**
- 症状：curl 加 Referer、User-Agent、Origin 后仍有 0 bytes 返回 → "下不来，算了"
- 损失：接口矩阵严重残缺
- 对治（进 L2）：补充 CDN 绕过策略清单：检查 CSS 资源引用路径、通过主域不同子路径尝试、检查是否有备选 CDN 域名、尝试 Kong 反代路径

**不利用响应头微秒级时序差异判断端点存活**
- 症状：用状态码 + 内容长度筛选存活端点，忽略 SPA fallback 和真实响应的 Latency 差异
- 损失：可能漏掉存活但被 SPA fallback 掩盖的端点
- 对治（进 L2）：补充利用 `X-Kong-Upstream-Latency` 等响应头差异判断端点的指令

### 业务逻辑层漏报（v1.1 新增·治"清单≠覆盖"）
- (待填)

### AI 谎报/误报模式（v1.2 新增·确认必带 PoC，含 CVE 幻觉）
- (待填)

### 高命中提问话术
- "这是 OAuth 还是 SAML？标准认证协议的话，检查 `/.well-known/oauth-authorization-server` 和 `/.well-known/openid-configuration`"
- "CDN 拦截了 JS。试试这些路径/域名：`[cdn域名]`, `[主域]/static/`, `[主域]/assets/`。CSS 文件中有没有额外的资源路径？"

### 复用攻击链模式

**OAuth CSRF → 登录劫持**
- 入口：发现 OAuth login 端点 state 参数无随机值
- 打法：构造恶意 state（含攻击者控制的 redirect_url），诱导已登录用户点击
- 结果：用户完成 OAuth 登录后被重定向到攻击者页面，token/cookie 被截获
- 条件：state 无 CSRF nonce + redirect_url 无服务端校验

**SSO 配置泄漏 → secretKey 提取**
- 入口：发现 SSO 前端 SPA
- 打法：找 `/static/config.js` 或 `/env.js` 等配置文件
- 结果：获取 secretKey 用于后续攻击

### 框架推导笔记（AI 识别后的弱点类，按组件累积）
- (待填)
