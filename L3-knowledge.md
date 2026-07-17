# L3 · 经验库（增长层）

> 每个项目收尾回灌。只增不删。反复出现的模式 → 提炼进 L1/L2。
> 这是整套 SOP 的复利发动机。
> 版本 v2.0 · 2026-07-01。沉淀区已回灌第一个实战项目（dreamcoder.djicorp.com）。
> L3 内容不受 v3.0 架构重构影响（该重构只调整 L1/L2 的分层，不改变本文件结构）。

## 回灌模板（每个项目复制一段填）

```
### [2026-07-15] · repair.ryzerobotics.com（Ryze 维修系统 - DJI 生态）
- AI 漏报：本次 AI 没主动想到的点 →
  - JS 中硬编码的 WeChat AppKey（`FFFF0N5N000000005F55`）——前端 WeChat OAuth 集成暴露了微信应用密钥
  - `/api/v1/Repair/GetAgentsList` 等 6 个端点无需认证即可访问——泄露了 DJI Store 等销售渠道的内部编码
  - ASP.NET MVC 版本头 `X-AspNetMvc-Version: 5.2` 和 `X-AspNet-Version: 4.0.30319` 直接暴露
  - Heimdallr 内部 API 网关（v0.5.37）在测试子域名下暴露
- 业务逻辑漏报：技术指纹跑了、但漏掉的业务逻辑洞 →
  - SendVerificationCode 端点无频率限制，可用于暴力枚举手机号/邮箱
  - SubmitCase 端点无完整认证校验，仅需验证码即可提交
  - 验证码错误提示 "验证码错误，请重新获取" 可被用来测试验证码有效性
- 有效新招：这次好用的打法/提问方式 →
  - "JS bundle 中搜索 SENTRY_DSN / WECHAT_APPKEY / API_KEY 等大写常量名"
  - "ASP.NET 应用优先找 `/api/v1/` 和 `/guava/api/v1/` 等路径模式"
  - "测试环境子域名枚举：`www.{domain}beta.com` / `api.{domain}beta.com` / `static.{domain}beta.me`"
- 命中的攻击链：哪些组合出现了严重/高危 →
  - Sentry DSN 注入 + API 未授权 + WeChat AppKey = 全链路攻击面（可注入事件、窃取渠道数据、微信钓鱼）
- 待提炼：是否该进 L1/L2 →
  - 是：微信生态（WeChat OAuth/小程序）相关的密钥搜索应加入 HF-2 JS 全量提取的检查清单
  - 是：ASP.NET 应用的响应头版本泄露（X-AspNet-Version）应加入 HF-1 指纹识别强制项
  - 是：API 无认证检测（HF-4）应覆盖 "返回 IsSuccess/Code 结构但不要求 token" 的场景

---
- AI 漏报：本次 AI 没主动想到的点 →
  - DNS NS 记录解析：初始侦察只关注了主站路径，未递归解析 NS 层级的 A 记录来发现内部 IP 泄露
  - Kong Admin 端口扫描：未主动探测 Kong Admin API 的标准端口（8001/8443/8444），导致遗漏了端口开放风险
  - Sentry DSN 中提取 project_id 后未进一步验证是否可枚举相邻项目 ID（420-426 均存活）
  - Alibaba WAF 规则差异化：初始未发现 `.gitattributes` 返回 403 而 `.git/config` 返回 405 的规则差异信号
- 业务逻辑漏报：技术指纹跑了、但漏掉的业务逻辑洞 →
  - (本次目标为纯静态 SPA，无服务端业务逻辑接口)
- 谎报/误报（含 CVE 幻觉）：确认未带 PoC、脑补漏洞、夸大评级、报无源 CVE →
  - (无)
- 有效新招：这次好用的打法/提问方式 →
  - "从 dji.com 的 NS 记录逐条解析 A 记录——是否存在 10.x.x.x 内网地址？"
  - "对 Kong 网关扫描标准 Admin 端口（8001/8443/8444）——是否对外开放？"
  - "自建 Sentry 实例的 /api/0/ 和 /_health/ 是否可匿名访问？"
  - "WAF 对 `.gitattributes` 和 `.git/config` 的响应码是否不同——是否存在规则绕过的信号？"
- 命中的攻击链：哪些组合出现了高危/严重 →
  - DNS 内部 IP 泄露 + Kong Admin 端口开放 = 内网基础设施横向移动路径
  - Sentry DSN 暴露 + CORS:* = 第三方注入伪造错误事件
- 待提炼：是否该进 L1/L2 →
  - 是：侦察阶段强制添加 DNS 深度解析步骤——递归解析子域名的 A 记录（尤其是 NS 托管记录），检查是否存在 RFC 1918 地址泄露
  - 是：基础设施暴露面（HF-6）需补充 Kong Admin 端口默认扫描项
  - 是：自建 Sentry/类似监控系统应纳入 CVE 检查和匿名访问验证

---
- AI 漏报：本次 AI 没主动想到的点 →
  - Zendesk `/api/v2/users/me` 对匿名用户返回 `authenticity_token`：初始侦察未识别该端点的 CSRF token 复用风险
  - 登录/密码重置端点缺少速率限制：AI 初始报告中未对比连续请求的 HTTP 状态码差异来确认限流是否存在
  - Next.js `_buildManifest.js` 中的路由表未被系统解析为攻击面（仅列了 JS 文件列表，未提取路由路径）
- 业务逻辑漏报：技术指纹跑了、但漏掉的业务逻辑洞 →
  - `/password/validate_password` 端点未认证即可调用，泄露密码策略强度判断
  - `/access/request_oauth` 未验证 `state` 参数随机性（标准 Zendesk 行为但需确认此实例是否配置）
- 谎报/误报（含 CVE 幻觉）：确认未带 PoC、脑补漏洞、夸大评级、报无源 CVE →
  - (无)
- 有效新招：这次好用的打法/提问方式 →
  - "Zendesk Help Center `/api/v2/users/me` 对匿名用户返回什么？"
  - "连续 5 次失败登录是否触发速率限制——HTTP 429 还是 200？"
  - "JS chunks 的 `_buildManifest.js` 路由表提取——直接从 `/api/v2/users/me` 和 `_buildManifest.js` 两个来源交叉验证接口清单"
- 命中的攻击链：哪些组合出现了中危 →
  - `authenticity_token` 泄露 + 无速率限制 = CSRF 绕过 + 暴力破解风险组合
  - robots.txt 暴露管理路径 + 部分路径未完全加固 = 隐蔽攻击面扩大
- 待提炼：是否该进 L1/L2 →
  - 否：Zendesk 特定模式太垂直（不通用），记在 L3 即可
  - 是：侦察阶段对 SaaS 平台（Zendesk/Salesforce 等）补充：`/api/v2/{service}/users/me` 类端点需测试匿名访问
  - 是：速率检测应作为 FUZZ 前置检查：连续 N 次请求后检查 X-RateLimit-* 头和 429 状态

---
- AI 漏报：本次 AI 没主动想到的点 →
  - DNS 深度解析：初始只扫了主站域名，未递归枚举 `*.djicorp.com` 的子域 A 记录，导致遗漏了 18+ 子域和 9 个 RFC 1918 内部 IP
  - Envoy 规则分析不系统：第一次 403 后仅尝试了 5-6 种绕过方式就放弃，未做系统性 Content-Type 枚举（大小写、参数后缀、变体）
  - gRPC 探测路径：第一次 gRPC 探测只随便猜了一个路径，未意识到需要系统枚举 gRPC 服务名模式
  - 鉴权测试：第一次认证测试只试了 5-6 种常见头就停止，未扩展到 DJI 生态特有的认证体系（Gw-S、X-DJI-*、OAuth2 client_id）
- 业务逻辑漏报：技术指纹跑了、但漏掉的业务逻辑洞 →
  - Envoy 对 REST 路径和 gRPC 路径的不一致处理本身就是逻辑漏洞——REST 被严格拦截，gRPC 却被放行
  - 后端 gRPC 拦截器的 "统一 PERMISSION_DENIED" 掩盖了真实的方法是否存在——无法区分"方法不存在"和"方法存在但需认证"
  - 443 端口 TLS 握手失败但 TCP 端口开放——可能是内部服务暴露或配置错误
- 谎报/误报（含 CVE 幻觉）：确认未带 PoC、脑补漏洞、夸大评级、报无源 CVE →
  - 已避免：所有 gRPC 服务名标注为"推测"，不确认具体 package 名
  - 已避免：不将 "所有路径返回相同 grpc-status: 7" 解读为"所有方法都存在"
- 有效新招：这次好用的打法/提问方式 →
  - "Envoy 对 Content-Type 的大小写是否敏感？尝试 `content-type` vs `Content-Type` vs `CONTENT-TYPE`"
  - "把 API 当成 gRPC 来测——如果 REST 全部 403，试着把 Content-Type 改成 `application/grpc` 看看是否穿透"
  - "gRPC 服务名枚举模式：`/{package}.{ServiceName}/{MethodName}`，package 从短到长（`FaceService` → `face.FaceService` → `com.dji.face.FaceService`），方法用业务词（Recognize/Detect/Verify/Register/Search/Auth/Health）"
  - "gRPC vs REST 的行为差异：gRPC 返回 HTTP 200 + `grpc-status: 7`（PERMISSION_DENIED）而 REST 返回 HTTP 403，两者是不同的拦截层"
  - "Content-Type 绕过要分两层：一是 Envoy 层的 Content-Type 匹配规则（精确？前缀？大小写？参数？），二是后端业务层的接口发现"
  - "当后端统一返回 PERMISSION_DENIED 时，测试顺序是：先验证 gRPC 协议穿透（200 + grpc-status）→ 再枚举服务名 → 最后暴力认证头"
  - "DNS 枚举不能只扫目标子域，要递归解析整个域名的 A/AAAA 记录来发现内网 IP 泄露"
  - "SSL 证书 SAN 条目是隐藏的攻击面——`openssl s_client -connect domain:443 | openssl x509 -text -noout | grep DNS`"
- 命中的攻击链：哪些组合出现了严重/高危 →
  - Envoy Content-Type 绕过 + gRPC 协议穿透 = 绕过了一层防御直接到达后端拦截器
  - DNS 内部 IP 泄露 + 已知服务名 = 如果获得内网访问可直接访问后端服务
- 待提炼：是否该进 L1/L2 →
  - 是：HF-1 指纹识别补充 Envoy/Istio 判断标准（`server: istio-envoy`、gRPC 协议特征）
  - 是：HF-3 FUZZ 补充 Content-Type 枚举策略（大小写、参数、变体）作为 WAF 规则探测前置
  - 是：HF-4 授权绕过补充 gRPC 协议测试流程（替换 Content-Type → 枚举服务名 → 测试认证头）
  - 是：侦察阶段补充 DNS 深度枚举 + SSL 证书 SAN 提取作为强制项
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

**以"这是第三方库/SDK"为由跳过 JS 文件分析**
- 症状：看到 Cesium.js、WASM 文件、drtc SDK 等，默认判定"不包含 API 端点" → 不下载不分析
- 损失：可能遗漏信令服务器地址、硬编码密钥、STUN/TURN 配置、内部资源路径
- 对治（进 L2）：强制要求 JS 资产表记录每个跳过文件的理由 + 标注"但未验证"

**不利用响应头微秒级时序差异判断端点存活**
- 症状：用状态码 + 内容长度筛选存活端点，忽略 SPA fallback 和真实响应的 Latency 差异
- 损失：可能漏掉存活但被 SPA fallback 掩盖的端点
- 对治（进 L2）：补充利用 `X-Kong-Upstream-Latency` 等响应头差异判断端点的指令

**Envoy/Istio 场景下不测试 gRPC 协议穿透**
- 症状：REST 路径全部 403 后，不尝试用 `Content-Type: application/grpc` 绕过 Envoy 直连后端
- 损失：无法发现后端的真实服务暴露面（gRPC 服务名、方法、认证机制）
- 对治（进 L2）：遇到 Envoy 403 后，强制测试 gRPC 协议穿透作为第一步绕过

**gRPC 服务名枚举不系统**
- 症状：随便猜一个路径就停，不系统性枚举 package 名（短→长）、服务名和方法名组合
- 损失：可能遗漏真实的服务端点
- 对治：gRPC 枚举公式 → `/{package}.{ServiceName}/{Method}`，package 从 `face` → `face.v1` → `com.dji.face` → `dji.face` 逐级递增

**Content-Type 绕过只试标准值**
- 症状：只试 `application/grpc` 一个值，不测试大小写、参数后缀、协议变体（`+proto`、`+json`）
- 损失：可能错过 Envoy 规则差异带来的绕过机会
- 对治：Content-Type 枚举矩阵应覆盖：精确值、大小写、参数（`; charset`）、变体（`+proto`）

**DNS 枚举不递归解析子域**
- 症状：只扫目标域名本身，不枚举 `*.domain.com` 的全部子域 A/AAAA 记录
- 损失：遗漏内部 IP 泄露、管理面入口、测试环境
- 对治：强制使用大字典枚举子域 + 递归解析每个子域的全部 DNS 记录类型

### 业务逻辑层漏报（v1.1 新增·治"清单≠覆盖"）
- (待填)

### AI 谎报/误报模式（v1.2 新增·确认必带 PoC，含 CVE 幻觉）
- (待填)

### 产品身份识别漏报：识别出产品后不加载该产品的已知漏洞库（v3.3 新增）

**发现问题**：
在 gcac.djicorp.com 测试中，通过 JS 版权声明识别出系统为**竹云 IAM 7.0.1.1-RELEASE**（深圳竹云科技有限公司），
但停留在了"信息泄露盘点"层面，没有立刻从已知漏洞库中加载竹云 IAM 的已知 CVE 和攻击模式进行定向验证。

**本质认知**：
- 识别产品身份（名称 + 版本）不是一个"记录字段"，而是一个**攻击面切换触发器**
- 识别出产品后，必须立即执行：
  1. 查询该产品的已知 CVE/漏洞库
  2. 根据版本号判断哪些漏洞适用
  3. 加载该产品常见错误配置清单
  4. 加载该产品特有的攻击面路径
- 不执行以上步骤 = "识别出了但没用上" = 等同于没识别出来

**实战信令（判断触发条件）**：

| 触发信号 | 切换动作 |
|---------|---------|
| 发现产品版权声明 / 版本号 / 特征路径 | 立即查询该产品已知漏洞 |
| 产品是商业/开源 IAM（如竹云、Keycloak、OAuth 2.0 服务） | 检查 OAuth CSRF、开放重定向、SAML 配置泄露、JWT 实现缺陷 |
| 产品是商业/开源 WAF/网关（如 Cloudflare、Kong） | 检查已知绕过模式、配置错误、管理端暴露 |
| 产品是框架（如 Spring Boot、Rails、Django） | 检查版本 CVE、默认端点、调试模式 |

**竹云 IAM 已知攻击面检查清单（沉淀复用）：**
```
□ OAuth redirect_uri 绕过（白名单跳转、协议混淆、子域名绕过）
□ SAML metadata 未鉴权（证书泄露、SSO 端点暴露）
□ JWT 实现缺陷（alg=none、key confusion、弱密钥、算法未锁定）
□ 密码重置逻辑（token 可预测、验证码绕过、步骤跳过）
□ 扫码登录 CSRF（qrcode 可被攻击者生成并诱导扫码）
□ config.js 硬编码 secretKey / 内部地址
□ 隐式授权流程未禁用（response_type=token 仍可访问）
□ OIDC Discovery 文档公开（攻击面扩大）
□ 内部服务地址泄露（auth.bam.bamboocloud.com 类内部域名）
□ CORS 配置不一致（部分端点 Access-Control-Allow-Origin: *）
```

### 元框架沉淀：Q1-Q5 科学推理模型（v3.3 新增·治"清单≠覆盖"的元思维）

**发现问题**：
在 face-recognition-api.djicorp.com 项目中，AI 的默认工作方式是：扫 → 遇到 403 → 记录 → 收工。
用户一句话"思路改变一下，这是人脸识别系统，Spring Boot 开发的"——让 AI 切换角色，
结果触发了完全不同的攻击路径。本质差距不在技巧，在思维框架：从"我该试什么攻击"变成了"这个系统是什么、怎么建的、哪里会坏"。

**本质认知**：
- **清单驱动的测试**：遇到墙就停，因为清单上没有"穿墙"这一项
- **元框架驱动的测试**：把防御当作信号来推理——画规则 → 找缺口 → 循环迭代

**实战信令（判断该切换元框架的触发条件）**：

| 触发信号 | 切换动作 |
|---------|---------|
| 目标有明确业务命名（如 face-recognition、payment、auth） | 走 Q2（共情建模）推导技术选型 |
| 目标来自已知生态（如 DJI、阿里、腾讯） | 拉取该生态的历史漏洞模式和认证方案 |
| 常规扫描全部返回 403/401 | 走 Q1（身份识别）定位防御层，再定绕过策略 |
| 目标技术栈已知（Spring Boot、ASP.NET、Go） | 加载该框架的默认配置缺陷和已知 CVE 模式 |

### 科学推理测试模型实战案例（所有攻击链模式的元框架）

> 以下所有「复用攻击链模式」都是此元框架在特定目标类型上的实例化应用。
> 这不是"Envoy 绕过技巧"，而是这个模型在任何 403 场景下的通用走法——
> 换成 Cloudflare WAF、换成 Spring Security、换成自定义中间件，Q1-Q5 流程完全不变，
> 变的只是 Q1 的判定信号和 Q4 的测试维度重点。

**Q1：身份识别**
```
响应头 server: istio-envoy
响应体 "RBAC: access denied"
→ 判定：API 网关层（Envoy/Istio），不是 WAF，不是应用层
→ 策略来源：Envoy 的 gRPC filter 和 RBAC 配置模式
```

**Q2：共情建模**
```
系统：DJI 人脸识别 API
如果是开发者：
  - 技术选型：Spring Boot + gRPC（protobuf 高性能序列化适合图像传输）
  - 网关：Envoy + Istio AuthorizationPolicy
  - 鉴权：ServerInterceptor + Bearer JWT
  - 最容易遗漏：gRPC/JSON 转码配置、Content-Type 白名单缺口、调试头残留
```

**Q3：假设生成**
```
H1：Envoy 规则不是基于路径的，而是基于 Content-Type
H2：gRPC 流量可能不受 REST 端点的 RBAC 约束
H3：gRPC 反射可能暴露完整 API 结构
H4：可能存在调试/开发认证头
```

**Q4：实验设计（变量隔离）**
```
控制组：POST /api/v1/face/recognize + Content-Type: application/json → 403
实验 1：POST /api/v1/face/recognize + Content-Type: application/grpc → 200  ← H1 成立
实验 2：POST /face.FaceService/Recognize + Content-Type: application/json → 403
实验 3：GET + app/grpc → 200，PUT + app/grpc → 200，HEAD + app/grpc → 200
实验 4：app/grpc+proto → 200，app/grpc+json → 200，app/grpc;charset → 403
实验 5：100+ auth header combos → all 200/7 (PERMISSION_DENIED)
```

**Q5：循环迭代**
```
第 1 轮：规则已画出——Envoy 精确匹配 Content-Type: application/grpc（含 +proto/+json，拒绝参数）
← 切到认证头维度 →
第 2 轮：所有认证组合返回 PERMISSION_DENIED
← 切到服务名枚举维度 →
第 3 轮：face.FaceService 5 方法 + 反射 + 健康检查均存在但需认证
← 结论：需外部有效令牌，当前网络位置无法进一步推进
```

### 高命中提问话术（思路类）

- **通用激活问（任何目标）**："先不要动手，回答 Q1-Q5：这是什么系统、在哪一层、如果是你开发会怎么建、最可能在哪坏、怎么验证？不回答完不许测试。"
- **遇到 403 时**："不要问'怎么绕过'，问——这是谁给的 403？它在检查哪个变量？什么请求不 403？我能不能只改一个维度来画出它的规则边界？"
- **遇到 401 时**："先判断鉴权框架的身份（Spring Security？Shiro？自定义？），查该框架已知的绕过模式，再设计方案"
- **技术栈识别**："从响应头和响应体的格式判断这个防御是谁给的——server 头、X-Powered-By、错误页风格、响应体结构都是信号"
- **变量隔离**："控制组是什么？这次只改了什么？实验结果告诉了我什么规则？如果没绕过——这个维度不行，还是所有维度都不行？"
- **认知纠偏**："你是在穷举绕过清单，还是在推理规则？如果是前者，停下来，先回答 Q1-Q2"

### 复用攻击链模式（Q1-Q5 框架的应用实例）

> 以下模式均为 Q1-Q5 元框架在特定目标类型上的实例。其中 Q1（身份识别系统类型）→ Q2（构建该生态的已知缺陷模型）→ Q4（设计实验验证）。

**OAuth CSRF → 登录劫持**
（Q1：识别 OAuth 提供商 → Q2：构建 CSRF 漏洞的缺陷模型 → Q4：测试 state 参数的随机性）
- 入口：发现 OAuth login 端点 state 参数无随机值
- 打法：构造恶意 state（含攻击者控制的 redirect_url），诱导已登录用户点击
- 结果：用户完成 OAuth 登录后被重定向到攻击者页面，token/cookie 被截获
- 条件：state 无 CSRF nonce + redirect_url 无服务端校验

**SSO 配置泄漏 → secretKey 提取**
（Q1：识别 SSO 系统 → Q2：推断配置文件位置约定 → Q4：探测已知路径）
- 入口：发现 SSO 前端 SPA
- 打法：找 `/static/config.js` 或 `/env.js` 等配置文件
- 结果：获取 secretKey 用于后续攻击

**Envoy Content-Type 绕过 → gRPC 后端暴露**
（Q1：识别网关层（server: istio-envoy）→ Q2：构建 Envoy gRPC filter 配置模型 → Q4：变量隔离测试 Content-Type 变体）
- 入口：目标返回 `server: istio-envoy` + 所有 REST 端点 403
- 打法：见上方「科学推理测试模型实战案例」的完整 Q1-Q5 推演
- 结果：穿透一层防御，摸清后端 gRPC 服务结构

**DNS 内部 IP 泄露 → 内网拓扑映射**
（Q1：识别内部子域 → Q2：构建 DNS 配置的常见缺陷模型 → Q4：递归解析所有 DNS 记录类型）
- 入口：目标域名
- 打法：
  1. 爆破 `*.target.com` 子域
  2. 解析每个子域的 A/AAAA 记录
  3. 标记所有 RFC 1918 地址（10.x.x.x, 172.16.x.x, 192.168.x.x）
  4. 标记所有特殊地址（240.x.x.x 等）
  5. 从 SSL 证书 SAN 提取更多关联域名，重复步骤 1-4
- 结果：获得完整的内部网络拓扑（开发/测试/管理/VPN/跳板机/SSO 的 IP 地址）

### 框架推导笔记（AI 识别后的弱点类，按组件累积）
- (待填)
