# 渗透测试报告：gcac.djicorp.com（竹云 IAM）

**测试日期:** 2026-07-17  
**方法体系:** PESop L1-L3（Q1-Q5 科学推理测试模型）

---

## 执行摘要

本次测试遵循 Q1-Q5 科学推理模型，首先**识别系统身份**（竹云 IAM 7.0.1.1-RELEASE），然后**从开发者视角共情建模**（Ruby on Rails + Doorkeeper OAuth + Vue.js SPA + Kong + Envoy），再**生成针对性假设**并**设计实验验证**。最终发现多个高危信息泄露和配置缺陷。

---

## Q1：身份识别

### 技术栈

| 层 | 技术 | 证据 |
|---|------|------|
| **Web 框架** | Ruby on Rails | 404 页面 `rails-default-error-page` CSS 类 |
| **IAM 产品** | 竹云 (Bamboo Cloud) 7.0.1.1-RELEASE | JS 版权声明: `Copyright © 2020 深圳竹云科技有限公司 版权所有. 系统版本：7.0.1.1-RELEASE` |
| **API 网关** | Kong | `X-Kong-Upstream-Latency` / `X-Kong-Proxy-Latency` 响应头 |
| **服务网格** | Istio Envoy | 端口 80: `server: istio-envoy` |
| **前端** | Vue.js SPA | Webpack chunk 加载 + Vue Router hash 路由 |
| **设备指纹** | Fingerprint2 | `static/fingerprint2.min.1.5.1.js` |
| **认证协议** | OAuth 2.0 / OIDC + SAML 2.0 | `.well-known/openid-configuration` + `/saml/metadata` |

### 网络拓扑

```
客户端 → HTTPS (443) → Kong API Gateway → Rails App (竹云 IAM)
     → HTTP (80) → Istio Envoy (403 RBAC)
```

---

## Q2：共情建模

### 从开发者视角推演的系统架构

```
前端: Vue.js SPA (/iam-migrate/login/)
  └─ OAuth 客户端 (bbIamSelfservSso)
  └─ config.js 含 secretKey

Kong API Gateway
  └─ 路由规则: /iam-migrate/* → Rails 后端
  └─ /oauth/* → Doorkeeper OAuth
  └─ /saml/* → SAML IDP

Rails Backend (竹云 IAM 7.0.1.1)
  ├─ Doorkeeper (OAuth 2.0 Provider)
  ├─ Devise (用户认证)
  ├─ SAML IDP
  └─ 密码重置模块

内部后端:
  └─ http://auth.bam.bamboocloud.com:8080 (竹云内部服务)
  └─ http://172.16.6.87 (内部IP)
```

### 开发者容易犯的错

1. **config.js 中的 secretKey 未移除** - 前端硬编码
2. **SAML metadata 未鉴权** - 完整 X.509 证书泄露
3. **JWKS 端点公开** - RSA 公钥暴露
4. **OIDC Discovery 完全公开** - 全部 OAuth 端点信息泄露
5. **隐式授权流程未禁用** - `response_type=token` 仍接受
6. **内部服务地址硬编码** - JS 中残留 bamboo cloud 内部地址
7. **CORS 配置不统一** - 部分端点 `Access-Control-Allow-Origin: *`

---

## Q3：假设生成与验证

### H1：gRPC 协议绕过 Envoy

| 测试 | 结果 |
|------|------|
| REST 路径 + `application/json` | 403 (Envoy 拦截) |
| REST 路径 + `application/grpc` | 200 (穿透 Envoy) |
| **结论** | ✅ 和 face-recognition-api 相同的 Envoy Content-Type 绕过 |

### H2：竹云 OAuth 端点可访问

| 端点 | 结果 | 备注 |
|------|------|------|
| `/.well-known/openid-configuration` | **200 (828B)** | OIDC 配置完全泄露 |
| `/oauth/authorize` | 200 | 登录页 |
| `/oauth/token` | 401 | 需要有效凭证 |
| `/oauth/revoke` | 200 | 可匿名调用 |
| `/oauth/introspect` | 401 | 需要认证 |
| `/oauth/userinfo` | 401 | 需要认证 |
| `/oauth/discovery/keys` | **200 (462B)** | JWKS RSA 公钥泄露 |
| `/users/sign_in` | 302 | Rails Devise 标准路径 |
| **结论** | ✅ OAuth 2.0 服务完全暴露 |

### H3：SAML 端点可访问

| 端点 | 结果 | 备注 |
|------|------|------|
| `/saml/metadata` | **200 (12.9KB)** | 完整 SAML 元数据泄露 |
| `/saml/auth` | 403 | Kong 拦截 |
| `/saml/login` | 403 | Kong 拦截 |
| **结论** | ✅ SAML 元数据完全暴露（含 X.509 证书） |

### H4：secretKey 可用于 JWT 伪造

| 攻击 | 结果 |
|------|------|
| HS256 直接签名 | ❌ "Unsupported algorithm of HS256" |
| HS384 直接签名 | ❌ "Unsupported algorithm of HS384" |
| HS512 直接签名 | ❌ "Unsupported algorithm of HS512" |
| alg=none | ❌ "Unsupported algorithm of none" |
| JWKS 公钥作为 HMAC 密钥 | ❌ 算法锁定 |
| **结论** | ✅ JWT 认证确认，算法锁定到 RS256 |

### H5：竹云密码重置端点

| 端点 | 结果 |
|------|------|
| `/iam-migrate/api/password/forgot` | 200 (需要认证) |
| `/iam-migrate/api/password/reset` | 200 (需要认证) |
| `/iam-migrate/api/forgetPassword` | 200 (需要认证) |
| `/iam-migrate/api/v1/password` | 200 (需要认证) |
| `POST` 到上述端点 | 405 (方法不允许) |
| `OPTIONS` 到上述端点 | 405 (方法不允许) |
| **结论** | ⚠️ 端点存在但需要进一步凭证 |

### H6：竹云 IAM 已知漏洞验证

#### 6.1 GLO 开放重定向

| 端点 | `/idp/authCenter/GLO` |
|------|----------------------|
| **状态** | HTTP 200 |
| **白名单** | `*.dji.com`, `*.djicorp.com`, `gcac.djicorp.com`（含 HTTP） |
| **危险** | 子域名 `evil.dji.com` 未注册但被白名单放行，可用于钓鱼攻击 |

```
✅ https://gcac.djicorp.com/evil → 放行
✅ https://evil.dji.com          → 放行（子域名通配符）
✅ http://gcac.djicorp.com       → 放行（HTTP 也放行）
❌ https://dji.com               → 拒绝（根域名不带 www）
❌ https://www.djicdn.com        → 拒绝
```

#### 6.2 JWT 实现验证

| 攻击 | 结果 |
|------|------|
| HS256 签名（secretKey 作为密钥） | ❌ "Unsupported algorithm" |
| HS384 签名 | ❌ "Unsupported algorithm" |
| HS512 签名 | ❌ "Unsupported algorithm" |
| alg=none | ❌ "Unsupported algorithm of none" |
| RS256 密钥混淆（公钥作为 HMAC 密钥） | ❌ 算法锁定 |
| **结论** | JWT 算法锁定到 RS256，密钥混淆攻击不适用 |

#### 6.3 扫描二维码登录端点

| 端点 | 方法 | 结果 |
|------|------|------|
| `/iam-migrate/api/qrcode` | GET | 200（需认证，返回 SPA） |
| `/iam-migrate/api/qrcode/login` | POST | 405 |
| `/iam-migrate/api/sms/send` | POST | 405 |
| `/iam-migrate/api/captcha/image` | GET | 200（需认证，返回 SPA） |

#### 6.4 密码重置端点

| 端点 | 方法 | 结果 |
|------|------|------|
| `/iam-migrate/api/forgetPassword` | GET | 200（SPA） |
| `/iam-migrate/api/forgetPassword` | POST | 405 |
| `/iam-migrate/api/password/reset` | GET | 200（SPA） |
| `/iam-migrate/api/password/reset` | POST | 405 |

---

## 发现与风险评估

### VULN-GCAC-01: 竹云 IAM 版本信息泄露

| 属性 | 值 |
|------|------|
| **严重性** | **中** |
| **信息** | 竹云 IAM 7.0.1.1-RELEASE（深圳竹云科技有限公司） |
| **位置** | JS 前端包 `app.ec95c637.js` |

### VULN-GCAC-02: 前端硬编码 secretKey

| 属性 | 值 |
|------|------|
| **严重性** | **高** |
| **值** | `t6dq3UwENBkUrEtQ8Gzc` |
| **位置** | `/iam-migrate/login/static/config.js` |
| **影响** | 可能用于 API 请求签名、会话加密、CSRF token 生成 |

### VULN-GCAC-03: OIDC Discovery 文档完全公开

| 属性 | 值 |
|------|------|
| **严重性** | **高** |
| **位置** | `/.well-known/openid-configuration` |
| **泄露内容** | 全部 OAuth 2.0 端点、支持的 scope、token 认证方式、签名算法 |

### VULN-GCAC-04: SAML 元数据泄露

| 属性 | 值 |
|------|------|
| **严重性** | **高** |
| **位置** | `/saml/metadata` |
| **泄露内容** | Entity ID、SSO/SLO 端点、完整 X.509 证书链、NameID 格式、属性映射 |

### VULN-GCAC-05: JWKS 公钥公开

| 属性 | 值 |
|------|------|
| **严重性** | **中** |
| **位置** | `/oauth/discovery/keys` |
| **泄露内容** | RSA 公钥 (kid: sXcNME2JXgd3gPAblbJ1BSTusik6vXTw2-rhty0s_ks) |

### VULN-GCAC-06: 隐式授权流程未禁用

| 属性 | 值 |
|------|------|
| **严重性** | **中** |
| **位置** | `/oauth/authorize?response_type=token` |
| **影响** | 隐式授权流程 (Implicit Grant) 在 OAuth 2.1 中已被废弃，存在 token 泄露风险 |

### VULN-GCAC-07: CORS 配置不一致

| 属性 | 值 |
|------|------|
| **严重性** | **中** |
| **位置** | `/oauth/authorize` 某些 response 返回 `Access-Control-Allow-Origin: *` |
| **影响** | 任意网站可发起跨域请求 |

### VULN-GCAC-08: 内部基础设施信息泄露

| 属性 | 值 |
|------|------|
| **严重性** | **高** |
| **泄露内容** | 竹云内部服务地址 `auth.bam.bamboocloud.com:8080`、内部 IP `172.16.6.87`、内部 API 路径 `/apphub-api/oauth/checklogin` |

---

## 下一步建议

1. **尝试竹云已知 CVE 验证**：竹云 IAM 7.x 存在多个已知安全漏洞
2. **密码重置流程测试**：需要有效 cookie/token 后测试重置功能
3. **获取 OAuth token 后**：测试 `/oauth/introspect`、`/oauth/revoke`、`/oauth/userinfo`
4. **OAuth CSRF 测试**：分析 lck 参数的可预测性
5. **内部服务 SSRF 测试**：如果发现其他应用存在 SSRF，可尝试访问 `auth.bam.bamboocloud.com:8080`
6. **API 认证绕过**：尝试使用 secretKey 作为不同格式的认证凭证