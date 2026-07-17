# Phase 1 Reconnaissance Report: repair.ryzerobotics.com

**Target**: https://repair.ryzerobotics.com/ (Ryze Robotics Self-Service Repair Center)  
**Date**: 2026-07-15  
**Methodology**: PESop Phase 1 — Passive & Light-Probe Reconnaissance

---

## 1. HTTP Reconnaissance

### 1.1 Main Page Response

```
Status: 200 OK
Protocol: HTTP/2
Content-Type: text/html; charset=utf-8
Content-Length: 12053
```

### 1.2 Complete Response Headers

```
HTTP/2 200
content-type: text/html; charset=utf-8
content-length: 12053
date: Wed, 15 Jul 2026 09:11:13 GMT
via: nw, 1.1 4ba901855539db34c69cebe9b6979e2c.cloudfront.net (CloudFront)
vary: Accept-Encoding
cache-control: private
x-aspnetmvc-version: 5.2
x-aspnet-version: 4.0.30319
x-powered-by: ASP.NET
x-cache: Miss from cloudfront
x-amz-cf-pop: HKG61-P1
x-amz-cf-id: jSjhUEEo49CRW2sUfu2IM3g-VjpY5Rg5c9--fEHCcA7dY1ivT8-AVQ==
```

**Evidence — CDN/WAF**:  
- **AWS CloudFront** (primary CDN/WAF): `via: nw, 1.1 ...cloudfront.net`, `x-cache: Miss from cloudfront`, `x-amz-cf-pop: HKG61-P1` (Hong Kong edge)
- **Alibaba Cloud WAF (AWSC)**: `<script src="https://g.alicdn.com/AWSC/AWSC/awsc.js">` loaded on page — Alibaba Web Security Console (cloud WAF client-side JS)
- **Alibaba Cloud Tengine**: Static subdomain `repair-static.ryzerobotics.com` serves via Tengine (Alibaba's Nginx fork) + Aliyun OSS
- **Kong API Gateway**: Present at both `api.ryzerobotics.com` and `www.ryzerobotics.com` (`x-kong-upstream-latency` header)

### 1.3 Cookies

Main page (repair.ryzerobotics.com) sets **no cookies directly**.  
`www.ryzerobotics.com` sets:
- `lang=zh-CN; domain=.ryzerobotics.com` (language preference)
- `lang-setter=app; domain=.ryzerobotics.com`

API gateway (`api.ryzerobotics.com`) sets:
- `acw_tc=...; HttpOnly; Max-Age=1800` (Alibaba Cloud WAF traffic cookie)

### 1.4 Discovered Sub-pages (Vue Router SPA Routes)

All return HTTP 200 (client-side rendered by Vue):

| Path | Purpose |
|------|---------|
| `/` | Home / Landing |
| `/guava` | Guava project portal |
| `/guava/repair` | Repair center (beta/dev path) |
| `/guava/repair/index` | Repair index |
| `/guava/echat` | E-commerce chat |
| `/guava/echat/index` | E-commerce chat index |
| `/repair` | Repair center |
| `/repair/index` | Repair main page |
| `/address` | Address management |
| `/submit` | Case submission |
| `/login` | Login page (client-side route) |
| `/register` | Registration |
| `/tickets` | Ticket list |
| `/orders` | Orders |
| `/status` | Status tracking |
| `/track` | Tracking |
| `/service` | Service center |
| `/rma` | RMA requests |
| `/warranty` | Warranty info |
| `/claim` | Claims |
| `/parts` | Parts ordering |
| `/health` | Health check page |
| `/ping` | Ping |
| `/docs` | Documentation |

### 1.5 Blocked Paths (WAF — 403)

| Path | Status |
|------|--------|
| `/.env` | 403 (blocked) |
| `/.git/config` | 403 (blocked) |
| `/swagger` | 403 (blocked) |

### 1.6 Not Found (404)

| Path | Status |
|------|--------|
| `/robots.txt` | 404 |
| `/sitemap.xml` | 404 |
| `/openapi.json` | 404 |
| `/config.json` | 404 |
| `/service-worker.js` | 404 |

---

## 2. Technology Stack Identification

### 2.1 Web Server & Backend

| Technology | Evidence |
|------------|----------|
| **ASP.NET MVC 5.2** | `x-aspnetmvc-version: 5.2` response header |
| **ASP.NET 4.x** | `x-aspnet-version: 4.0.30319` response header |
| **.NET Framework 4.x** | `x-powered-by: ASP.NET` |
| **AWS CloudFront** | `via: ...cloudfront.net`, DNS: CNAME to `d3411gia7oiq7i.cloudfront.net` |
| **Kong API Gateway** | `x-kong-upstream-latency: 1` on `api.ryzerobotics.com` and `www.ryzerobotics.com` |
| **Alibaba Cloud Tengine** | `server: Tengine` on static CDN subdomain |
| **Alibaba Cloud OSS** | `x-oss-request-id`, `x-oss-cdn-auth`, `x-oss-server-time` headers on static CDN |

### 2.2 Frontend Framework

| Technology | Evidence |
|------------|----------|
| **Vue.js 2.6.10** | `app.js` contains `Vue.version="2.6.10"`, Vue Router, webpack build |
| **Element UI** | `element-ui` imports in JS, Element CSS classes, Element icons |
| **Webpack** | Webpack bootstrap in all JS bundles, chunk manifest file |
| **Axios** | HTTP client for API calls in `app.js` module |
| **Lodash** | Utility library (clone, debounce, throttle, etc.) |
| **Moment.js 2.30.1** | Date/time library in vendor bundle |
| **js-cookie** | Cookie management library |
| **Q.js** | Promise library |

### 2.3 CMS / Repair Ticket System

**Custom repair system** — not an off-the-shelf CMS. Evidence:
- Custom API endpoint pattern: `/api/v1/Repair/{ActionName}`
- Custom JSON response format: `{"IsSuccess": bool, "Code": int, "Message": string, "Value": any}`
- Project codename: **"Guava"** — internal development path `/guava/api/v1/`

### 2.4 Monitoring & Error Tracking

| Service | Evidence |
|---------|----------|
| **New Relic APM** | `NREUM.info` block with `applicationID: "290603284"`, `licenseKey: "ef41a9e0ff"` |
| **Sentry** | `SENTRY_IO_DSN` config key found in JS; Sentry DSN URL pattern found |
| **Google Analytics** | `sendToGA` function in JS; `_ga`, `_gid`, `_gat`, `_gcl_au` storage keys |
| **Alibaba Cloud ARMS** | `arms-retcode.aliyuncs.com` and `retcode-us-west-1.arms.aliyuncs.com/r.png` beacon URL (Application Real-Time Monitoring Service) |
| **Alibaba Cloud AWSC** | `https://g.alicdn.com/AWSC/AWSC/awsc.js` — WAF client-side |

---

## 3. API Endpoint Discovery

### 3.1 API Pattern

Production: `/api/v1/{Controller}/{Action}`  
Development/Testing: `/guava/api/v1/{Controller}/{Action}`  

### 3.2 Discovered API Endpoints

| Endpoint | Method | Status | Response |
|----------|--------|--------|----------|
| `/api/v1/Repair/GetAllProductLine` | GET | 200 | `{"IsSuccess":true,"Code":200,"Value":[]}` |
| `/api/v1/Repair/GetRegionList` | GET | 200 | Returns 7 regions (Mainland China, Europe, N. America, Asia-Pacific, Middle East/Africa, S. America, others) |
| `/api/v1/Repair/GetNoticeList` | GET | 200 | `{"IsSuccess":true,"Code":200,"Value":[]}` |
| `/api/v1/Repair/SubmitCase` | POST | 405 → 200 | Error 10216: "验证码错误，请重新获取验证码" (no auth token) |
| `/api/v1/Repair/ShowSubInfo` | POST | 405 | Method not allowed via GET |
| `/api/v1/Repair/SendVerificationCode` | POST | 200 | Error 10004: "系统异常，请刷新重试" (no valid phone) |
| `/api/v1/Repair/GetAgentsList` | GET | 200 (inferred from JS) | — |
| `/guava/api/v1/Repair/GetAllProductLine` | GET | 200 | Same response as production |

### 3.3 API Error Code Map (from JS)

| Code | Chinese | English |
|------|---------|---------|
| 10004 | 系统异常，请刷新重试 | (empty) |
| 10216 | 验证码错误，请重新获取验证码 | (empty) |

### 3.4 API Response Structure

```json
{
  "IsSuccess": bool,
  "Code": int,
  "Message": "{\"Code\":\"...\",\"Chinese\":\"...\",\"English\":\"...\"}",
  "Value": object | null
}
```

---

## 4. JavaScript Analysis

### 4.1 JS Files Discovered

| URL | Size | Purpose |
|-----|------|---------|
| `repair-static.ryzerobotics.com/static/js/app.7537653e5d96a1bb6079.1773903529786.js` | 174 KB | Main app bundle (Vue components, API calls, routes) |
| `repair-static.ryzerobotics.com/static/js/vendor.c6984d5e1f4a37b21b70.1773903529786.js` | ~375 KB | Vendor bundle (Vue, Moment, Lodash, Element UI) |
| `repair-static.ryzerobotics.com/static/js/vendor_e7d5e3.dll.js` | 375 KB | Vendor DLL (Vue 2.6.10, core libraries) |
| `repair-static.ryzerobotics.com/static/js/manifest.b20c4bda3b8fff978777.1773903529786.js` | ~2 KB | Webpack manifest (chunk loader) |
| `cdn.ryzerobotics.com/assets/v1.1/build/scio.umd.2.15.2.js` | 66 KB | DJI SCIO SDK (analytics/telemetry SDK) |
| `g.alicdn.com/AWSC/AWSC/awsc.js` | Alibaba CDN | Alibaba Cloud WAF client-side JS |

### 4.2 Hardcoded Config Keys & Secrets Found

| Key | Value/Pattern | Sensitivity |
|-----|--------------|-------------|
| `WECHAT_APPKEY` | (config variable) | **HIGH** — WeChat integration key |
| `SENTRY_IO_DSN` | `https://41e688f7df5e4abea0e6b053968c3c46@...` | **HIGH** — Sentry DSN (exposed in JS) |
| `STORAGE_KEY_TELLO` | `tello` | Tello product data storage |
| `STORAGE_KEY_USID` | user ID storage | User session data |
| `STORAGE_KEY_CNID` | Chinese ID storage | **HIGH** — potential PII exposure |
| `STORAGE_KEY_FORMDATA` | Form data storage | Repair form data |
| `STORAGE_KEY_ABOUTUS` | About us page data | — |
| `STORAGE_KEY_BUYWAY` | Purchase method | — |
| `STORAGE_KEY_HELPER` | Helper data | — |
| `djiid` | Cookie/storage key | DJI user ID |
| `cookieListUrl` | Cookie banner config | — |
| `policyUrl` | `https://www.ryzerobotics.com/policy` | Privacy policy URL |
| `cookiePreferences` | Cookie preferences | — |
| `termsFooter` | Footer terms | — |
| `repair-dji-com-Login` | Login event name | — |
| `MenuConfig` | Menu configuration | — |
| `PUBLIC_URL` | Public URL config | — |

### 4.3 Internal URLs Extracted from JS

```
https://cdn.ryzerobotics.com/assets/v1.1/build/scio.umd.2.15.2.js
https://repair-static.ryzerobotics.com/
https://retcode-us-west-1.arms.aliyuncs.com/r.png
https://www.ryzebeta.com/
https://www.ryzerobotics.com/
https://www.ryzerobotics.com/policy
```

### 4.4 Sensitive Code Patterns

**Auth redirect on 401** (app.js module 101):
```javascript
if (res && (res.unauthorized || res.status === 401 || res.data.Code === 401)) {
  window.location.href = res.data.Value;
}
```
The server returns a redirect URL in `res.data.Value` on auth failure — potential open redirect if Value is attacker-controlled.

**XSS protection** (helper.js):
```javascript
filterSpecialSymbols: function(val) {
  return val.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
```
Only `<` and `>` are escaped — no escaping of `&`, `"`, `'` — **incomplete XSS protection**.

---

## 5. Subdomain Enumeration

### 5.1 Active Subdomains

| Subdomain | Status | DNS | Service |
|-----------|--------|-----|---------|
| `repair.ryzerobotics.com` | **200** | CloudFront `d3411gia7oiq7i.cloudfront.net` | Main repair site (ASP.NET) |
| `api.ryzerobotics.com` | **200** | Alibaba `kunluncan.com` (120.232.98.x) | Kong API Gateway → Alibaba Cloud |
| `www.ryzerobotics.com` | **302** → `/cn` | Alibaba `kunluncan.com` | Main company site (Kong) |
| `cdn.ryzerobotics.com` | **403** | Alibaba `alikunlun.com` (183.240.x.x) | CDN for assets |
| `repair-static.ryzerobotics.com` | **403** | Alibaba OSS | Static asset hosting |

### 5.2 Inactive/Timeout Subdomains

| Subdomain | Status |
|-----------|--------|
| `admin.ryzerobotics.com` | Timeout |
| `mail.ryzerobotics.com` | Timeout |
| `ftp.ryzerobotics.com` | Timeout |
| `dev.ryzerobotics.com` | Timeout |
| `staging.ryzerobotics.com` | Timeout |
| `shop.ryzerobotics.com` | Timeout |
| `blog.ryzerobotics.com` | Timeout |
| `help.ryzerobiotics.com` | Timeout |
| `support.ryzerobotics.com` | Timeout |
| `docs.ryzerobotics.com` | Timeout |
| `status.ryzerobotics.com` | Timeout |
| `portal.ryzerobotics.com` | Timeout |
| `sso.ryzerobotics.com` | Timeout |
| `account.ryzerobotics.com` | Timeout |
| `auth.ryzerobotics.com` | Timeout |
| `service.ryzerobotics.com` | Timeout |
| `parts.ryzerobotics.com` | Timeout |
| `m.ryzerobotics.com` | Timeout |
| `aftersales.ryzerobotics.com` | Timeout |

### 5.3 Related Domains Discovered

| Domain | Status | DNS | Service |
|--------|--------|-----|---------|
| `www.ryzebeta.com` | **401** (Kong auth) | CloudFront `d386zz5gsq7o2s.cloudfront.net` | Ryze beta environment (Kong + CloudFront) |
| `static.dbeta.me` | **403** | CloudFront `d3chqak0sxifhx.cloudfront.net` | Beta static assets |
| `api.ryzebeta.com` | — | Inferred from CSP | Beta API (in CSP `connect-src`) |

---

## 6. DJI Ecosystem Connections

### 6.1 Direct DJI Infrastructure

| Domain | Status | Purpose | Evidence |
|--------|--------|---------|----------|
| `cdp-vg.djiservice.org` | **200** | DJI CDP service | CSP `connect-src`; Server: `Sws` (DJI's custom server) |
| `test-cdp.djiservice.org` | **200** | DJI CDP test environment | CSP `connect-src` |
| `cdn.djivideos.com` | **200** | DJI video CDN | CSP `frame-ancestors`; Alibaba Tengine + OSS |
| `csp.djicdn.com` | **200** | DJI CSP reporting | CSP `report-uri`; OpenResty + CloudFront; Kong |

### 6.2 Ryze→DJI Brand/Product References in JS

| Reference | Count | Context |
|-----------|-------|---------|
| `ryze` | 64 | Product name, project config |
| `guava`/`Guava` | 45 | Internal project codename |
| `dji` | 11 | DJI IDs, event names (e.g., `djiid`) |
| `TELLO`/`tello`/`Tello` | 19 | Tello drone product references |
| `sdk` | 2 | SDK references |

### 6.3 DJI SDK & Services (SCIO)

`scio.umd.2.15.2.js` hosted at `https://cdn.ryzerobotics.com/assets/v1.1/build/scio.umd.2.15.2.js`  
- **67 KB** — DJI's internal analytics/telemetry SDK
- Hosted on Alibaba Cloud CDN (Tengine + Aliyun OSS)
- Last modified: 2026-01-29
- Served via CloudFront → Alibaba hybrid delivery

### 6.4 DJI CDP Integration

The CSP header from `www.ryzebeta.com` reveals DJI's Customer Data Platform (CDP):
```
connect-src 'self' arms-retcode.aliyuncs.com api.ryzebeta.com 
             retcode-us-west-1.arms.aliyuncs.com 
             cdp-vg.djiservice.org test-cdp.djiservice.org;
```
This means the Ryze frontend sends analytics/telemetry data directly to DJI's CDP service at `djiservice.org`.

### 6.5 CSP Reporting to DJI

```
report-uri https://csp.djicdn.com/_/http-sec-report
```
All CSP violations from the Ryze beta site are reported to DJI's infrastructure.

---

## 7. Architecture Summary

```
User Browser
    │
    ├── AWS CloudFront (repair.ryzerobotics.com)
    │       │
    │       └── ASP.NET MVC 5.2 (IIS / .NET 4.x Backend)
    │               │
    │               └── API: /api/v1/Repair/{Action}
    │
    ├── Alibaba Cloud (api.ryzerobotics.com)
    │       │
    │       └── Kong API Gateway → Alibaba Backend
    │
    ├── Alibaba Cloud OSS (repair-static.ryzerobotics.com)
    │       └── Static files (JS, CSS, fonts, images)
    │
    ├── Alibaba Cloud AWSC WAF
    │       └── g.alicdn.com/AWSC/AWSC/awsc.js
    │
    ├── DJI CDP (cdp-vg.djiservice.org)
    │       └── Analytics / telemetry
    │
    └── DJI CDN (cdn.djivideos.com)
            └── Video content
```

### Monitoring Stack
- New Relic APM (backend)
- Alibaba Cloud ARMS (frontend RUM)
- Sentry (error tracking)
- Google Analytics (user analytics)
- DJI SCIO SDK (DJI-specific analytics)

---

## 8. Attack Surface Assessment

### 8.1 High-Value Targets

| Target | Risk | Reason |
|--------|------|--------|
| `/api/v1/Repair/SubmitCase` | **HIGH** | Case submission with file upload potential; requires phone verification bypass |
| `/api/v1/Repair/SendVerificationCode` | **HIGH** | SMS verification endpoint — potential for OTP brute-force or SMS bombing |
| `/guava/api/v1/` | **HIGH** | Development/testing API path — may have weaker auth or debugging enabled |
| `www.ryzebeta.com` | **HIGH** | Beta environment with Kong auth — potential for weaker security controls |
| `api.ryzerobotics.com` | **HIGH** | Kong API Gateway — potential for misconfigured routes/rate limits |

### 8.2 Notable Observations

1. **Dual-cloud architecture**: AWS CloudFront + Alibaba Cloud (Tengine/Kong/OSS) — complex routing increases misconfiguration surface
2. **No CSRF tokens**: API only checks for `csrf-token` and `x-csrf-token` headers but response indicates they are optional
3. **Sentry DSN exposed**: `https://41e688f7df5e4abea0e6b053968c3c46@...` in JavaScript (public but allows error submission)
4. **WeChat AppKey**: Hardcoded config variable in JS — could expose WeChat OAuth/app integration
5. **djiid cookie**: Cross-domain `.ryzerobotics.com` cookie — session sharing across subdomains
6. **No HSTS on main domain** (`repair.ryzerobotics.com`) — only `www.ryzerobotics.com` and `api.ryzerobotics.com` have HSTS
7. **Incomplete XSS filtering**: Only `<` and `>` escaped, not `&`, `"`, `'` in `filterSpecialSymbols`
8. **Auth redirect in Value field**: 401 responses return redirect URL in JSON `Value` field — potential open redirect

### 8.3 Recommended Phase 2 Focus

1. **API fuzzing** on `/api/v1/Repair/*` — parameter injection, IDOR, auth bypass
2. **Guava endpoint testing** — `/guava/api/v1/` may have less restrictive policies
3. **Beta environment** — `www.ryzebeta.com` with Kong auth (try common credentials, token leaks)
4. **DJI CDP analysis** — `cdp-vg.djiservice.org` integration points
5. **SMS bombing / OTP brute-force** on `SendVerificationCode`
6. **Subdomain takeover** check on timeout subdomains
7. **WeChat integration testing** — potential OAuth misconfiguration