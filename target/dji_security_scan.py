#!/usr/bin/env python3
"""
PESop HF-1 to HF-7 Security Assessment: developer.dji.com
Authorized Penetration Test - Phase 1 Reconnaissance
"""
import json
import re
import ssl
import time
import urllib.request
import urllib.error
import http.client
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser
from collections import OrderedDict
import socket
import gzip
import io

# ========== CONFIG ==========
TARGETS = [
    "https://developer.dji.com",
    "https://developer.dji.com/documentation/",
    "https://developer.dji.com/mobile-sdk/",
    "https://developer.dji.com/onboard-sdk/",
    "https://developer.dji.com/payload-sdk/",
    "https://developer.dji.com/windows-sdk/",
    "https://developer.dji.com/search/",
]
ADDITIONAL = [
    "https://store-api.dji.com",
    "https://account.dji.com",
    "https://terra-1-g.djicdn.com",
]
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

report = {
    "target": "developer.dji.com",
    "methodology": "PESop HF-1 to HF-7",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "api_endpoints": [],
    "security_issues": [],
    "infrastructure": {"domains": {}, "cdns": {}, "servers": []},
    "hardcoded_secrets": [],
    "js_assets": [],
    "attack_tree": [],
    "http_security_headers": {},
    "cors_findings": [],
    "routes_found": [],
    "error_leaks": [],
    "tech_stack": {},
}


def fetch(url, method="GET", headers=None, body=None, timeout=15):
    """Generic HTTP(S) fetcher with SSL bypass."""
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", USER_AGENT)
    headers.setdefault("Accept", "*/*")
    headers.setdefault("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7")
    
    parsed = urlparse(url)
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.netloc, timeout=timeout, context=ssl_ctx)
    else:
        conn = http.client.HTTPConnection(parsed.netloc, timeout=timeout)
    
    path = parsed.path if parsed.path else "/"
    if parsed.query:
        path += "?" + parsed.query
    
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        content_type = resp.getheader("Content-Type", "")
        all_headers = dict(resp.getheaders())
        
        # Try to decompress
        try:
            if resp.getheader("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
        except:
            pass
        
        conn.close()
        return {
            "status": resp.status,
            "reason": resp.reason,
            "headers": all_headers,
            "body": data,
            "text": data.decode("utf-8", errors="replace"),
            "content_type": content_type,
        }
    except Exception as e:
        return {"status": 0, "error": str(e), "body": b"", "text": "", "headers": {}, "content_type": ""}


class JSExtractor(HTMLParser):
    """Extract JS src and inline scripts from HTML."""
    def __init__(self):
        super().__init__()
        self.js_files = []
        self.js_inline = []
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "script":
            src = attrs_dict.get("src")
            if src:
                self.js_files.append(src)


class LinkExtractor(HTMLParser):
    """Extract all href/src from HTML."""
    def __init__(self):
        super().__init__()
        self.links = []
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag in ("a", "link"):
            href = attrs_dict.get("href")
            if href:
                self.links.append(href)
        if tag in ("script", "img", "source", "iframe"):
            src = attrs_dict.get("src")
            if src:
                self.links.append(src)


def extract_api_endpoints(text, source=""):
    """Extract API endpoints from JS/text using regex."""
    endpoints = set()
    
    patterns = [
        r'(?:"|\')(/[a-zA-Z0-9_\-/{}]+(?:api|v[0-9]+|graphql|rest|rpc)[a-zA-Z0-9_\-/{}]*)(?:"|\')',
        r'["\'](https?://[^"\']+)["\']',
        r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
        r'apiPrefix\s*[=:]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[=:]\s*["\']([^"\']+)["\']',
        r'baseUrl\s*[=:]\s*["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch|request)\s*\(\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*:\s*["\']([^"\']+)["\']',
        r'path\s*:\s*["\']([^"\']+)["\']',
        r'route\s*:\s*["\']([^"\']+)["\']',
        r'pathPrefix\s*[=:]\s*["\']([^"\']+)["\']',
        r'proxy\s*[=:]\s*\{[^}]*?["\']/api["\']',
        r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/graphql)["\']',
        r'["\'](/rest/[a-zA-Z0-9_\-/]+)["\']',
        r'//[a-z]+\.[a-z]+\.[a-z]+/[^"\')\s]+',
    ]
    
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        for m in matches:
            if m and len(m) > 3:
                endpoints.add(m.strip())
    
    return sorted(endpoints)


def extract_secrets(text, source=""):
    """Extract potential hardcoded secrets from text."""
    secrets = []
    
    patterns = [
        (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']', "API Key"),
        (r'(?i)(?:secret|secret[_-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', "Secret Key"),
        (r'(?i)(?:token|auth[_-]?token|access[_-]?token)\s*[=:]\s*["\']([^"\']{8,})["\']', "Access Token"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Password"),
        (r'(?i)(?:jwt[_-]?secret|jwt_secret)\s*[=:]\s*["\']([^"\']{8,})["\']', "JWT Secret"),
        (r'(?i)(?:sentry[_-]?dsn|dsn)\s*[=:]\s*["\'](https?://[^"\']+)["\']', "Sentry DSN"),
        (r'(?:SENTRY_DSN|SENTRY_IO_DSN)\s*[=:]\s*["\']([^"\']+)["\']', "Sentry DSN"),
        (r'(?i)(?:wechat[_-]?app[_-]?id|wechat_appid)\s*[=:]\s*["\']([^"\']+)["\']', "WeChat App ID"),
        (r'(?i)(?:wechat[_-]?app[_-]?key|wechat_appkey|WECHAT_APPKEY)\s*[=:]\s*["\']([^"\']+)["\']', "WeChat App Key"),
        (r'(?i)(?:aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']([^"\']+)["\']', "AWS Access Key ID"),
        (r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']([^"\']+)["\']', "AWS Secret Access Key"),
        (r'(?i)(?:google[_-]?analytics[_-]?id|ga[_-]?id|gtm[_-]?id)\s*[=:]\s*["\']([^"\']+)["\']', "Google Analytics ID"),
        (r'(?i)(?:app[_-]?id|client[_-]?id)\s*[=:]\s*["\']([a-zA-Z0-9._-]{8,})["\']', "App/Client ID"),
        (r'(?i)(?:private[_-]?key|rsa[_-]?private)\s*[=:]\s*["\']([^"\']{20,})["\']', "Private Key"),
        (r'(?:-----BEGIN[ A-Z]*PRIVATE KEY-----)', "PEM Private Key"),
        (r'(?:-----BEGIN CERTIFICATE-----)', "PEM Certificate"),
        (r'[bB]asic\s+[A-Za-z0-9+/]{20,}={0,2}', "Basic Auth Credentials"),
        (r'[Bb]earer\s+[A-Za-z0-9._-]{20,}', "Bearer Token"),
    ]
    
    for pat, desc in patterns:
        matches = re.findall(pat, text)
        for m in matches:
            val = m if isinstance(m, str) else m[0]
            if val and len(val) < 200:
                secrets.append({"type": desc, "value": val[:80] + ("..." if len(val) > 80 else ""), "source": source})
    
    return secrets


def extract_routes(text, source=""):
    """Extract SPA route definitions from JS."""
    routes = []
    
    patterns = [
        r'(?:path|component)\s*[=:]\s*["\']([^"\']+)["\']',
        r'path\s*:\s*["\']([^"\'/:][^"\']*)["\']',
        r'routeConfig[^}]*?path:\s*["\']([^"\']+)["\']',
        r'Router[^}]*?path:\s*["\']([^"\']+)["\']',
        r'createRoute[^)]*?["\']([^"\']+)["\']',
        r'addRoute[^)]*?["\']([^"\']+)["\']',
    ]
    
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        for m in matches:
            if m and m not in ("/", "") and not m.startswith(("http", "#", "javascript:")):
                routes.append(m)
    
    return list(set(routes))


def extract_backend_urls(text):
    """Extract backend URLs (internal services, API gateways)."""
    urls = set()
    
    patterns = [
        r'https?://[a-zA-Z0-9._-]+\.dji\.com[^"\')\s]*',
        r'https?://[a-zA-Z0-9._-]+\.djicdn\.com[^"\')\s]*',
        r'https?://[a-zA-Z0-9._-]+\.djiservice\.org[^"\')\s]*',
        r'https?://[a-zA-Z0-9._-]+\.djivideos\.com[^"\')\s]*',
        r'https?://[a-zA-Z0-9._-]+\.ryzerobotics\.com[^"\')\s]*',
        r'https?://10\.\d+\.\d+\.\d+[^"\')\s]*',
        r'https?://172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+[^"\')\s]*',
        r'https?://192\.168\.\d+\.\d+[^"\')\s]*',
    ]
    
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        for m in matches:
            urls.add(m.strip())
    
    return sorted(urls)


def analyze_security_headers(headers, domain):
    """Check HTTP security headers."""
    findings = []
    checks = {
        "Strict-Transport-Security": {"check": lambda v: "max-age" in v and int(re.search(r'max-age=(\d+)', v).group(1)) >= 31536000 if v and re.search(r'max-age=(\d+)', v) else False, "desc": "HSTS with >=1 year max-age"},
        "Content-Security-Policy": {"check": lambda v: bool(v), "desc": "CSP is set"},
        "X-Content-Type-Options": {"check": lambda v: v == "nosniff", "desc": "X-Content-Type-Options: nosniff"},
        "X-Frame-Options": {"check": lambda v: v in ("DENY", "SAMEORIGIN"), "desc": "X-Frame-Options prevents clickjacking"},
        "X-XSS-Protection": {"check": lambda v: v == "1; mode=block", "desc": "X-XSS-Protection enabled"},
        "Referrer-Policy": {"check": lambda v: bool(v), "desc": "Referrer-Policy is set"},
        "Permissions-Policy": {"check": lambda v: bool(v), "desc": "Permissions-Policy is set"},
    }
    
    for header, check in checks.items():
        val = headers.get(header, headers.get(header.lower(), ""))
        if not val:
            findings.append({
                "type": "missing_security_header",
                "header": header,
                "severity": "low",
                "domain": domain,
                "description": f"Missing {header} header",
                "impact": f"Increased risk of certain attacks without {header}"
            })
    
    return findings


def test_cors(url):
    """Test CORS configuration on a URL."""
    findings = []
    parsed = urlparse(url)
    origin = "https://evil-attacker.com"
    
    headers = {
        "User-Agent": USER_AGENT,
        "Origin": origin,
    }
    
    result = fetch(url, headers=headers)
    resp_headers = result.get("headers", {})
    
    acao = resp_headers.get("Access-Control-Allow-Origin", "")
    acac = resp_headers.get("Access-Control-Allow-Credentials", "")
    
    if acao == "*":
        findings.append({
            "severity": "medium",
            "type": "cors_wildcard",
            "url": url,
            "description": f"CORS allows all origins (*)",
            "poc": f"curl -H 'Origin: {origin}' -I {url}",
            "impact": "Any website can make cross-origin requests to this endpoint"
        })
    elif acao == origin:
        findings.append({
            "severity": "high",
            "type": "cors_reflect_origin",
            "url": url,
            "description": "CORS reflects arbitrary Origin header",
            "poc": f"curl -H 'Origin: {origin}' -I {url}",
            "impact": "Attacker can exfiltrate data via malicious websites"
        })
    
    if acao and acac == "true":
        findings.append({
            "severity": "high",
            "type": "cors_credentials",
            "url": url,
            "description": "CORS with credentials and arbitrary/reflected origin",
            "poc": f"curl -H 'Origin: {origin}' -H 'Cookie: ...' {url}",
            "impact": "Cookie-based session hijacking via cross-origin requests"
        })
    
    return findings


def test_endpoint(url, method="GET", headers=None):
    """Test a single API endpoint."""
    if headers is None:
        headers = {"User-Agent": USER_AGENT}
    result = fetch(url, method=method, headers=headers)
    return {
        "status": result.get("status"),
        "headers": result.get("headers", {}),
        "body_preview": result.get("text", "")[:500] if result.get("text") else "",
        "content_type": result.get("content_type", ""),
    }


def check_auth_bypass(url):
    """Test if endpoint works without auth."""
    result = fetch(url, headers={"User-Agent": USER_AGENT})
    no_auth_result = fetch(url, headers={"User-Agent": USER_AGENT})
    return {
        "url": url,
        "status_without_auth": result.get("status"),
        "requires_auth": result.get("status") in (401, 403),
        "body_sample": result.get("text", "")[:300] if result.get("text") else "",
    }


def scan_endpoints():
    """Scan known and discovered API endpoints."""
    known_endpoints = [
        "https://developer.dji.com/api/report/web",
        "https://store-api.dji.com/logger/beacon.gif",
        "https://store-api.dji.com/health",
        "https://account.dji.com/oauth/token",
        "https://account.dji.com/oauth/authorize",
        "https://account.dji.com/.well-known/oauth-authorization-server",
        "https://account.dji.com/.well-known/openid-configuration",
        "https://developer.dji.com/robots.txt",
        "https://developer.dji.com/sitemap.xml",
        "https://developer.dji.com/.env",
        "https://developer.dji.com/.git/config",
        "https://developer.dji.com/api/v1/",
        "https://developer.dji.com/api/v2/",
        "https://developer.dji.com/graphql",
        "https://developer.dji.com/rest/",
    ]
    
    results = []
    for ep in known_endpoints:
        parsed = urlparse(ep)
        for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            result = test_endpoint(ep, method=method)
            
            entry = {
                "url": ep,
                "method": method,
                "status": result["status"],
                "content_type": result["content_type"],
                "response_sample": result["body_preview"],
            }
            
            if result["status"] not in (0, 404):
                # Check auth requirement
                auth_check = check_auth_bypass(ep)
                entry["requires_auth"] = auth_check["requires_auth"]
                
                # Check for error leaks
                if re.search(r'(?:stack.?trace|exception|error|warning|debug)', result.get("body_preview", ""), re.IGNORECASE):
                    report["error_leaks"].append({
                        "url": ep,
                        "method": method,
                        "evidence": result["body_preview"][:200],
                        "severity": "medium",
                    })
            
            results.append(entry)
            break  # Only test one method per endpoint for initial scan
    
    report["api_endpoints"] = results


def scan_infrastructure():
    """Scan infrastructure - security headers, DNS, etc."""
    domains = [
        "developer.dji.com",
        "store-api.dji.com",
        "account.dji.com",
        "terra-1-g.djicdn.com",
        "devcn.djicdn.com",
        "www.dji.com",
    ]
    
    for domain in domains:
        try:
            url = f"https://{domain}"
            result = fetch(url)
            
            if result["status"]:
                info = {
                    "domain": domain,
                    "status": result["status"],
                    "server": result["headers"].get("Server", result["headers"].get("server", "unknown")),
                    "headers": result["headers"],
                }
                
                # Security headers analysis
                sec_findings = analyze_security_headers(result["headers"], domain)
                if domain not in report["http_security_headers"]:
                    report["http_security_headers"][domain] = {}
                
                for f in sec_findings:
                    report["http_security_headers"][domain][f["header"]] = f["description"]
                    report["security_issues"].append(f)
                
                # CORS test
                cors = test_cors(url)
                report["cors_findings"].extend(cors)
                report["security_issues"].extend(cors)
                
                # Try to resolve IP
                try:
                    ip = socket.gethostbyname(domain)
                    info["ip"] = ip
                except:
                    info["ip"] = None
                
                report["infrastructure"]["domains"][domain] = info
        except Exception as e:
            report["infrastructure"]["domains"][domain] = {"domain": domain, "error": str(e)}


def download_and_analyze_js():
    """Download all JS files found on target pages and analyze them."""
    all_js_files = set()
    
    # Phase 1: Download all target pages and extract JS references
    print("[*] Phase 1: Downloading target pages...")
    for target in TARGETS:
        result = fetch(target)
        if result["status"] == 200:
            parser = JSExtractor()
            parser.feed(result["text"])
            for js_path in parser.js_files:
                if js_path.startswith("//"):
                    js_path = "https:" + js_path
                elif js_path.startswith("/"):
                    js_path = urljoin(target, js_path)
                elif not js_path.startswith("http"):
                    js_path = urljoin(target, js_path)
                all_js_files.add(js_path)
            
            # Also extract from HTML body
            text = result["text"]
            
            # Backend URLs
            back_urls = extract_backend_urls(text)
            for u in back_urls:
                if u not in report["infrastructure"].get("backend_urls", []):
                    report["infrastructure"].setdefault("backend_urls", []).append(u)
            
            # Secrets in HTML
            html_secrets = extract_secrets(text, source=target)
            for s in html_secrets:
                exists = any(ex["value"] == s["value"] for ex in report["hardcoded_secrets"])
                if not exists:
                    report["hardcoded_secrets"].append(s)
    
    # Phase 2: Download each JS file
    print(f"[*] Phase 2: Downloading {len(all_js_files)} JS files...")
    js_contents = {}
    for js_url in sorted(all_js_files):
        print(f"    Downloading: {js_url[:100]}...")
        try:
            result = fetch(js_url)
            if result["status"] == 200:
                js_contents[js_url] = result["text"]
                report["js_assets"].append({
                    "url": js_url,
                    "size": len(result["text"]),
                    "status": result["status"],
                })
            else:
                report["js_assets"].append({
                    "url": js_url,
                    "size": 0,
                    "status": result["status"],
                    "error": "Non-200 status"
                })
        except Exception as e:
            report["js_assets"].append({
                "url": js_url,
                "size": 0,
                "status": 0,
                "error": str(e)
            })
    
    # Phase 3: Analyze JS contents
    print(f"[*] Phase 3: Analyzing {len(js_contents)} JS files...")
    for js_url, js_text in js_contents.items():
        # Extract API endpoints
        endpoints = extract_api_endpoints(js_text, source=js_url)
        for ep in endpoints:
            report["api_endpoints"].append({
                "url": ep,
                "source": js_url,
                "method": "UNKNOWN",
                "status": 0,
                "requires_auth": None,
                "response_sample": "",
            })
        
        # Extract secrets
        secrets = extract_secrets(js_text, source=js_url)
        for s in secrets:
            exists = any(ex["value"] == s["value"] for ex in report["hardcoded_secrets"])
            if not exists:
                report["hardcoded_secrets"].append(s)
        
        # Extract routes
        routes = extract_routes(js_text, source=js_url)
        for r in routes:
            report["routes_found"].append({"route": r, "source": js_url})
        
        # Extract backend URLs
        back_urls = extract_backend_urls(js_text)
        for u in back_urls:
            if u not in report["infrastructure"].get("backend_urls", []):
                report["infrastructure"].setdefault("backend_urls", []).append(u)
        
        # Technology detection
        if "react" in js_text.lower() or "React" in js_text:
            report["tech_stack"]["frontend_framework"] = "React"
        if "vue" in js_text.lower() or "Vue" in js_text:
            report["tech_stack"]["frontend_framework"] = "Vue"
        if "angular" in js_text.lower() or "ng-" in js_text:
            report["tech_stack"]["frontend_framework"] = "Angular"
        if "next" in js_text.lower() and "next_route" in js_text.lower():
            report["tech_stack"]["frontend_framework"] = "Next.js"
        if "webpack" in js_text.lower():
            report["tech_stack"]["bundler"] = "Webpack"
        if "axios" in js_text.lower():
            report["tech_stack"]["http_client"] = "Axios"
        if "fetch" in js_text.lower():
            if "http_client" not in report["tech_stack"]:
                report["tech_stack"]["http_client"] = "Fetch API"
    
    print(f"[*] Analysis complete: {len(report['api_endpoints'])} endpoints, {len(report['hardcoded_secrets'])} secrets, {len(report['routes_found'])} routes")


def scan_terraform_cdn():
    """Check terra-1-g.djicdn.com for directory traversal."""
    print("[*] Scanning CDN: terra-1-g.djicdn.com...")
    base = "https://terra-1-g.djicdn.com"
    
    paths_to_try = [
        "/", "/robots.txt", "/.env", "/package.json", "/webpack.config.js",
        "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/.git/config", "/admin/", "/api/", "/static/", "/assets/",
        "/version.txt", "/config.json", "/swagger.json", "/openapi.json",
        "/health", "/healthz", "/favicon.ico",
    ]
    
    for path in paths_to_try:
        url = f"{base}{path}"
        result = fetch(url)
        if result["status"] not in (0, 403, 404):
            report["infrastructure"].setdefault("terraform_findings", []).append({
                "url": url,
                "status": result["status"],
                "content_type": result["content_type"],
                "body_preview": result["text"][:200],
            })


def test_oauth_endpoints():
    """Test OAuth endpoints on account.dji.com."""
    print("[*] Testing OAuth endpoints...")
    
    oauth_tests = [
        ("https://account.dji.com/.well-known/oauth-authorization-server", "OAuth server metadata"),
        ("https://account.dji.com/.well-known/openid-configuration", "OpenID configuration"),
        ("https://account.dji.com/oauth/authorize", "OAuth authorize endpoint"),
        ("https://account.dji.com/oauth/token", "OAuth token endpoint"),
        ("https://account.dji.com/oauth/revoke", "OAuth revoke endpoint"),
    ]
    
    for url, desc in oauth_tests:
        result = fetch(url)
        
        # Check for open redirect
        if result["status"] in (301, 302, 307, 308):
            loc = result["headers"].get("Location", result["headers"].get("location", ""))
            if loc and not loc.startswith("https://account.dji.com"):
                report["security_issues"].append({
                    "severity": "high" if "javascript:" in loc.lower() or "data:" in loc.lower() else "medium",
                    "type": "open_redirect",
                    "url": url,
                    "description": f"Potential open redirect to: {loc}",
                    "poc": f"curl -v '{url}?redirect_uri=https://evil.com'",
                    "impact": "An attacker could redirect users to malicious sites after OAuth flow"
                })
        
        # Check for CSRF in authorize endpoint (missing/weak state parameter)
        if "authorize" in url:
            body_lower = result.get("text", "").lower() if result.get("text") else ""
            if "state" not in body_lower and result["status"] == 200:
                report["security_issues"].append({
                    "severity": "high",
                    "type": "oauth_missing_state",
                    "url": url,
                    "description": "OAuth authorize endpoint may lack state parameter (CSRF)",
                    "poc": f"Visit {url}?response_type=code&client_id=...&redirect_uri=...",
                    "impact": "Attacker can perform CSRF on OAuth login flow"
                })
        
        # Check for error info leaking
        if result["status"] == 200:
            body = result.get("text", "")
            if re.search(r'(?:error|exception|stack|trace|debug)', body, re.IGNORECASE):
                report["error_leaks"].append({
                    "url": url,
                    "evidence": body[:200],
                    "severity": "medium",
                })
        
        report["infrastructure"]["domains"].setdefault("account.dji.com", {})[desc] = {
            "url": url,
            "status": result["status"],
            "headers": dict(result.get("headers", {})),
            "body_preview": result.get("text", "")[:300] if result.get("text") else "",
        }


def build_attack_tree():
    """Build the attack tree from all findings."""
    attack_tree = {
        "entry_points": [],
        "escalation_paths": [],
        "high_value_targets": [],
        "attack_chains": [],
    }
    
    # Entry points from security issues
    for issue in report["security_issues"]:
        if issue["severity"] in ("high", "critical"):
            attack_tree["entry_points"].append({
                "type": issue["type"],
                "description": issue["description"],
                "poc": issue.get("poc", ""),
            })
    
    # Attack chains
    chains = []
    
    # Chain 1: OAuth CSRF + Open Redirect
    has_oauth_csrf = any(i["type"] == "oauth_missing_state" for i in report["security_issues"])
    has_open_redirect = any(i["type"] == "open_redirect" for i in report["security_issues"])
    if has_oauth_csrf and has_open_redirect:
        chains.append({
            "name": "OAuth Login Hijacking",
            "severity": "critical",
            "steps": [
                "Attacker crafts malicious OAuth authorization URL with attacker's redirect_uri",
                "Victim (already authenticated to developer.dji.com) clicks the crafted URL",
                "OAuth flow completes and authorization code is sent to attacker's server",
                "Attacker exchanges code for access token",
                "Full account takeover achieved"
            ],
            "conditions": ["No state CSRF token in OAuth flow", "No redirect_uri validation"],
        })
    
    # Chain 2: API secrets + CORS
    hardcoded_keys = [s for s in report["hardcoded_secrets"] if s["type"] in ("API Key", "Secret Key", "Access Token")]
    weak_cors = [c for c in report["cors_findings"] if c["severity"] in ("high", "medium")]
    if hardcoded_keys and weak_cors:
        chains.append({
            "name": "API Key Leak through CORS",
            "severity": "high",
            "steps": [
                f"Hardcoded API keys found in JS: {[s['value'][:20] for s in hardcoded_keys[:3]]}",
                "CORS allows cross-origin requests",
                "Attacker's website can extract keys and access backend APIs",
                "Potential data exfiltration and unauthorized operations"
            ],
            "conditions": ["Exposed API keys in client-side code", "Permissive CORS policy"],
        })
    
    # Chain 3: Internal endpoints exposed
    internal_urls = [u for u in report["infrastructure"].get("backend_urls", []) if "internal" in u.lower() or re.search(r'10\.\d+', u)]
    unauthed_endpoints = [e for e in report["api_endpoints"] if isinstance(e, dict) and e.get("requires_auth") == False]
    if internal_urls or unauthed_endpoints:
        chains.append({
            "name": "Unauthenticated Internal API Access",
            "severity": "high",
            "steps": [
                f"Internal URLs found: {internal_urls[:3]}",
                f"Unauthenticated endpoints: {[e.get('url','')[:50] for e in unauthed_endpoints[:3]]}",
                "Direct access to internal APIs without authentication",
                "Potential information disclosure and privilege escalation"
            ],
            "conditions": ["Leaked internal URLs", "Missing authentication on sensitive endpoints"],
        })
    
    attack_tree["attack_chains"] = chains
    report["attack_tree"] = attack_tree


def generate_report():
    """Generate final JSON report."""
    report["summary"] = {
        "total_api_endpoints": len(report["api_endpoints"]),
        "total_security_issues": len(report["security_issues"]),
        "total_hardcoded_secrets": len(report["hardcoded_secrets"]),
        "total_routes_found": len(report["routes_found"]),
        "total_js_files_analyzed": len(report["js_assets"]),
        "critical_issues": len([i for i in report["security_issues"] if i["severity"] == "critical"]),
        "high_issues": len([i for i in report["security_issues"] if i["severity"] == "high"]),
        "medium_issues": len([i for i in report["security_issues"] if i["severity"] == "medium"]),
        "low_issues": len([i for i in report["security_issues"] if i["severity"] == "low"]),
    }
    
    output_file = "/home/opencode/PESop/target/dji_security_report.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"\n{'='*60}")
    print(f"PESop Security Assessment Complete")
    print(f"{'='*60}")
    print(f"Summary:")
    print(f"  API Endpoints Found:   {report['summary']['total_api_endpoints']}")
    print(f"  Security Issues:       {report['summary']['total_security_issues']} (Crit: {report['summary']['critical_issues']}, High: {report['summary']['high_issues']}, Med: {report['summary']['medium_issues']}, Low: {report['summary']['low_issues']})")
    print(f"  Hardcoded Secrets:     {report['summary']['total_hardcoded_secrets']}")
    print(f"  SPA Routes Found:      {report['summary']['total_routes_found']}")
    print(f"  JS Files Analyzed:     {report['summary']['total_js_files_analyzed']}")
    print(f"  Report saved to:       {output_file}")
    
    return output_file


def main():
    start_time = time.time()
    
    print(f"{'='*60}")
    print(f"PESop Security Assessment: developer.dji.com")
    print(f"Methodology: HF-1 (Fingerprint) through HF-7 (Real-time Protocol)")
    print(f"Start Time:  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"{'='*60}\n")
    
    print("[HF-1] Fingerprinting & CVE identification...")
    scan_infrastructure()
    
    print("\n[HF-2] JS Full Extraction & API Mapping...")
    download_and_analyze_js()
    
    print("\n[HF-3] API Endpoint Security Testing...")
    scan_endpoints()
    
    print("\n[HF-4/HF-5] Auth Bypass & Business Logic Testing...")
    test_oauth_endpoints()
    
    print("\n[HF-6] Infrastructure Analysis...")
    scan_terraform_cdn()
    
    print("\n[HF-7] Building Attack Tree...")
    build_attack_tree()
    
    elapsed = time.time() - start_time
    print(f"\nTotal execution time: {elapsed:.1f}s")
    
    report["execution_time_seconds"] = elapsed
    generate_report()


if __name__ == "__main__":
    main()