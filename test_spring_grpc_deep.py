#!/usr/bin/env python3
"""
PESop v3.3 - Spring Boot gRPC 深度扫描
目标: umsmsg.djicorp.com
"""
import socket, struct, time, sys

HOST = '240.240.1.18'
PORT = 80

def encode_varint(value):
    r = []
    while value > 0x7F:
        r.append((value & 0x7F) | 0x80)
        value >>= 7
    r.append(value & 0x7F)
    return bytes(r)

def grpc_call(path, body=b'', extra_headers=None):
    if extra_headers is None:
        extra_headers = {}
    hstr = ''.join(f'{k}: {v}\r\n' for k, v in extra_headers.items())
    ml = len(body)
    frame = struct.pack('!BI', 0, ml) + body
    req = (
        f'POST {path} HTTP/1.1\r\n'
        f'Host: umsmsg.djicorp.com\r\n'
        f'Content-Type: application/grpc\r\n'
        f'TE: trailers\r\n'
        f'{hstr}'
        f'Content-Length: {5 + ml}\r\n'
        f'\r\n'
    ).encode() + frame
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, PORT))
        s.sendall(req)
        resp = b''
        while True:
            try:
                c = s.recv(4096)
                if not c: break
                resp += c
            except: break
        return resp
    except Exception as e:
        return f'Error: {e}'.encode()
    finally:
        s.close()

def parse_grpc(resp):
    r = {}
    if isinstance(resp, bytes):
        t = resp.decode(errors='ignore')
        for line in t.split('\r\n'):
            if line.lower().startswith('grpc-status:'):
                r['status'] = int(line.split(':')[1].strip())
            elif line.lower().startswith('grpc-message:'):
                r['message'] = line.split(':', 1)[1].strip()
            elif line.startswith('HTTP/'):
                r['http'] = line.split(' ')[1] if ' ' in line else '?'
            elif line.lower().startswith('content-type:'):
                r['ct'] = line.split(':', 1)[1].strip()
        if '\r\n\r\n' in t:
            body = t.split('\r\n\r\n', 1)[1]
            if body and len(body) > 5:
                r['body_start'] = body[:100]
    return r

print("=" * 70)
print("Spring Boot gRPC 深度扫描")
print("=" * 70)

# Phase 1: Build valid protobuf messages and send them
# Even with wrong proto, different field numbers change behavior
print("\n[Phase 1] 带实际 Protobuf 载荷的 gRPC 调用")
print("-" * 50)

test_messages = [
    # 空消息
    ("empty", b''),
    # 各种 field 组合 (int32 fields like field=1 value=1)
    ("field1=1", bytes([0x08, 0x01])),
    ("field1=0", bytes([0x08, 0x00])),
    ("field1=100", bytes([0x08, 0x64])),
    ("string_field1='hello'", bytes([0x0A, 0x05]) + b'hello'),
    ("field3=1", bytes([0x18, 0x01])),
    ("field5=1", bytes([0x28, 0x01])),
    ("field10=1", bytes([0x50, 0x01])),
    # 复合消息
    ("field1+field2", bytes([0x08, 0x01, 0x12, 0x03]) + b'abc'),
    ("field3_string", bytes([0x1A, 0x05]) + b'admin'),
    ("field4_bytes", bytes([0x22, 0x04, 0x00, 0x01, 0x02, 0x03])),
]

services = [
    "umsmsg.MessageService",
    "umsmsg.UMSMsgService",
    "umsmsg.NotificationService", 
    "umsmsg.PushService",
    "umsmsg.SMSService",
    "umsmsg.EmailService",
    "message.MessageService",
    "notification.NotificationService",
    "push.PushService",
    "msg.MessageService",
    "ums.MessageService",
    "ums.NotificationService",
    "dji.ums.MessageService",
    "dji.message.MessageService",
    "grpc.health.v1.Health",
    "grpc.health.v1alpha.Health",
    "spring.health.v1.Health",
    "actuator.Health",
    "actuator.health.Health",
    "org.springframework.boot.actuate.health.Health",
]

# Try known gRPC health check protocol
# grpc.health.v1.Health/Check expects: {service: "..."} as protobuf
# Protobuf: field 1 = string service
for svc in ["umsmsg.MessageService", "msg.MessageService", "email.EmailService"]:
    for service_name in ["", "umsmsg.MessageService", "umsmsg", "message"]:
        # Health Check Request: message HealthCheckRequest { string service = 1; }
        pb = bytes([0x0A, len(service_name)]) + service_name.encode() if service_name else b''
        
        for method in ["Check", "Watch", "Health", "Ping", "Status"]:
            path = f"/grpc.health.v1.Health/{method}"
            resp = grpc_call(path, body=pb)
            parsed = parse_grpc(resp)
            s = parsed.get('status', '?')
            msg = parsed.get('message', '')
            http = parsed.get('http', '?')
            body = parsed.get('body_start', '')
            
            if s != '?' or http != '403':
                marker = ''
                if s != 7 and s != '?':
                    marker = ' <<<'
                if s == 0 or (body and body != 'RBAC: access denied'):
                    marker = ' <<< INTERESTING'
                print(f"[PATH:{path}] svc='{service_name}' | HTTP={http} gRPC={s} msg={msg}{marker}")
                if body:
                    print(f"  Body: {body}")

# Phase 2: Try proto reflection with actual proto message
print("\n[Phase 2] Proto Reflection 枚举（带有效载荷）")
print("-" * 50)

# gRPC reflection protocol uses:
# message ServerReflectionRequest {
#   oneof message_request {
#     string host = 9;  (for file_by_filename)
#     string file_containing_extension = 14; (not used for listing)
#   }
#   string list_services = 7;
# }
# For listing: field 7 = list_services, with empty string value
# wire type 2 (length-delimited) for string
# Actually, in protobuf:
#   list_services is string field 7
#   So: (7 << 3) | 2 = 58 = 0x3A, then length

for svc_name in [
    "grpc.reflection.v1alpha.ServerReflection",
    "grpc.reflection.v1.ServerReflection"
]:
    for method in ["ServerReflectionInfo", "ListServices", "List", "ListService"]:
        for payload_name, payload in [
            ("empty", b''),
            # field 7 = list_services (string) - try with empty string
            ("list_services=''", bytes([0x3A, 0x00])),
            # field 7 = list_services = "umsmsg.MessageService"  
            ("list_services=umsmsg", bytes([0x3A, len("umsmsg.MessageService")]) + b"umsmsg.MessageService"),
            # field 9 = host (string)
            ("host=''", bytes([0x4A, 0x00])),
            # Try field 1-10 just to see if any changes behavior
            ("field1_varint", bytes([0x08, 0x00])),
        ]:
            path = f"/{svc_name}/{method}"
            resp = grpc_call(path, body=payload)
            parsed = parse_grpc(resp)
            s = parsed.get('status', '?')
            msg = parsed.get('message', '')
            if s != 7 or msg != 'RBAC: access denied':
                print(f"[!] {path} ({payload_name}): grpc={s} msg={msg}")

# Phase 3: Spring Boot gRPC health with different response sizes
print("\n[Phase 3] gRPC 响应体大小检测（推断服务存在性）")
print("-" * 50)

# When service doesn't exist: 12 (UNIMPLEMENTED) + short body
# When service exists but no auth: 7 (PERMISSION_DENIED) + body with error
# When healthy: 0 (OK) + protobuf body
# We measure response body length to distinguish

services_with_methods = [
    ("umsmsg.MessageService", "Send"),
    ("umsmsg.MessageService", "SendMessage"),
    ("umsmsg.NotificationService", "Notify"),
    ("umsmsg.PushService", "Push"),
    ("umsmsg.SMSService", "SendSMS"),
    ("nonexistent.NonexistentService", "NonexistentMethod"),
    ("grpc.health.v1.Health", "Check"),
    ("grpc.reflection.v1alpha.ServerReflection", "ServerReflectionInfo"),
]

for svc, method in services_with_methods:
    path = f"/{svc}/{method}"
    resp = grpc_call(path)
    parsed = parse_grpc(resp)
    s = parsed.get('status', '?')
    msg = parsed.get('message', '')
    body = parsed.get('body_start', '')
    http = parsed.get('http', '?')
    
    # 注意 response length
    rl = len(resp) if isinstance(resp, bytes) else 0
    print(f"  {svc}/{method}: HTTP={http} gRPC={s} msg='{msg}' resp_len={rl}")

# Phase 4: Try HTTP/2 gRPC (bypass proxy-level checks)
print("\n[Phase 4] HTTP/2 直连 gRPC 请求")
print("-" * 50)

def http2_grpc_call(path, body=b''):
    """Send gRPC over HTTP/2"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, PORT))
        
        # HTTP/2 connection preface
        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        s.sendall(preface)
        
        # Read SETTINGS from server
        time.sleep(0.3)
        s.recv(4096)
        
        # Send empty SETTINGS (ack)
        settings_ack = bytes.fromhex('00000004010000000000')
        s.sendall(settings_ack)
        time.sleep(0.2)
        
        # Build HEADERS frame for POST
        # Encode pseudo-headers
        headers_str = ''
        headers_str += b':method: POST'.decode()
        
        # Actually let's use HTTP/1.1 gRPC which we know works
        s.close()
        return None
    except:
        return None
    finally:
        s.close()

print("  HTTP/2 调试 - 使用 HTTP/1.1 gRPC 替代（已验证可行）")

# Phase 5: Detailed response analysis - check if gRPC response has body
print("\n[Phase 5] gRPC 响应体逐字节分析")
print("-" * 50)

# Compare the actual response bodies for different paths
paths_to_compare = [
    "/umsmsg.MessageService/Send",
    "/nonexistent.NonexistentService/NonexistentMethod",
    "/grpc.health.v1.Health/Check",
]

responses = {}
for path in paths_to_compare:
    resp = grpc_call(path)
    if isinstance(resp, bytes):
        responses[path] = resp

# Compare lengths
if responses:
    base_len = len(responses.get(paths_to_compare[0], b''))
    for path, data in responses.items():
        diff = len(data) - base_len
        print(f"  {path}: {len(data)} bytes (diff from first: {diff:+d})")

print("\n" + "=" * 70)
print("Spring Boot gRPC 深度扫描完成")
print("=" * 70)