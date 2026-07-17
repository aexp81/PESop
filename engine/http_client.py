#!/usr/bin/env python3
"""
PESop engine · http_client —— 统一发包 + 自动存证

这是整套 SOP "执行即证据" 范式的地基：
  - 任何一次发包都会把 [完整 raw 请求 + 完整 raw 响应 + 元数据] 落盘成一条证据。
  - 返回一个 evidence_id，供后续 "确认漏洞 / 证伪" 时引用真实证据，
    而不是让 AI 用文字复述一个它没真正发出去的响应（这是治 F2 谎报的关键）。

发包后端优先级（对应 "curl 优先 + python 兜底" 策略）：
  1. curl   —— 渗透场景首选，raw 能力强、行为最接近手工验证。
  2. python —— urllib 标准库兜底，curl 不可用 / 报错时自动降级，零依赖。

设计约束：
  - 只用 Python 标准库，保证持久化环境到哪都能跑，不装依赖。
  - 不做任何 "智能判定漏洞"，只负责 "如实发包 + 如实存证"。判定交给上层。

CLI 用法（AI 可直接 shell 调用）：
  python engine/http_client.py --target https://t.com GET /api/user
  python engine/http_client.py --target https://t.com POST /login \
      -H "Content-Type: application/json" --data '{"u":"a"}'
  python engine/http_client.py --target https://t.com GET /x --backend python
  python engine/http_client.py --target https://t.com GET /x --note "越权测试:B账号token"
"""

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

# runs/ 根目录：所有证据按目标隔离存放
_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
RUNS_ROOT = os.path.join(_PROJECT_ROOT, "runs")


def _now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()


def _slug(target: str) -> str:
    """把 target URL 转成安全的目录名，如 https://a.com:8080 -> a.com_8080"""
    p = urlparse(target if "://" in target else "http://" + target)
    host = p.hostname or "unknown"
    port = f"_{p.port}" if p.port else ""
    return f"{host}{port}".replace("/", "_")


def _evidence_dir(target: str) -> str:
    d = os.path.join(RUNS_ROOT, _slug(target), "evidence")
    os.makedirs(d, exist_ok=True)
    return d


def _curl_available() -> bool:
    return shutil.which("curl") is not None


# --------------------------------------------------------------------------
# 发包后端 1：curl
# --------------------------------------------------------------------------
def _send_via_curl(url, method, headers, data, timeout, insecure):
    """
    用 curl 发包。-i 带响应头，-s 静默，-S 显示错误，--max-time 超时。
    用 \\r\\n\\r\\n 切分响应头与响应体；用 %{...} 拿状态码等元数据。
    返回 (raw_request_repr, raw_response, meta) 或抛异常。
    """
    # 用 -w 把机器可读的元数据附在响应末尾,再切出来。
    # marker 两侧用换行,write-out 用竖线分隔的纯文本(不塞 JSON,避免引号转义坑)。
    marker = "\nPESOP_META|"
    write_out = marker + "%{http_code}|%{time_total}|%{size_download}|%{num_redirects}|%{url_effective}\n"

    cmd = ["curl", "-i", "-s", "-S", "--max-time", str(timeout),
           "-X", method, "-w", write_out]
    if insecure:
        cmd.append("-k")
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if data is not None:
        cmd += ["--data-binary", data]
    cmd.append(url)

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(f"curl failed rc={proc.returncode}: {proc.stderr.strip()}")

    out = proc.stdout
    meta_extra = {}
    if "PESOP_META|" in out:
        out, meta_line = out.rsplit("\nPESOP_META|", 1)
        parts = meta_line.strip().split("|")
        keys = ["http_code", "time_total", "size_download", "num_redirects", "url_effective"]
        meta_extra = dict(zip(keys, parts))

    # 状态码：优先用 -w 的 http_code；拿不到时从响应行正则兜底(取重定向链最后一个)
    status_code = _safe_int(meta_extra.get("http_code"))
    if status_code is None:
        import re as _re
        codes = _re.findall(r"HTTP/[\d.]+\s+(\d{3})", out)
        status_code = int(codes[-1]) if codes else None

    # 重建可读的 raw 请求（curl 不回显请求，这里按实际参数重构）
    req_lines = [f"{method} {url}"]
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    if data is not None:
        req_lines.append("")
        req_lines.append(data)
    raw_request = "\n".join(req_lines)

    meta = {
        "backend": "curl",
        "status_code": status_code,
        "time_total_s": _safe_float(meta_extra.get("time_total")),
        "size_download": _safe_int(meta_extra.get("size_download")),
        "url_effective": meta_extra.get("url_effective"),
        "num_redirects": _safe_int(meta_extra.get("num_redirects")),
        "curl_stderr": proc.stderr.strip() or None,
    }
    return raw_request, out, meta


# --------------------------------------------------------------------------
# 发包后端 2：python urllib（兜底）
# --------------------------------------------------------------------------
def _send_via_python(url, method, headers, data, timeout, insecure):
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)

    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    t0 = time.time()
    status = None
    resp_headers = []
    resp_body = ""
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            status = r.status
            resp_headers = list(r.getheaders())
            resp_body = r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        # HTTP 错误码（4xx/5xx）也是有效响应，必须存证，不是异常
        status = e.code
        resp_headers = list(e.headers.items()) if e.headers else []
        resp_body = e.read().decode("utf-8", errors="replace")
    elapsed = time.time() - t0

    # 重建 raw
    req_lines = [f"{method} {url}"]
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    if data is not None:
        req_lines.append("")
        req_lines.append(data if isinstance(data, str) else data.decode("utf-8", "replace"))
    raw_request = "\n".join(req_lines)

    resp_lines = [f"HTTP {status}"]
    for k, v in resp_headers:
        resp_lines.append(f"{k}: {v}")
    resp_lines.append("")
    resp_lines.append(resp_body)
    raw_response = "\n".join(resp_lines)

    meta = {
        "backend": "python",
        "status_code": status,
        "time_total_s": round(elapsed, 4),
        "size_download": len(resp_body),
        "url_effective": url,
    }
    return raw_request, raw_response, meta


def _safe_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _safe_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# 对外主函数
# --------------------------------------------------------------------------
def send(target, method="GET", path="/", headers=None, data=None,
         timeout=20, insecure=True, backend="auto", note=""):
    """
    发一个请求并落盘存证。返回 dict：
      { evidence_id, status_code, backend, time_total_s, size_download,
        evidence_path, raw_response(截断预览) }
    backend: auto(默认,curl优先) | curl | python
    note: 这次请求的意图（如 "越权:B账号token调A资源"），写进证据元数据，
          方便回看时一眼知道每条证据在验证什么假设。
    """
    headers = dict(headers or {})
    url = urljoin(target if target.endswith("/") else target + "/", path.lstrip("/")) \
        if not path.startswith("http") else path

    # 选后端
    use = backend
    if backend == "auto":
        use = "curl" if _curl_available() else "python"

    err = None
    try:
        if use == "curl":
            raw_req, raw_resp, meta = _send_via_curl(url, method, headers, data, timeout, insecure)
        else:
            raw_req, raw_resp, meta = _send_via_python(url, method, headers, data, timeout, insecure)
    except Exception as e:
        # curl 意外失败 → 自动降级 python（仅 auto 模式）
        if backend == "auto" and use == "curl":
            err = f"curl 失败,已降级 python: {e}"
            raw_req, raw_resp, meta = _send_via_python(url, method, headers, data, timeout, insecure)
        else:
            raise

    evidence_id = f"ev-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    record = {
        "evidence_id": evidence_id,
        "timestamp": _now_iso(),
        "target": target,
        "request": {"method": method, "url": url, "headers": headers,
                    "data": data, "note": note},
        "meta": meta,
        "fallback_note": err,
        "raw_request": raw_req,
        "raw_response": raw_resp,
    }
    ev_dir = _evidence_dir(target)
    ev_path = os.path.join(ev_dir, f"{evidence_id}.json")
    with open(ev_path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)

    return {
        "evidence_id": evidence_id,
        "status_code": meta.get("status_code"),
        "backend": meta.get("backend"),
        "time_total_s": meta.get("time_total_s"),
        "size_download": meta.get("size_download"),
        "evidence_path": ev_path,
        "fallback_note": err,
        "raw_response_preview": raw_resp[:800],
    }


def _parse_headers(header_list):
    h = {}
    for item in header_list or []:
        if ":" in item:
            k, v = item.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def main():
    ap = argparse.ArgumentParser(description="PESop 统一发包+存证 (curl优先,python兜底)")
    ap.add_argument("--target", required=True, help="目标基址,如 https://t.com")
    ap.add_argument("method", nargs="?", default="GET")
    ap.add_argument("path", nargs="?", default="/")
    ap.add_argument("-H", "--header", action="append", default=[], help="请求头,可多次")
    ap.add_argument("--data", default=None, help="请求体")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--backend", choices=["auto", "curl", "python"], default="auto")
    ap.add_argument("--note", default="", help="本次请求意图,写入证据")
    ap.add_argument("--secure", action="store_true", help="校验证书(默认不校验)")
    args = ap.parse_args()

    result = send(
        target=args.target, method=args.method.upper(), path=args.path,
        headers=_parse_headers(args.header), data=args.data,
        timeout=args.timeout, insecure=not args.secure,
        backend=args.backend, note=args.note,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
