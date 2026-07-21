#!/usr/bin/env python3
"""
PESop engine · js_harvester —— JS 全量拉取 + 接口/密钥/路由提取

对应 L2 HF-2「JS 必须全量啃完」的自动化下限:
  拉 HTML -> 提取所有 <script src> 与内联 JS -> 逐个下载(走 http_client 存证)
  -> 正则挖: API 路径 / fetch·axios·XHR 调用点 / 硬编码密钥token / 路由表
  -> 汇总成 "接口候选清单 + 敏感信息清单",落盘 runs/<target>/js_assets.json

定位:这是"挖全"的机器下限,不是终点。它保证不会因为"JS 是压缩大包/第三方
库"就漏挖(治 F3)。跳过任何文件都会在产物里显式标注"跳过+理由+但未验证"。

密钥检测走高信号常量名(见 L3 repair.ryzerobotics 教训:WECHAT_APPKEY/SENTRY_DSN
/API_KEY 等大写常量),而非低命中的泛正则,减少噪声。

依赖:仅标准库 + 复用 http_client。

CLI:
  python engine/js_harvester.py --target https://t.com
  python engine/js_harvester.py --target https://t.com --html-path /   # 指定入口页
  python engine/js_harvester.py --target https://t.com --max-js 50
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
RUNS_ROOT = os.path.join(_PROJECT_ROOT, "runs")

sys.path.insert(0, _ENGINE_DIR)
import http_client  # noqa: E402


def _slug(target):
    p = urlparse(target if "://" in target else "http://" + target)
    host = p.hostname or "unknown"
    port = f"_{p.port}" if p.port else ""
    return f"{host}{port}".replace("/", "_")


def _target_dir(target):
    d = os.path.join(RUNS_ROOT, _slug(target))
    os.makedirs(d, exist_ok=True)
    return d


# --------------------------------------------------------------------------
# 提取正则
# --------------------------------------------------------------------------
# <script src="...">
_RE_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
# API 路径:以 / 开头、像接口的路径(含 /api /v1 /rest 等,或带层级)
_RE_API_PATH = re.compile(r'["\'](/(?:api|rest|v\d|service|gateway|admin|internal)[\w\-/{}.:]*)["\']', re.I)
# 泛化路径(次级信号):任意多段路径字符串
_RE_ANY_PATH = re.compile(r'["\'](/[a-zA-Z][\w\-]+(?:/[\w\-{}.:]+){1,})["\']')
# fetch/axios/xhr 调用点
_RE_CALLSITE = re.compile(r'(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch)|XMLHttpRequest|\.open)\s*\(\s*["\']([^"\']+)["\']', re.I)

# 高信号密钥常量名(大写命名约定) = value
_SECRET_KEY_NAMES = [
    "APP_KEY", "APPKEY", "APP_SECRET", "APPSECRET", "SECRET_KEY", "SECRETKEY",
    "API_KEY", "APIKEY", "ACCESS_KEY", "ACCESSKEY", "AK", "SK",
    "WECHAT_APPKEY", "WX_APPID", "WECHAT_APPID",
    "SENTRY_DSN", "TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN",
    "PRIVATE_KEY", "CLIENT_SECRET", "OSS_ACCESS", "STS_TOKEN",
    "AMAP_KEY", "GOOGLE_API_KEY", "FIREBASE",
]
_RE_SECRET = re.compile(
    r'["\']?(' + "|".join(re.escape(k) for k in _SECRET_KEY_NAMES) +
    r')["\']?\s*[:=]\s*["\']([^"\']{6,120})["\']', re.I)
# 通用高熵疑似密钥(次级):AKID / 32位hex / 长base64
_RE_AKID = re.compile(r'(LTAI[0-9A-Za-z]{12,}|AKIA[0-9A-Z]{16})')  # 阿里云/AWS AK
# 内部域名
_RE_INTERNAL_HOST = re.compile(r'["\'](https?://[\w.\-]*(?:internal|intranet|corp|test|dev|stg|staging|pre)[\w.\-]*[^"\']*)["\']', re.I)


def _find_script_urls(html, base):
    urls = []
    for m in _RE_SCRIPT_SRC.finditer(html):
        src = m.group(1)
        urls.append(src if src.startswith("http") else urljoin(base, src))
    # 去重保序
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u); out.append(u)
    return out


def _extract_from_js(text):
    apis = set(m.group(1) for m in _RE_API_PATH.finditer(text))
    for m in _RE_ANY_PATH.finditer(text):
        apis.add(m.group(1))
    callsites = set(m.group(1) for m in _RE_CALLSITE.finditer(text))
    secrets = []
    for m in _RE_SECRET.finditer(text):
        secrets.append({"name": m.group(1), "value": m.group(2)})
    for m in _RE_AKID.finditer(text):
        secrets.append({"name": "CLOUD_AK(疑似)", "value": m.group(1)})
    internal = set(m.group(1) for m in _RE_INTERNAL_HOST.finditer(text))
    return {
        "api_paths": sorted(apis),
        "callsites": sorted(callsites),
        "secrets": secrets,
        "internal_hosts": sorted(internal),
    }


def harvest(target, html_path="/", max_js=100):
    tdir = _target_dir(target)
    result = {
        "target": target,
        "html_entry": html_path,
        "evidence_ids": [],
        "js_files": [],       # 每个 js: {url, evidence_id, status, size, skipped, skip_reason, extracted}
        "aggregate": {"api_paths": set(), "callsites": set(),
                      "secrets": [], "internal_hosts": set()},
    }

    # 1. 拉入口 HTML
    r = http_client.send(target=target, method="GET", path=html_path, note="js_harvester:入口HTML")
    result["evidence_ids"].append(r["evidence_id"])
    with open(r["evidence_path"], encoding="utf-8") as f:
        html_raw = json.load(f)["raw_response"]

    base = target if target.startswith("http") else "https://" + target
    script_urls = _find_script_urls(html_raw, base)

    # 内联 JS 也挖(HTML 里 <script>...</script> 的内容)
    inline_blocks = re.findall(r'<script(?![^>]*src)[^>]*>(.*?)</script>', html_raw, re.S | re.I)
    if inline_blocks:
        inline_text = "\n".join(inline_blocks)
        ext = _extract_from_js(inline_text)
        result["js_files"].append({"url": "<inline-in-html>", "evidence_id": r["evidence_id"],
                                   "skipped": False, "extracted": ext})
        _merge(result["aggregate"], ext)

    # 2. 逐个下载 JS(全量,不因"大包/三方库"跳过;超出 max_js 才显式标跳过)
    for i, ju in enumerate(script_urls):
        if i >= max_js:
            result["js_files"].append({
                "url": ju, "skipped": True,
                "skip_reason": f"超出 max_js={max_js} 限制,但未验证——请提高 max_js 重跑",
            })
            continue
        jr = http_client.send(target=base, method="GET", path=ju, note=f"js_harvester:JS[{i}]")
        result["evidence_ids"].append(jr["evidence_id"])
        with open(jr["evidence_path"], encoding="utf-8") as f:
            body = json.load(f)["raw_response"]
        # 切掉响应头,只留 body 做提取
        js_body = body.split("\n\n", 1)[1] if "\n\n" in body else body
        ext = _extract_from_js(js_body)
        result["js_files"].append({
            "url": ju, "evidence_id": jr["evidence_id"],
            "status": jr["status_code"], "size": jr["size_download"],
            "skipped": False, "extracted": ext,
        })
        _merge(result["aggregate"], ext)

    # 3. 汇总集合转 list 落盘
    agg = result["aggregate"]
    out = {
        "target": target,
        "evidence_ids": result["evidence_ids"],
        "js_file_count": len([j for j in result["js_files"] if not j.get("skipped")]),
        "skipped_count": len([j for j in result["js_files"] if j.get("skipped")]),
        "js_files": result["js_files"],
        "aggregate": {
            "api_paths": sorted(agg["api_paths"]),
            "callsites": sorted(agg["callsites"]),
            "secrets": agg["secrets"],
            "internal_hosts": sorted(agg["internal_hosts"]),
        },
    }
    with open(os.path.join(tdir, "js_assets.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    # 产物自动流入 intel(接口/密钥/内网域名自动进情报库,供各域取用)
    try:
        import intel as _intel
        for p in out["aggregate"]["api_paths"]:
            _intel.add(target, "endpoints", {"path": p, "method": "?", "source": "js"}, dedup_key="path")
        for s in out["aggregate"]["secrets"]:
            _intel.add(target, "secrets", {**s, "source": s.get("name", "js")}, dedup_key="value")
        for h in out["aggregate"]["internal_hosts"]:
            _intel.add(target, "hosts", h)
        out["intel_synced"] = True
    except Exception as e:
        out["intel_sync_error"] = str(e)
    return out


def _merge(agg, ext):
    agg["api_paths"].update(ext["api_paths"])
    agg["callsites"].update(ext["callsites"])
    agg["secrets"].extend(ext["secrets"])
    agg["internal_hosts"].update(ext["internal_hosts"])


def main():
    ap = argparse.ArgumentParser(description="PESop JS 全量拉取+接口/密钥提取")
    ap.add_argument("--target", required=True)
    ap.add_argument("--html-path", default="/")
    ap.add_argument("--max-js", type=int, default=100)
    args = ap.parse_args()
    out = harvest(args.target, args.html_path, args.max_js)
    # 控制台只打摘要,详情看落盘文件
    summary = {
        "target": out["target"],
        "js_file_count": out["js_file_count"],
        "skipped_count": out["skipped_count"],
        "api_paths_found": len(out["aggregate"]["api_paths"]),
        "callsites_found": len(out["aggregate"]["callsites"]),
        "secrets_found": len(out["aggregate"]["secrets"]),
        "internal_hosts_found": len(out["aggregate"]["internal_hosts"]),
        "detail_file": f"runs/{_slug(args.target)}/js_assets.json",
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if out["aggregate"]["secrets"]:
        print("\n[!] 疑似密钥(需人工确认):")
        for s in out["aggregate"]["secrets"][:10]:
            print(f"    {s['name']} = {s['value'][:40]}...")


if __name__ == "__main__":
    main()
