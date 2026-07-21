#!/usr/bin/env python3
"""
PESop engine · js_harvester —— JS 全量提取 + 接口/密钥/路由提取

对应 L2 HF-2「JS 必须全量啃完」的自动化下限,分级递进拿到应用全部 JS:
  L0 入口层    HTML 的 <script src> + 内联 <script>
  L1 静态分包  识别打包工具(读 knowledge/js/bundlers.yaml)→ 抠 chunk 映射 → 递归下载全部 chunk
  L1.5 源码还原 若 JS 有 sourceMappingURL → 下载 .js.map → 解 sourcesContent → 在原始源码上提取
  L2 浏览器    (可选)headless 浏览器捕获动态加载的 JS,补静态盲区;不可用则降级静态并标注
  → 正则挖:API 路径 / fetch·axios·XHR 调用点 / 硬编码密钥 / 内部域名 → 落盘 js_assets.json

【后端接入点】前后端分离下,接口真实 URL = base(后端host:port) + prefix(如/prod-api) + path。
从 JS 挖明写的 base(axios.baseURL/环境变量/域名端口常量)与 prefix(拦截器prefix/路径公共前缀
归纳),产出结构化 backends 写入 intel。engine 只如实呈现候选,不盲拼、不发验证包——由 AI 判断
用哪个 base+prefix 去测(勿把接口直接拼在前端地址上)。

打包工具规则外置到 knowledge/js/bundlers.yaml(webpack/vite/nextjs...),加一种追加一条即可,
故 React 站点(CRA→webpack / Vite+React→vite / Next.js→nextjs)均覆盖。浏览器只"发现"URL,
真正下载仍走 http_client 存证——"发包必存证"铁律不被绕过。

依赖:主干仅标准库(pyyaml 可选);浏览器增强为可选后端(engine/js_browser.py),无则降级。

CLI:
  python engine/js_harvester.py --target https://t.com
  python engine/js_harvester.py --target https://t.com --max-js 200
  python engine/js_harvester.py --target https://t.com --no-browser   # 只走静态
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


# ---- 后端接入点(base)提取:前后端分离下,接口真实 URL = base + prefix + path ----
_RE_BASEURL = re.compile(r'''base[Uu][Rr][Ll]\s*[:=]\s*["'`]([^"'`]+)["'`]''')
_RE_ENV_API = re.compile(
    r'''["'`]?((?:VITE|VUE_APP|REACT_APP|NEXT_PUBLIC|NG)[\w]*?(?:API|BASE|URL|HOST|SERVER)[\w]*?)["'`]?\s*[:=]\s*["'`]([^"'`]+)["'`]''',
    re.I)
_RE_API_CONST = re.compile(
    r'''["'`]?((?:api|base|server|gateway|backend|service)[\w]*?(?:url|host|base|api|addr|origin))["'`]?\s*[:=]\s*["'`]([^"'`]+)["'`]''',
    re.I)
_RE_URL_PORT = re.compile(r'''["'`(](https?://[\w.\-]+:(\d{2,5})(?:/[\w\-/.]*)?)["'`)]''')
_RE_PREFIX = re.compile(
    r'''["'`]?(?:api_?prefix|prefix|context_?path|base_?path)["'`]?\s*[:=]\s*["'`](/[\w\-/]+)["'`]''',
    re.I)


def _norm_base(u):
    """把 base 候选归一。相对 '/xxx' 视为 prefix;http(s)/host:port 视为 base。非法返回 None。"""
    u = (u or "").strip()
    if not u:
        return None
    if u.startswith("/"):
        return {"kind": "prefix", "value": u.rstrip("/")}
    if not u.startswith("http"):
        p = urlparse("http://" + u)          # 补 scheme 解析 host:port
    else:
        p = urlparse(u)
    if not p.hostname:
        return None
    port = f":{p.port}" if p.port else ""
    scheme = p.scheme if u.startswith("http") else "https"
    return {"kind": "base", "base": f"{scheme}://{p.hostname}{port}",
            "prefix": p.path.rstrip("/") if p.path and p.path != "/" else ""}


def extract_backends(text, frontend_base):
    """从 JS 文本挖【后端接入点】(接口真实 URL = base + prefix + path)。
    只挖 JS 明写的(确定级),不推断、不发包。返回 (backends, prefixes)。
    """
    backends, prefixes = [], []
    fe_host = urlparse(frontend_base).hostname

    def _add_base(raw, source, conf, ctx):
        nb = _norm_base(raw)
        if not nb:
            return
        if nb["kind"] == "prefix":
            prefixes.append({"prefix": nb["value"], "source": source, "context": ctx})
        else:
            bh = urlparse(nb["base"]).hostname
            same = (bh == fe_host and ":" not in nb["base"].split("//", 1)[1])
            backends.append({"base": nb["base"], "prefix": nb["prefix"], "source": source,
                             "confidence": ("low" if same else conf),
                             "same_as_frontend": same, "context": ctx})

    for m in _RE_BASEURL.finditer(text):
        _, ctx = _line_and_context(text, m.start()); _add_base(m.group(1), "axios.baseURL", "high", ctx)
    for m in _RE_ENV_API.finditer(text):
        _, ctx = _line_and_context(text, m.start()); _add_base(m.group(2), f"env:{m.group(1)}", "high", ctx)
    for m in _RE_API_CONST.finditer(text):
        _, ctx = _line_and_context(text, m.start()); _add_base(m.group(2), f"const:{m.group(1)}", "medium", ctx)
    for m in _RE_URL_PORT.finditer(text):
        _, ctx = _line_and_context(text, m.start()); _add_base(m.group(1), f"url-with-port:{m.group(2)}", "medium", ctx)
    for m in _RE_PREFIX.finditer(text):
        _, ctx = _line_and_context(text, m.start())
        prefixes.append({"prefix": m.group(1).rstrip("/"), "source": "explicit-prefix", "context": ctx})
    return backends, prefixes


def infer_common_prefix(api_paths):
    """从多条接口路径归纳公共前缀(如都以 /prod-api/ 开头)。覆盖多数且像 API 前缀才给。"""
    if len(api_paths) < 3:
        return []
    firsts = {}
    for p in api_paths:
        if p.startswith("/"):
            seg = "/" + p.strip("/").split("/", 1)[0]
            firsts[seg] = firsts.get(seg, 0) + 1
    out = []
    for seg, cnt in firsts.items():
        if cnt >= max(3, int(len(api_paths) * 0.6)) and re.search(r'api|gateway|rest|service|admin', seg, re.I):
            out.append({"prefix": seg, "source": "inferred-common-prefix", "sample_count": cnt})
    return out


def _classify_secret(name, value):
    """把一条密钥归类,便于 AI 判断攻击面(engine 只分类不验证)。"""
    n, v = (name or "").lower(), value or ""
    if v.startswith("LTAI"):
        return "aliyun_ak"
    if v.startswith("AKIA"):
        return "aws_ak"
    if v.startswith("eyJ") and v.count(".") >= 2:
        return "jwt"
    if "wechat" in n or "wx_" in n or n in ("wechat_appid", "wx_appid"):
        return "wechat"
    if "sentry" in n:
        return "sentry_dsn"
    if "private_key" in n or "-----begin" in v.lower():
        return "private_key"
    if "client_secret" in n or "app_secret" in n or "appsecret" in n:
        return "app_secret"
    if "token" in n:
        return "token"
    if any(k in n for k in ("api_key", "apikey", "access_key", "accesskey", "secret_key")):
        return "api_key"
    return "generic"


def _line_and_context(text, pos, span=60):
    """给定命中位置,返回 (行号, 该行去空白后的片段上下文)。"""
    line_no = text.count("\n", 0, pos) + 1
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    # 片段:以命中点为中心截一段,避免整行压缩代码太长
    rel = pos - line_start
    frag = line[max(0, rel - span):rel + span]
    return line_no, frag


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
        name, value = m.group(1), m.group(2)
        line, ctx = _line_and_context(text, m.start())
        secrets.append({"name": name, "value": value,
                        "type": _classify_secret(name, value),
                        "line": line, "context": ctx})
    for m in _RE_AKID.finditer(text):
        value = m.group(1)
        line, ctx = _line_and_context(text, m.start())
        secrets.append({"name": "CLOUD_AK(疑似)", "value": value,
                        "type": _classify_secret("", value),
                        "line": line, "context": ctx})
    internal = set(m.group(1) for m in _RE_INTERNAL_HOST.finditer(text))
    return {
        "api_paths": sorted(apis),
        "callsites": sorted(callsites),
        "secrets": secrets,
        "internal_hosts": sorted(internal),
    }


# --------------------------------------------------------------------------
# 打包工具识别 + 静态分包提取(L1) —— 规则外置到 knowledge/js/bundlers.yaml
# --------------------------------------------------------------------------
_KNOW_DIR = os.path.join(_PROJECT_ROOT, "knowledge")
_BUNDLERS_YAML = os.path.join(_KNOW_DIR, "js", "bundlers.yaml")

# 通用静态资源引用:JS/HTML 里出现的 "xxx.js" 相对/绝对路径(chunk 兜底捞取)
_RE_JS_REF = re.compile(r'["\'\(]([\w./\-]*?/?[\w\-]+\.[\w]*\.?js)["\'\)]', re.I)
# webpack chunkId -> hash 映射片段: {12:"abc",34:"def"} 或 {12:"abc"}
_RE_WP_MAP = re.compile(r'\{((?:\s*\d+\s*:\s*"[\w\-]+"\s*,?)+)\}')
# webpack publicPath: .p="/static/js/" 或 __webpack_require__.p=
_RE_WP_PUBPATH = re.compile(r'\.p\s*=\s*["\']([^"\']*)["\']')
# vite modulepreload / import
_RE_VITE_PRELOAD = re.compile(r'<link[^>]+rel=["\']modulepreload["\'][^>]+href=["\']([^"\']+)["\']', re.I)
_RE_VITE_IMPORT = re.compile(r'''import[^"'`]*["'`](/assets/[^"'`]+\.js)["'`]''')
# sourceMappingURL
_RE_SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=([^\s*]+)')


def _load_bundlers():
    """读打包工具规则库(pyyaml 优先,无则内置极简兜底)。返回 list。"""
    if not os.path.exists(_BUNDLERS_YAML):
        return []
    with open(_BUNDLERS_YAML, encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml
        return (yaml.safe_load(text) or {}).get("bundlers", [])
    except ImportError:
        return _minimal_parse_bundlers(text)


def _minimal_parse_bundlers(text):
    """无 pyyaml 兜底:只解析 id/chunk_rule + detect/asset_dirs 的内联列表。"""
    out, cur = [], None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        m_id = re.match(r'^\s*-\s*id:\s*(\S+)', line)
        if m_id:
            if cur:
                out.append(cur)
            cur = {"id": m_id.group(1).strip('"\''), "detect": [], "asset_dirs": []}
            continue
        if cur is None:
            continue
        m = re.match(r'^\s+(\w+):\s*(.*)$', line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k in ("detect", "asset_dirs") and v.startswith("["):
            # 稳健切分内联列表:按引号配对提取每个元素(容忍元素内的逗号/转义)
            inner = v.strip()[1:-1] if v.endswith("]") else v.strip()[1:]
            items = re.findall(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', inner)
            if items:
                cur[k] = [(a or b).replace('\\"', '"').replace("\\'", "'") for a, b in items]
            else:
                cur[k] = [x.strip().strip('"\'') for x in inner.split(",") if x.strip()]
        elif k in ("chunk_rule", "note"):
            cur[k] = v.strip('"\'')
    if cur:
        out.append(cur)
    return out


def identify_bundler(html_text, entry_js_text, bundlers):
    """按 detect 信号识别打包工具。返回 bundler dict 或 None。"""
    blob = (html_text + "\n" + entry_js_text).lower()
    for b in bundlers:
        for sig in b.get("detect", []):
            if sig.lower() in blob:
                return b
    return None


def _abs_js_url(ref, base):
    """把一个 js 引用转成绝对 URL。"""
    return ref if ref.startswith("http") else urljoin(base, ref)


def extract_chunk_urls(texts, base, bundler, asset_dirs_extra=None):
    """
    从若干 JS/HTML 文本里,按 bundler 的 chunk_rule + 通用资源引用扫描,抠出所有 chunk 的绝对 URL。
    texts: [文本,...]  base: 站点根 URL。返回去重后的 URL 列表。
    """
    found = set()
    rule = (bundler or {}).get("chunk_rule")
    asset_dirs = list((bundler or {}).get("asset_dirs", []))
    if asset_dirs_extra:
        asset_dirs += asset_dirs_extra
    joined = "\n".join(texts)

    # 规则一:webpack chunkId->hash 映射 + publicPath + 文件名拼接
    if rule == "webpack_chunk_map":
        pubpaths = _RE_WP_PUBPATH.findall(joined) or [""]
        for mp in _RE_WP_MAP.finditer(joined):
            pairs = re.findall(r'(\d+)\s*:\s*"([\w\-]+)"', mp.group(1))
            for cid, chash in pairs:
                for pp in pubpaths:
                    # 常见命名: <pub><cid>.<hash>.chunk.js / <pub><cid>.<hash>.js
                    for tpl in (f"{cid}.{chash}.chunk.js", f"{cid}.{chash}.js", f"{chash}.js"):
                        found.add(urljoin(base, (pp or "/static/js/") + tpl))

    # 规则二:vite modulepreload / import
    if rule == "vite_modulepreload":
        for m in _RE_VITE_PRELOAD.finditer(joined):
            found.add(urljoin(base, m.group(1)))
        for m in _RE_VITE_IMPORT.finditer(joined):
            found.add(urljoin(base, m.group(1)))

    # 规则三:nextjs —— 直接扫 /_next/static/ 下的 .js 引用(manifest 与 chunk 都在此)
    if rule == "nextjs_manifest":
        for m in re.finditer(r'["\'\(](/_next/static/[^"\'\)]+\.js)["\'\)]', joined):
            found.add(urljoin(base, m.group(1)))

    # 通用兜底:扫所有 "xxx.js" 引用,命中 asset_dirs 前缀的收进来(不依赖精确映射)
    for m in _RE_JS_REF.finditer(joined):
        ref = m.group(1)
        if ref.startswith("http"):
            # 只收本站同源的
            if urlparse(ref).hostname == urlparse(base).hostname:
                found.add(ref)
            continue
        norm = ref if ref.startswith("/") else "/" + ref
        if not asset_dirs or any(norm.startswith(d) for d in asset_dirs) or "/" in ref:
            found.add(urljoin(base, ref))
    return sorted(found)


def _find_sourcemap_url(js_body, js_url):
    """从 JS 末尾找 sourceMappingURL,返回 .map 的绝对 URL 或 None。"""
    m = None
    for m in _RE_SOURCEMAP.finditer(js_body):
        pass  # 取最后一个
    if not m:
        return None
    ref = m.group(1).strip()
    if ref.startswith("data:"):
        return None   # 内联 base64 sourcemap,由调用方另行解(v0.1 只处理外链 .map)
    return urljoin(js_url, ref)


def recover_sourcemap(map_body):
    """解析 .js.map,返回 sourcesContent 拼接的原始源码(供提取)。失败返回 ""。"""
    try:
        data = json.loads(map_body)
    except (json.JSONDecodeError, TypeError):
        return "", 0
    srcs = data.get("sourcesContent") or []
    real = [s for s in srcs if s]
    return "\n".join(real), len(real)


def _split_body(raw_response):
    """从 http_client 落盘的 raw_response 里切出响应体(兼容 CRLF 与 LF 两种分隔)。"""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_response:
            return raw_response.split(sep, 1)[1]
    return raw_response


def _download(target_base, url, note):
    """走 http_client 下载一个 URL,返回 (evidence_id, status, size, body) 或 None。"""
    r = http_client.send(target=target_base, method="GET", path=url, note=note)
    try:
        with open(r["evidence_path"], encoding="utf-8") as f:
            body = json.load(f)["raw_response"]
    except Exception:
        body = ""
    return r, _split_body(body)


def harvest(target, html_path="/", max_js=100, use_browser="auto"):
    tdir = _target_dir(target)
    base = target if target.startswith("http") else "https://" + target
    result = {
        "target": target,
        "html_entry": html_path,
        "bundler": None,
        "evidence_ids": [],
        "js_files": [],
        "sourcemaps": [],
        "browser_augment": False,
        "backends": [],
        "prefixes": [],
        "aggregate": {"api_paths": set(), "callsites": set(),
                      "secrets": [], "internal_hosts": set()},
    }

    # L0. 拉入口 HTML
    r = http_client.send(target=target, method="GET", path=html_path, note="js_harvester:入口HTML")
    result["evidence_ids"].append(r["evidence_id"])
    with open(r["evidence_path"], encoding="utf-8") as f:
        html_raw = json.load(f)["raw_response"]
    html_body = _split_body(html_raw)

    # L0. 入口 <script src> + 内联
    entry_urls = _find_script_urls(html_body, base)
    inline_blocks = re.findall(r'<script(?![^>]*src)[^>]*>(.*?)</script>', html_body, re.S | re.I)
    inline_text = "\n".join(inline_blocks) if inline_blocks else ""
    if inline_text.strip():
        ext = _extract_from_js(inline_text)
        for s in ext["secrets"]:
            s["js_url"] = "<inline-in-html>"
        result["js_files"].append({"url": "<inline-in-html>", "evidence_id": r["evidence_id"],
                                   "source": "inline", "skipped": False, "extracted": ext})
        _merge(result["aggregate"], ext)
        bks, pfs = extract_backends(inline_text, base)
        result["backends"].extend(bks)
        result["prefixes"].extend(pfs)

    # 先下载入口 JS(用于识别打包工具 + 抠 chunk 映射)
    queue = list(entry_urls)           # 待下载队列(会追加 chunk)
    seen = set()
    entry_texts = [html_body, inline_text]
    downloaded_entry = []
    for eu in entry_urls[:max_js]:
        seen.add(eu)
        jr, jbody = _download(base, eu, note="js_harvester:entryJS")
        result["evidence_ids"].append(jr["evidence_id"])
        downloaded_entry.append((eu, jr, jbody))
        entry_texts.append(jbody)

    # L1. 识别打包工具 + 静态分包:抠出所有 chunk URL 追加进队列
    bundlers = _load_bundlers()
    bundler = identify_bundler(html_body, "\n".join(entry_texts), bundlers)
    result["bundler"] = bundler["id"] if bundler else None
    chunk_urls = extract_chunk_urls(entry_texts, base, bundler)
    for cu in chunk_urls:
        if cu not in seen:
            seen.add(cu)
            queue.append(cu)

    # 汇总要处理的 JS:入口(已下)+ chunk(待下)
    def _process_js(url, source, jr, jbody):
        # L1.5 sourcemap 还原:有 .map 就在源码上提取(信息更全),否则在(压缩)body 上提取
        text_for_extract = jbody
        sm_url = _find_sourcemap_url(jbody, urljoin(base, url) if not url.startswith("http") else url)
        from_sm = False
        if sm_url:
            smr, smbody = _download(base, sm_url, note="js_harvester:sourcemap")
            result["evidence_ids"].append(smr["evidence_id"])
            src_code, n = recover_sourcemap(smbody)
            if src_code:
                text_for_extract = src_code
                from_sm = True
                result["sourcemaps"].append({"js_url": url, "map_url": sm_url, "recovered_sources": n})
        ext = _extract_from_js(text_for_extract)
        # 给每条密钥补来源 JS URL(便于回溯:哪个文件第几行)
        src_label = url + (" (via sourcemap)" if from_sm else "")
        for s in ext["secrets"]:
            s["js_url"] = src_label
        result["js_files"].append({
            "url": url, "evidence_id": jr["evidence_id"],
            "status": jr.get("status_code"), "size": jr.get("size_download"),
            "source": source, "from_sourcemap": from_sm, "skipped": False, "extracted": ext,
        })
        _merge(result["aggregate"], ext)
        # 挖后端接入点(base+prefix):前后端分离下接口真实 URL = base+prefix+path
        bks, pfs = extract_backends(text_for_extract, base)
        for b in bks:
            if b["base"] + b["prefix"] not in {x["base"] + x["prefix"] for x in result["backends"]}:
                result["backends"].append(b)
        for pf in pfs:
            if pf["prefix"] not in {x["prefix"] for x in result["prefixes"]}:
                result["prefixes"].append(pf)

    for (eu, jr, jbody) in downloaded_entry:
        _process_js(eu, "entry", jr, jbody)

    # 下载并处理 chunk(受 max_js 限;超限显式标跳过)
    processed = len(downloaded_entry)
    for cu in queue:
        if cu in {j["url"] for j in result["js_files"]}:
            continue
        if processed >= max_js:
            result["js_files"].append({"url": cu, "skipped": True,
                                       "skip_reason": f"超出 max_js={max_js},未验证——提高 max_js 重跑"})
            continue
        jr, jbody = _download(base, cu, note="js_harvester:chunkJS")
        result["evidence_ids"].append(jr["evidence_id"])
        _process_js(cu, "chunk", jr, jbody)
        processed += 1

    # L2. 浏览器增强(可选):发现动态 chunk 的 URL,仍交 http_client 下载存证
    if use_browser in ("auto", True, "true", "yes"):
        try:
            import js_browser as _jb
            cap = _jb.capture(target)
            if cap.get("available"):
                result["browser_augment"] = True
                for bu in cap.get("js_urls", []):
                    if bu in {j["url"] for j in result["js_files"]} or processed >= max_js:
                        continue
                    jr, jbody = _download(base, bu, note="js_harvester:browserJS")
                    result["evidence_ids"].append(jr["evidence_id"])
                    _process_js(bu, "browser", jr, jbody)
                    processed += 1
        except Exception as e:
            result["browser_note"] = f"浏览器增强不可用,已降级静态:{e}"

    # 汇总落盘
    agg = result["aggregate"]
    # 前缀:显式挖到的 + 从接口路径归纳的(去重)
    all_prefixes = list(result["prefixes"])
    seen_pf = {p["prefix"] for p in all_prefixes}
    for pf in infer_common_prefix(sorted(agg["api_paths"])):
        if pf["prefix"] not in seen_pf:
            all_prefixes.append(pf); seen_pf.add(pf["prefix"])
    coverage = f"打包工具={result['bundler'] or '未识别'};静态chunk={len(chunk_urls)}个"
    coverage += ";浏览器增强已跑" if result["browser_augment"] else ";未做浏览器增强(动态chunk可能漏)"
    out = {
        "target": target,
        "bundler": result["bundler"],
        "evidence_ids": result["evidence_ids"],
        "js_file_count": len([j for j in result["js_files"] if not j.get("skipped")]),
        "skipped_count": len([j for j in result["js_files"] if j.get("skipped")]),
        "sourcemap_count": len(result["sourcemaps"]),
        "browser_augment": result["browser_augment"],
        "coverage_note": coverage,
        "js_files": result["js_files"],
        "sourcemaps": result["sourcemaps"],
        "backends": result["backends"],
        "prefixes": all_prefixes,
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
        for b in out["backends"]:
            _intel.add(target, "backends", b, dedup_key="base")
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
    ap = argparse.ArgumentParser(description="PESop JS 全量提取(静态分包+sourcemap+可选浏览器)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--html-path", default="/")
    ap.add_argument("--max-js", type=int, default=100)
    ap.add_argument("--no-browser", action="store_true", help="禁用浏览器增强,只走静态")
    args = ap.parse_args()
    out = harvest(args.target, args.html_path, args.max_js,
                  use_browser=(not args.no_browser))
    summary = {
        "target": out["target"],
        "bundler": out["bundler"],
        "js_file_count": out["js_file_count"],
        "skipped_count": out["skipped_count"],
        "sourcemap_count": out["sourcemap_count"],
        "browser_augment": out["browser_augment"],
        "coverage_note": out["coverage_note"],
        "api_paths_found": len(out["aggregate"]["api_paths"]),
        "callsites_found": len(out["aggregate"]["callsites"]),
        "secrets_found": len(out["aggregate"]["secrets"]),
        "internal_hosts_found": len(out["aggregate"]["internal_hosts"]),
        "detail_file": f"runs/{_slug(args.target)}/js_assets.json",
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if out.get("backends") or out.get("prefixes"):
        print("\n[*] 后端接入点(接口真实URL = base + prefix + path,勿直接拼前端地址):")
        for b in out.get("backends", [])[:10]:
            flag = " (疑似仍是前端)" if b.get("same_as_frontend") else ""
            print(f"    base={b['base']}{b['prefix']}  [{b['confidence']}] 来源:{b['source']}{flag}")
        for p in out.get("prefixes", [])[:10]:
            print(f"    prefix={p['prefix']}  来源:{p['source']}")
    if out["aggregate"]["secrets"]:
        print("\n[!] 疑似密钥(分类+来源,engine 只如实呈现不验证,由你判断攻击面):")
        for s in out["aggregate"]["secrets"][:15]:
            loc = f"{s.get('js_url','?')}:{s.get('line','?')}"
            print(f"    [{s.get('type','generic')}] {s['name']} = {str(s['value'])[:40]}...")
            print(f"        ↳ 来源 {loc}")


if __name__ == "__main__":
    main()
