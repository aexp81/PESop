#!/usr/bin/env python3
"""
js_harvester 静态分包 + sourcemap 还原单元测试(不发真包,纯函数级)。

覆盖:
  1. 打包工具识别(webpack/vite/nextjs 的 detect 命中)
  2. chunk URL 提取(webpack chunk_map / vite modulepreload / nextjs / 通用引用兜底)
  3. sourcemap 解析(sourcesContent 还原)
  4. CRLF/LF 响应头切分(修复历史 bug)
  5. bundlers.yaml 无 pyyaml 兜底解析与 pyyaml 一致
运行: pytest engine/tests/test_js_harvester.py -v
"""
import os
import sys

_ENGINE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ENGINE_DIR)
import js_harvester as jh   # noqa: E402

BASE = "https://t.example.com"


# ---------------------------------------------------------- 打包工具识别
def test_identify_webpack():
    b = jh.identify_bundler("<html></html>", "var x=__webpack_require__(0)", jh._load_bundlers())
    assert b and b["id"] == "webpack"


def test_identify_nextjs():
    b = jh.identify_bundler('<script src="/_next/static/chunks/main.js">', "", jh._load_bundlers())
    assert b and b["id"] == "nextjs"


def test_identify_vite():
    b = jh.identify_bundler('<script type="module" src="/assets/index.js">', "", jh._load_bundlers())
    assert b and b["id"] == "vite"


def test_identify_none():
    assert jh.identify_bundler("<html>plain</html>", "", jh._load_bundlers()) is None


# ---------------------------------------------------------- chunk 提取
def test_webpack_chunk_map():
    bundlers = jh._load_bundlers()
    wp = next(b for b in bundlers if b["id"] == "webpack")
    # 模拟 webpack runtime 里的 chunkId->hash 映射 + publicPath
    entry = '__webpack_require__.p="/static/js/";var m={12:"aaa",34:"bbb"};'
    urls = jh.extract_chunk_urls([entry], BASE, wp)
    joined = " ".join(urls)
    assert "12.aaa" in joined and "34.bbb" in joined
    assert all(u.startswith("https://t.example.com/static/js/") for u in urls if "static/js" in u)


def test_vite_modulepreload():
    bundlers = jh._load_bundlers()
    vt = next(b for b in bundlers if b["id"] == "vite")
    html = '<link rel="modulepreload" href="/assets/vendor-abc.js">'
    urls = jh.extract_chunk_urls([html], BASE, vt)
    assert "https://t.example.com/assets/vendor-abc.js" in urls


def test_nextjs_chunks():
    bundlers = jh._load_bundlers()
    nx = next(b for b in bundlers if b["id"] == "nextjs")
    txt = '{"page":"/_next/static/chunks/pages/index-123.js"}'
    urls = jh.extract_chunk_urls([txt], BASE, nx)
    assert "https://t.example.com/_next/static/chunks/pages/index-123.js" in urls


def test_generic_asset_ref_fallback():
    # 即使 bundler=None,通用引用扫描也应捞到明显的 js 引用
    txt = 'loadScript("/app/module-x.js")'
    urls = jh.extract_chunk_urls([txt], BASE, None)
    assert any(u.endswith("/app/module-x.js") for u in urls)


# ---------------------------------------------------------- sourcemap 还原
def test_find_sourcemap_url():
    js = "console.log(1)\n//# sourceMappingURL=app.js.map"
    sm = jh._find_sourcemap_url(js, "https://t.example.com/static/js/app.js")
    assert sm == "https://t.example.com/static/js/app.js.map"


def test_find_sourcemap_url_data_uri_ignored():
    js = "x\n//# sourceMappingURL=data:application/json;base64,ey--"
    assert jh._find_sourcemap_url(js, "https://t.example.com/a.js") is None


def test_recover_sourcemap():
    import json
    m = json.dumps({"sourcesContent": ["const API='/api/v1/users'", None, "export default 1"]})
    code, n = jh.recover_sourcemap(m)
    assert n == 2
    assert "/api/v1/users" in code


def test_recover_sourcemap_bad_json():
    code, n = jh.recover_sourcemap("not-json")
    assert code == "" and n == 0


# ---------------------------------------------------------- CRLF 切头(修 bug)
def test_split_body_crlf():
    raw = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar body=1;"
    assert jh._split_body(raw) == "var body=1;"


def test_split_body_lf():
    raw = "HTTP 200\nContent-Type: x\n\nvar body=1;"
    assert jh._split_body(raw) == "var body=1;"


# ---------------------------------------------------------- 密钥可回溯呈现
def test_secret_has_traceable_fields():
    js = ('line1\n'
          'var x=1;\n'
          'const APP_SECRET = "s3cr3t_value_here_long";\n')
    ext = jh._extract_from_js(js)
    assert ext["secrets"], "应挖到 APP_SECRET"
    s = ext["secrets"][0]
    assert s["name"].upper() == "APP_SECRET"
    assert s["type"] == "app_secret"          # 分类
    assert s["line"] == 3                       # 行号(1-based)
    assert "APP_SECRET" in s["context"]         # 原文上下文


def test_secret_classification():
    assert jh._classify_secret("", "LTAI5txxxxxxxxxxxxxx") == "aliyun_ak"
    assert jh._classify_secret("", "AKIAIOSFODNN7EXAMPLE") == "aws_ak"
    assert jh._classify_secret("", "eyJhbGciOi.eyJzdWIi.sig") == "jwt"
    assert jh._classify_secret("WECHAT_APPID", "wxabc") == "wechat"
    assert jh._classify_secret("API_KEY", "abc") == "api_key"
    assert jh._classify_secret("RANDOM", "abc") == "generic"



def test_minimal_parse_bundlers_matches_pyyaml():
    with open(jh._BUNDLERS_YAML, encoding="utf-8") as f:
        text = f.read()
    import yaml
    expected = yaml.safe_load(text)["bundlers"]
    got = jh._minimal_parse_bundlers(text)
    assert [b["id"] for b in got] == [b["id"] for b in expected]
    for g, e in zip(got, expected):
        assert g["chunk_rule"] == e["chunk_rule"]
        assert set(g["detect"]) == set(e["detect"])
