#!/usr/bin/env python3
"""
PESop engine · js_browser —— L2 浏览器增强后端(可选,可插拔)

职责:用 headless 浏览器真实加载页面,捕获运行时实际请求到的所有 *.js URL,
补静态分包抓不到的动态 chunk(运行时计算 chunk 名 / SPA 懒加载路由)。

边界(重要):本模块只负责【发现 JS 的 URL】,不负责【下载取证】。
发现的 URL 交回 js_harvester 用 http_client 下载存证,保证"发包必存证"铁律
不被浏览器绕过。

可选性:主干用 try:import js_browser 调用;本模块探测环境里可用的浏览器方案
(playwright > chromium/chrome --headless),都不可用则 capture 返回
{"available": False},主干据此降级为纯静态并标注。

探测顺序:
  1. playwright(python 包 + 已装浏览器)——最稳,能监听网络请求
  2. chromium/google-chrome --headless --dump-dom——兜底:只能拿渲染后 DOM 里的 <script>,
     拿不到网络层的动态请求(能力弱于 playwright,但零 python 依赖)
"""

import json
import re
import shutil
import subprocess
from urllib.parse import urljoin, urlparse


def _try_playwright(target, timeout):
    """用 playwright 监听网络,返回加载过程中请求到的所有 js URL。"""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    js_urls = set()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("response", lambda resp: (
                js_urls.add(resp.url)
                if resp.url.split("?")[0].endswith(".js") else None))
            page.goto(target, wait_until="networkidle", timeout=timeout * 1000)
            # 触发可能的懒加载:滚动到底 + 等一小会(v0.1 被动为主)
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(1500)
            except Exception:
                pass
            browser.close()
        return sorted(js_urls)
    except Exception:
        return None


def _try_headless_chrome(target, timeout):
    """兜底:chromium/chrome --headless --dump-dom,只能拿渲染后 DOM 的 <script src>。"""
    exe = (shutil.which("chromium") or shutil.which("chromium-browser")
           or shutil.which("google-chrome") or shutil.which("chrome"))
    if not exe:
        return None
    try:
        out = subprocess.run(
            [exe, "--headless=new", "--no-sandbox", "--disable-gpu",
             "--dump-dom", "--virtual-time-budget=8000", target],
            capture_output=True, text=True, timeout=timeout)
        dom = out.stdout or ""
    except Exception:
        return None
    base = target
    urls = set()
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', dom, re.I):
        src = m.group(1)
        urls.add(src if src.startswith("http") else urljoin(base, src))
    # DOM 里出现的 .js 引用也捞
    for m in re.finditer(r'["\'\(]([\w./\-]+\.js)["\'\)]', dom):
        ref = m.group(1)
        if ref.startswith("http"):
            if urlparse(ref).hostname == urlparse(base).hostname:
                urls.add(ref)
        else:
            urls.add(urljoin(base, ref))
    return sorted(urls) if urls else None


def capture(target, timeout=30):
    """探测可用浏览器方案并捕获动态 JS URL。
    返回 {"available": bool, "engine": str, "js_urls": [...]}。
    """
    tgt = target if target.startswith("http") else "https://" + target

    pw = _try_playwright(tgt, timeout)
    if pw is not None:
        return {"available": True, "engine": "playwright", "js_urls": pw}

    ch = _try_headless_chrome(tgt, timeout)
    if ch is not None:
        return {"available": True, "engine": "headless-chrome(dump-dom)", "js_urls": ch}

    return {"available": False, "engine": None, "js_urls": [],
            "note": "未探测到可用浏览器(playwright/chromium),已降级纯静态"}


def main():
    import argparse
    ap = argparse.ArgumentParser(description="PESop 浏览器增强:捕获动态 JS URL(只发现不取证)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()
    print(json.dumps(capture(args.target, args.timeout), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
