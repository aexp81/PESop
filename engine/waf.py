#!/usr/bin/env python3
"""
PESop engine · waf —— WAF 横切调节器（架构维度三）

WAF 不是攻击域,是"调节器":
  1. identify: 发探测包 → 匹配 knowledge/waf/fingerprints.yaml → 判有无WAF+什么WAF
     → 写入 intel(waf 字段),供所有域感知。
  2. advise:   给出该 WAF 的绕过手法清单(knowledge/waf/bypass/<id>.yaml),
     供 AI 在发 payload 前参考应用。

设计取舍:waf.py 不做"黑盒自动改写 payload"——WAF 绕过是策略性的(换源站IP/编码/
换方法/分块),需要结合具体 payload 和场景由 AI 判断应用,固定自动变换反而僵化、
命中率低。所以这里给"手法清单 + 判据",执行由 AI 做(符合'给判据不给死套路'原则)。
无 WAF 时 advise 返回空,AI 直接上常规 payload。

依赖:pyyaml 优先,无则内置极简解析;发包走 http_client。

CLI:
  python engine/waf.py identify --target https://t.com
  python engine/waf.py advise --waf cloudflare
"""

import argparse
import json
import os
import sys

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
WAF_FP = os.path.join(_PROJECT_ROOT, "knowledge", "waf", "fingerprints.yaml")
WAF_BYPASS_DIR = os.path.join(_PROJECT_ROOT, "knowledge", "waf", "bypass")

sys.path.insert(0, _ENGINE_DIR)
import http_client  # noqa: E402


def _load_yaml(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        return None  # 极简场景下 advise 仍可用文本兜底,identify 用关键词表


# WAF 识别关键词(比自然语言 signal 更可靠,与 recon 同思路)
_WAF_KEYWORDS = {
    "cloudflare": ["cf-ray", "server: cloudflare", "__cf_bm", "cf-cache-status"],
    "aliyun": ["acw_tc", "acw_sc__"],
    "modsecurity": ["mod_security", "not acceptable", "noyb"],
    "aws-waf": ["x-amzn-requestid"],
    "f5-bigip": ["bigipserver", "x-waf-event"],
}


def identify(target, write_intel=True):
    """发探测包识别 WAF,写入 intel。返回 {present, id, evidence_id}。"""
    # 发一个正常包 + 一个带明显攻击特征的包(更易触发 WAF 拦截页)
    r_normal = http_client.send(target=target, method="GET", path="/", note="waf识别:正常包")
    r_probe = http_client.send(target=target, method="GET",
                               path="/?x=<script>alert(1)</script>", note="waf识别:探测包")
    evidence_ids = [r_normal["evidence_id"], r_probe["evidence_id"]]

    # 汇总两个响应的原文做匹配
    texts = []
    for r in (r_normal, r_probe):
        try:
            with open(r["evidence_path"], encoding="utf-8") as f:
                texts.append(json.load(f)["raw_response"].lower())
        except Exception:
            texts.append(r.get("raw_response_preview", "").lower())
    blob = " || ".join(texts)

    hit_id = None
    matched = None
    for wid, kws in _WAF_KEYWORDS.items():
        for kw in kws:
            if kw.lower() in blob:
                hit_id, matched = wid, kw
                break
        if hit_id:
            break

    present = hit_id is not None
    result = {
        "target": target,
        "waf_present": present,
        "waf_id": hit_id,
        "matched_on": matched,
        "evidence_ids": evidence_ids,
        "next": (f"有WAF({hit_id}) -> 发payload前 advise 拿绕过手法" if present
                 else "未识别到WAF -> 各域可直接上常规payload(仍留意隐性拦截)"),
    }
    if write_intel:
        try:
            import intel as _intel
            _intel.set_waf(target, present, hit_id, evidence_ids[1])
        except Exception as e:
            result["intel_write_error"] = str(e)
    return result


def advise(waf_id):
    """返回该 WAF 的绕过手法清单(供 AI 发 payload 前参考)。"""
    if not waf_id or waf_id == "null":
        return {"waf": None, "advice": "无 WAF,直接上常规 payload"}
    path = os.path.join(WAF_BYPASS_DIR, f"{waf_id}.yaml")
    if not os.path.exists(path):
        return {"waf": waf_id,
                "advice": f"暂无 {waf_id} 专属绕过手法,可用通用手法(源站IP直连/编码变体/换CT/换方法/分块),并 reflow 回灌新手法"}
    data = _load_yaml(path)
    if data is None:
        # 无 pyyaml,返回原文让 AI 读
        return {"waf": waf_id, "advice_raw": open(path, encoding="utf-8").read()}
    return {
        "waf": waf_id,
        "techniques": [{"id": t.get("id"), "why": t.get("why"), "how": t.get("how")}
                       for t in data.get("techniques", [])],
        "note": data.get("general_note", ""),
    }


def main():
    ap = argparse.ArgumentParser(description="PESop WAF 横切调节器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("identify"); i.add_argument("--target", required=True)
    a = sub.add_parser("advise"); a.add_argument("--waf", required=True)

    args = ap.parse_args()
    if args.cmd == "identify":
        print(json.dumps(identify(args.target), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(advise(args.waf), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
