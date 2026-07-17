#!/usr/bin/env python3
"""
PESop engine · recon —— 指纹识别 + 攻击面切换触发

对应 AGENT.md SOP loop 第 1-2 步的自动化:
  发探测包 -> 抓响应头/错误体/cookie/行为特征 -> 匹配 knowledge/fingerprints.yaml
  -> 输出"这是什么(产品/框架/网关身份)" + "该加载哪个 playbook"

核心认知(L3 竹云IAM 教训):识别产品身份 = 攻击面切换触发器,不是记录字段。
所以本模块不止"报告识别到什么",还直接告诉 AI 下一步该读哪个 playbook。

发包全部走 http_client(自动存证),所以每个指纹判定都有真实证据 evidence_id 支撑,
不是凭空断言(治 F2)。

依赖:优先 pyyaml,无则降级内置极简解析器,保证零第三方依赖也能跑。

CLI:
  python engine/recon.py --target https://t.com
  python engine/recon.py --target https://t.com --probe-paths /,/api,/actuator
"""

import argparse
import json
import os
import re
import sys

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
FINGERPRINTS = os.path.join(_PROJECT_ROOT, "knowledge", "fingerprints.yaml")

# 复用 http_client 发包存证
sys.path.insert(0, _ENGINE_DIR)
import http_client  # noqa: E402


# --------------------------------------------------------------------------
# 载入指纹库(pyyaml 优先,无则内置极简解析)
# --------------------------------------------------------------------------
def load_fingerprints():
    with open(FINGERPRINTS, encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml
        data = yaml.safe_load(text)
        return data.get("fingerprints", [])
    except ImportError:
        return _minimal_parse_fingerprints(text)


def _minimal_parse_fingerprints(text):
    """
    无 pyyaml 时的兜底解析器,只认 fingerprints.yaml 的固定结构:
      fingerprints:
        - id: xxx
          layer: xxx
          signals:
            - "..."
          identity: "..."
          confidence: xxx
          playbook: xxx
    """
    fps = []
    cur = None
    in_signals = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if re.match(r"^\s*-\s+id:\s*", line):
            if cur:
                fps.append(cur)
            cur = {"signals": []}
            cur["id"] = line.split("id:", 1)[1].strip()
            in_signals = False
        elif cur is not None:
            m = re.match(r"^\s+(\w+):\s*(.*)$", line)
            if re.match(r"^\s+signals:\s*$", line):
                in_signals = True
            elif re.match(r"^\s+-\s+", line) and in_signals:
                val = line.split("-", 1)[1].strip().strip('"').strip("'")
                cur["signals"].append(val)
            elif m:
                k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
                if k != "signals":
                    cur[k] = None if v == "null" else v
                    in_signals = False
    if cur:
        fps.append(cur)
    return fps


# --------------------------------------------------------------------------
# 从一批探测响应里提取可比对的特征文本
# --------------------------------------------------------------------------
def _collect_features(target, probe_paths):
    """对每个探测路径发包,汇总 [状态行 + 响应头 + 响应体片段 + set-cookie] 供匹配。"""
    features = []       # [(path, evidence_id, feature_text_lower)]
    evidence_ids = []
    for p in probe_paths:
        r = http_client.send(target=target, method="GET", path=p,
                             note=f"recon探测:{p}")
        evidence_ids.append(r["evidence_id"])
        # 从落盘证据里取完整 raw_response 做匹配(preview 可能截断)
        ev_file = r["evidence_path"]
        raw = ""
        try:
            with open(ev_file, encoding="utf-8") as f:
                raw = json.load(f)["raw_response"]
        except Exception:
            raw = r.get("raw_response_preview", "")
        features.append((p, r["evidence_id"], r.get("status_code"), raw.lower()))
    return features, evidence_ids


# --------------------------------------------------------------------------
# 匹配:signal 里的关键词是否出现在任一探测特征里
# --------------------------------------------------------------------------
# 从 signal 自然语言里抽出真正要匹配的关键 token(去掉"响应头""含"等描述词)
_SIGNAL_KEYWORDS = {
    "istio-envoy": ["istio-envoy"],
    "kong": ["x-kong", "server: kong"],
    "aliyun-waf": ["acw_tc", "acw_"],
    "cloudflare": ["cloudflare", "cf-ray"],
    "spring-boot": ["whitelabel error page", '"timestamp"', "x-application-context"],
    "spring-security": ["www-authenticate", "jsessionid"],
    "shiro": ["remembeme", "rememberme", "deleteme"],
    "asp-net": ["x-aspnet-version", "x-aspnetmvc-version", "asp.net"],
    "oauth-oidc": ["/oauth", "/sso", "openid-configuration", ".well-known"],
    "zhuyun-iam": ["bamboocloud", "竹云"],
}


def match_fingerprints(features, fingerprints):
    """
    返回命中列表:[{id, identity, confidence, playbook, matched_on, evidence_id}]
    匹配用 _SIGNAL_KEYWORDS(比自然语言 signal 更可靠);
    未在表里的新指纹条目,退回用其 signals 文本里的引号内容做子串匹配。
    """
    hits = []
    all_text = " || ".join(f[3] for f in features)
    for fp in fingerprints:
        fid = fp.get("id")
        keywords = _SIGNAL_KEYWORDS.get(fid)
        matched_kw = None
        if keywords:
            for kw in keywords:
                if kw.lower() in all_text:
                    matched_kw = kw
                    break
        else:
            # 新增指纹兜底:用 signals 里出现的明显 token
            for sig in fp.get("signals", []):
                toks = re.findall(r'"([^"]+)"|`([^`]+)`', sig)
                for t in toks:
                    tok = (t[0] or t[1]).lower()
                    if tok and len(tok) >= 3 and tok in all_text:
                        matched_kw = tok
                        break
                if matched_kw:
                    break
        if matched_kw:
            # 找出是哪个探测路径命中的,附上其证据
            ev = next((f[1] for f in features if matched_kw in f[3]), features[0][1] if features else None)
            hits.append({
                "id": fid,
                "identity": fp.get("identity"),
                "layer": fp.get("layer"),
                "confidence": fp.get("confidence"),
                "playbook": fp.get("playbook"),
                "matched_on": matched_kw,
                "evidence_id": ev,
            })
    return hits


def recon(target, probe_paths=None):
    probe_paths = probe_paths or ["/", "/api", "/actuator", "/login", "/.well-known/openid-configuration"]
    fingerprints = load_fingerprints()
    features, evidence_ids = _collect_features(target, probe_paths)
    hits = match_fingerprints(features, fingerprints)

    playbooks_to_load = sorted({h["playbook"] for h in hits if h.get("playbook")})
    if playbooks_to_load:
        next_action = f"加载 playbook: {', '.join(playbooks_to_load)}"
    elif hits:
        ids = ", ".join(h["id"] for h in hits)
        next_action = (f"命中指纹 [{ids}] 但暂无对应 playbook -> 走 Q1-Q5 手工建模,"
                       f"并考虑为其补建 knowledge/playbooks/")
    else:
        next_action = "无已知指纹命中 -> 走 Q1-Q5 手工建模,并把新指纹信号收尾回灌 fingerprints.yaml"
    return {
        "target": target,
        "probed_paths": probe_paths,
        "evidence_ids": evidence_ids,
        "status_by_path": {f[0]: f[2] for f in features},
        "fingerprint_hits": hits,
        "playbooks_to_load": playbooks_to_load,
        "next_action": next_action,
    }


def main():
    ap = argparse.ArgumentParser(description="PESop 指纹识别+攻击面切换触发")
    ap.add_argument("--target", required=True)
    ap.add_argument("--probe-paths", default=None,
                    help="逗号分隔的探测路径,默认 /,/api,/actuator,/login,openid-configuration")
    args = ap.parse_args()
    paths = [p.strip() for p in args.probe_paths.split(",")] if args.probe_paths else None
    print(json.dumps(recon(args.target, paths), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
