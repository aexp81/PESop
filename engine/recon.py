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
# 匹配:纯读 fingerprints.yaml 每条指纹的 match 字段
# --------------------------------------------------------------------------
# recon 不硬编码关键词。每条指纹自带 match:[token,...],recon 只读它;
# reflow 回灌新指纹(带 match)后 recon 立即能识别。


def _fp_match_tokens(fp):
    """取一条指纹的匹配 token 列表:优先 match 字段;缺失则从 signals 抠引号内容兜底。"""
    tokens = fp.get("match")
    if tokens:
        return [str(t).lower() for t in tokens]
    # 兜底:老指纹没写 match 时,从 signals 的引号/反引号内容抠 token
    toks = []
    for sig in fp.get("signals", []):
        for m in re.findall(r'"([^"]+)"|`([^`]+)`', sig):
            tok = (m[0] or m[1]).lower()
            if tok and len(tok) >= 3:
                toks.append(tok)
    return toks


def match_fingerprints(features, fingerprints):
    """
    返回命中列表:[{id, identity, tag, confidence, playbook, matched_on, evidence_id}]
    纯读每条指纹的 match 字段做子串匹配(命中任一 token 即算命中)。
    """
    hits = []
    all_text = " || ".join(f[3] for f in features)
    for fp in fingerprints:
        fid = fp.get("id")
        matched_kw = None
        for kw in _fp_match_tokens(fp):
            if kw in all_text:
                matched_kw = kw
                break
        if matched_kw:
            # 找出是哪个探测路径命中的,附上其证据
            ev = next((f[1] for f in features if matched_kw in f[3]), features[0][1] if features else None)
            hits.append({
                "id": fid,
                "identity": fp.get("identity"),
                "tag": fp.get("tag"),
                "layer": fp.get("layer"),
                "confidence": fp.get("confidence"),
                "playbook": fp.get("playbook"),
                "matched_on": matched_kw,
                "evidence_id": ev,
            })
    return hits


def recon(target, probe_paths=None, write_intel=True):
    probe_paths = probe_paths or ["/", "/api", "/actuator", "/login", "/.well-known/openid-configuration"]
    fingerprints = load_fingerprints()
    features, evidence_ids = _collect_features(target, probe_paths)
    hits = match_fingerprints(features, fingerprints)

    # 按 tag(打法域)分诊:每个域收集各自命中的指纹和 playbook
    TAGS = ["infra", "framework", "application"]
    dispatch = {t: [h for h in hits if h.get("tag") == t] for t in TAGS}
    untagged = [h for h in hits if h.get("tag") not in TAGS]

    # 写入情报库(维度二:供后续所有域共享)
    if write_intel:
        try:
            import intel as _intel
            for h in hits:
                _intel.add(target, "fingerprints", {
                    "id": h["id"], "identity": h["identity"], "tag": h.get("tag"),
                    "confidence": h.get("confidence"), "evidence_id": h.get("evidence_id"),
                }, dedup_key="id")
        except Exception as e:
            untagged.append({"intel_write_error": str(e)})

    # 生成分域行动建议(反射档 vs 建模档)
    domain_actions = {}
    missing_playbooks = []
    for t in TAGS:
        if not dispatch[t]:
            continue
        pbs = sorted({h["playbook"] for h in dispatch[t] if h.get("playbook")})
        # 校验每个 playbook 文件是否真实存在(治指纹→playbook 悬空引用)
        for pb in pbs:
            if not os.path.exists(os.path.join(_PROJECT_ROOT, "knowledge", pb)):
                missing_playbooks.append(pb)
        if t in ("infra", "framework"):
            mode = "反射档:指纹已定,直接展开确定性攻击链/未授权,不必逐条写Q1-Q5"
        else:
            mode = "建模档:必须先写Q1-Q5+开发者共情,再发散测试"
        domain_actions[t] = {
            "hits": [h["id"] for h in dispatch[t]],
            "playbooks": pbs,
            "mode": mode,
        }

    if domain_actions:
        order = [t for t in ["framework", "infra", "application"] if t in domain_actions]
        next_action = (f"按域调度(优先级 framework/infra 反射档先打 → application 建模档): "
                       f"{' , '.join(order)}")
    elif hits:
        next_action = (f"命中指纹但无 tag/playbook: {[h['id'] for h in hits]} "
                       f"-> 走 Q1-Q5 手工建模并补建知识")
    else:
        next_action = "无已知指纹命中 -> 走 Q1-Q5 手工建模,并把新指纹信号收尾 reflow 回灌"

    if missing_playbooks:
        next_action += (f" | ⚠ 指纹指向的 playbook 文件缺失:{sorted(set(missing_playbooks))} "
                        f"-> 该指纹缺打法,先按建模档手工推进,并 reflow check 补建 playbook")

    return {
        "target": target,
        "probed_paths": probe_paths,
        "evidence_ids": evidence_ids,
        "status_by_path": {f[0]: f[2] for f in features},
        "fingerprint_hits": hits,
        "dispatch_by_tag": domain_actions,
        "missing_playbooks": sorted(set(missing_playbooks)),
        "untagged_hits": untagged,
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
