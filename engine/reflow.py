#!/usr/bin/env python3
"""
PESop engine · reflow —— 自动回灌(复利飞轮的动力)

作用:让 AI 收尾时把本次测试学到的可复用知识,用命令 append 进 knowledge/,
而不是靠人手写。这是"越用越强"的关键——沉淀动作被机器化、格式被统一、
只增不删被强制。

回灌两类知识:
  1. 新指纹      -> append 进 knowledge/fingerprints.yaml
  2. 新 check    -> append 进 knowledge/playbooks/<id>.yaml 的 checks(不存在则新建 playbook)

原则(对应 AGENT.md 第 5 节):
  - 只回灌"可复用的判据/手法",不回灌"目标专属数据"(那留在 runs/)。
  - 只增不删:reflow 只做 append,绝不改写/删除已有条目。
  - 去重:同 id 已存在则跳过并提示,不产生重复。

依赖:pyyaml(回灌需结构化读写 yaml;若环境无 pyyaml,reflow 会明确报错要求安装,
     因为纯文本 append yaml 易破坏格式,这里不做降级)。

CLI:
  # 回灌一个新指纹
  python engine/reflow.py fingerprint \
      --id gitlab --layer framework \
      --signal "响应头 x-gitlab-*" --signal "/users/sign_in 登录页" \
      --identity "GitLab" --confidence high --playbook gitlab

  # 回灌一个新 check 到已有/新 playbook
  python engine/reflow.py check --playbook spring-boot \
      --check-id h2-console --why "H2 Console 常被忘记关" \
      --how "GET /h2-console/" --signal "200 返回 H2 登录界面 -> 可能 RCE"

  # 从某次 run 的 js_assets.json 里把新发现的内部域名提示为待回灌(辅助)
  python engine/reflow.py suggest --target https://t.com
"""

import argparse
import json
import os
import sys

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
KNOW_DIR = os.path.join(_PROJECT_ROOT, "knowledge")
FINGERPRINTS = os.path.join(KNOW_DIR, "fingerprints.yaml")
PLAYBOOK_DIR = os.path.join(KNOW_DIR, "playbooks")
RUNS_ROOT = os.path.join(_PROJECT_ROOT, "runs")


def _require_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        print("[错误] reflow 需要 pyyaml(结构化读写 yaml,避免破坏格式)。"
              "请 pip install pyyaml 后重试。", file=sys.stderr)
        sys.exit(2)


def add_fingerprint(fid, layer, signals, identity, confidence, playbook, note=""):
    yaml = _require_yaml()
    with open(FINGERPRINTS, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    fps = data.setdefault("fingerprints", [])
    if any(x.get("id") == fid for x in fps):
        return {"ok": False, "reason": f"指纹 id '{fid}' 已存在,跳过(只增不删,不覆盖)"}
    entry = {
        "id": fid, "layer": layer, "signals": signals,
        "identity": identity, "confidence": confidence, "playbook": playbook,
    }
    if note:
        entry["note"] = note
    fps.append(entry)
    with open(FINGERPRINTS, "w", encoding="utf-8") as f:
        f.write("# PESop 指纹库 —— 信号 -> 产品身份 -> 触发的 playbook（自动回灌维护,只增不删）\n\n")
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return {"ok": True, "added": entry}


def add_check(playbook_id, check_id, why, how, signal, escalate="", endpoints=None):
    yaml = _require_yaml()
    path = os.path.join(PLAYBOOK_DIR, f"{playbook_id}.yaml")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        data = {"playbook": playbook_id, "identity": playbook_id, "checks": []}
    checks = data.setdefault("checks", [])
    if any(c.get("id") == check_id for c in checks):
        return {"ok": False, "reason": f"check id '{check_id}' 在 {playbook_id} 已存在,跳过"}
    entry = {"id": check_id, "why": why, "how": how, "signal": signal}
    if endpoints:
        entry["endpoints"] = endpoints
    if escalate:
        entry["escalate"] = escalate
    checks.append(entry)
    newfile = not os.path.exists(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Playbook: {data.get('identity', playbook_id)}（自动回灌维护,只增不删）\n\n")
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return {"ok": True, "added": entry, "new_playbook": newfile, "path": path}


def suggest(target):
    """从某次 run 产物里挑出'可能值得回灌'的线索,只提示不自动写。"""
    from urllib.parse import urlparse
    p = urlparse(target if "://" in target else "http://" + target)
    slug = f"{p.hostname}{('_'+str(p.port)) if p.port else ''}".replace("/", "_")
    tdir = os.path.join(RUNS_ROOT, slug)
    hints = []
    ja = os.path.join(tdir, "js_assets.json")
    if os.path.exists(ja):
        d = json.load(open(ja, encoding="utf-8"))
        if d["aggregate"].get("internal_hosts"):
            hints.append("发现内部域名,考虑是否体现新架构模式(内部域名本身是目标数据,不回灌;但若揭示了新的指纹信号可回灌)")
        if d["aggregate"].get("secrets"):
            hints.append(f"发现 {len(d['aggregate']['secrets'])} 个疑似密钥常量名,若出现新的高信号常量名可回灌进 js_harvester 的 _SECRET_KEY_NAMES")
    if not hints:
        hints.append("未从产物中发现明显可回灌线索;请人工判断本次是否有新指纹/新手法值得沉淀")
    return {"target": target, "reflow_hints": hints}


def main():
    ap = argparse.ArgumentParser(description="PESop 自动回灌(只增不删)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    fp = sub.add_parser("fingerprint", help="回灌新指纹到 fingerprints.yaml")
    fp.add_argument("--id", required=True)
    fp.add_argument("--layer", required=True)
    fp.add_argument("--signal", action="append", default=[], required=True, help="可多次")
    fp.add_argument("--identity", required=True)
    fp.add_argument("--confidence", default="medium", choices=["high", "medium", "low"])
    fp.add_argument("--playbook", default=None)
    fp.add_argument("--note", default="")

    ck = sub.add_parser("check", help="回灌新 check 到 playbook")
    ck.add_argument("--playbook", required=True)
    ck.add_argument("--check-id", required=True)
    ck.add_argument("--why", required=True)
    ck.add_argument("--how", required=True)
    ck.add_argument("--signal", required=True)
    ck.add_argument("--escalate", default="")
    ck.add_argument("--endpoint", action="append", default=[], help="可多次")

    sg = sub.add_parser("suggest", help="从 run 产物提示可回灌线索")
    sg.add_argument("--target", required=True)

    args = ap.parse_args()
    if args.cmd == "fingerprint":
        r = add_fingerprint(args.id, args.layer, args.signal, args.identity,
                            args.confidence, args.playbook, args.note)
    elif args.cmd == "check":
        r = add_check(args.playbook, args.check_id, args.why, args.how,
                      args.signal, args.escalate, args.endpoint or None)
    else:
        r = suggest(args.target)
    print(json.dumps(r, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
