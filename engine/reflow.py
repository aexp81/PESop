#!/usr/bin/env python3
"""
PESop engine · reflow —— 自动回灌(复利飞轮的动力)

作用:让 AI 收尾时把本次测试学到的可复用知识,用命令 append 进 knowledge/,
而不是靠人手写。这是"越用越强"的关键——沉淀动作被机器化、格式被统一、
只增不删被强制。

回灌两类知识:
  1. 新指纹      -> append 进 knowledge/fingerprints.yaml
  2. 新 check    -> append 进 knowledge/domains/<tag>/<playbook>.yaml 的 checks(不存在则新建)

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
DOMAINS_DIR = os.path.join(KNOW_DIR, "domains")          # 三域 playbook 根
WAF_FP = os.path.join(KNOW_DIR, "waf", "fingerprints.yaml")
WAF_BYPASS_DIR = os.path.join(KNOW_DIR, "waf", "bypass")
PAYLOADS_DIR = os.path.join(KNOW_DIR, "payloads")
VALID_TAGS = ["infra", "framework", "application"]
RUNS_ROOT = os.path.join(_PROJECT_ROOT, "runs")


def _require_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        print("[错误] reflow 需要 pyyaml(结构化读写 yaml,避免破坏格式)。"
              "请 pip install pyyaml 后重试。", file=sys.stderr)
        sys.exit(2)


def add_fingerprint(fid, tag, signals, identity, confidence, playbook=None, note="", match=None):
    yaml = _require_yaml()
    if tag not in VALID_TAGS:
        return {"ok": False, "reason": f"tag 必须是 {VALID_TAGS} 之一,收到 '{tag}'"}
    if not match:
        return {"ok": False, "reason": "必须提供 --match(结构化匹配token),否则 recon 无法识别该指纹"}
    with open(FINGERPRINTS, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    fps = data.setdefault("fingerprints", [])
    if any(x.get("id") == fid for x in fps):
        return {"ok": False, "reason": f"指纹 id '{fid}' 已存在,跳过(只增不删,不覆盖)"}
    # playbook 未指定时按 tag 自动生成域内路径
    if not playbook:
        playbook = f"domains/{tag}/{fid}.yaml"
    entry = {
        "id": fid, "tag": tag, "signals": signals,
        "match": [str(m).lower() for m in match],
        "identity": identity, "confidence": confidence, "playbook": playbook,
    }
    if note:
        entry["note"] = note
    fps.append(entry)
    with open(FINGERPRINTS, "w", encoding="utf-8") as f:
        f.write("# PESop 指纹库 —— 信号->身份->tag(打法域)+playbook（自动回灌维护,只增不删）\n")
        f.write("# match 字段是 recon 的匹配依据,回灌必带\n\n")
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return {"ok": True, "added": entry}


def add_check(tag, playbook_id, check_id, why, how, signal, escalate="", endpoints=None):
    yaml = _require_yaml()
    if tag not in VALID_TAGS:
        return {"ok": False, "reason": f"tag 必须是 {VALID_TAGS} 之一"}
    domain_dir = os.path.join(DOMAINS_DIR, tag)
    os.makedirs(domain_dir, exist_ok=True)
    path = os.path.join(domain_dir, f"{playbook_id}.yaml")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        data = {"playbook": playbook_id, "identity": playbook_id, "checks": []}
    checks = data.setdefault("checks", [])
    if any(c.get("id") == check_id for c in checks):
        return {"ok": False, "reason": f"check id '{check_id}' 在 {tag}/{playbook_id} 已存在,跳过"}
    entry = {"id": check_id, "why": why, "how": how, "signal": signal}
    if endpoints:
        entry["endpoints"] = endpoints
    if escalate:
        entry["escalate"] = escalate
    newfile = not os.path.exists(path)
    checks.append(entry)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Playbook: {data.get('identity', playbook_id)} (tag={tag})（自动回灌维护,只增不删）\n\n")
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return {"ok": True, "added": entry, "new_playbook": newfile, "path": path}


def add_waf(waf_id, signals=None, bypass_technique=None):
    """回灌 WAF 指纹 和/或 绕过手法。"""
    yaml = _require_yaml()
    result = {"ok": True, "waf": waf_id, "actions": []}
    # 1. 指纹
    if signals:
        with open(WAF_FP, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {"wafs": []}
        wafs = data.setdefault("wafs", [])
        if any(w.get("id") == waf_id for w in wafs):
            result["actions"].append(f"WAF指纹 '{waf_id}' 已存在,跳过")
        else:
            wafs.append({"id": waf_id, "signals": signals, "bypass": waf_id})
            with open(WAF_FP, "w", encoding="utf-8") as f:
                f.write("# WAF 识别指纹库（自动回灌维护,只增不删）\n\n")
                yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
            result["actions"].append(f"新增 WAF 指纹 '{waf_id}'")
    # 2. 绕过手法
    if bypass_technique:
        os.makedirs(WAF_BYPASS_DIR, exist_ok=True)
        bpath = os.path.join(WAF_BYPASS_DIR, f"{waf_id}.yaml")
        if os.path.exists(bpath):
            bdata = yaml.safe_load(open(bpath, encoding="utf-8")) or {}
        else:
            bdata = {"waf": waf_id, "techniques": []}
        techs = bdata.setdefault("techniques", [])
        tid = bypass_technique.get("id")
        if any(t.get("id") == tid for t in techs):
            result["actions"].append(f"绕过手法 '{tid}' 已存在,跳过")
        else:
            techs.append(bypass_technique)
            with open(bpath, "w", encoding="utf-8") as f:
                f.write(f"# WAF 绕过手法: {waf_id}（自动回灌维护,只增不删）\n\n")
                yaml.safe_dump(bdata, f, allow_unicode=True, sort_keys=False)
            result["actions"].append(f"新增绕过手法 '{tid}'")
    if not result["actions"]:
        result = {"ok": False, "reason": "需提供 --signal 或 --bypass-id/--bypass-how"}
    return result


def add_payload(group, payload, why=""):
    """回灌绕过 payload 到 knowledge/payloads/auth-bypass.yaml 的指定组。"""
    yaml = _require_yaml()
    path = os.path.join(PAYLOADS_DIR, "auth-bypass.yaml")
    if os.path.exists(path):
        data = yaml.safe_load(open(path, encoding="utf-8")) or {}
    else:
        data = {"by_framework": {}}
    bf = data.setdefault("by_framework", {})
    grp = bf.setdefault(group, {"why": why, "payloads": []})
    if isinstance(grp, dict):
        pls = grp.setdefault("payloads", [])
        if payload in pls:
            return {"ok": True, "skipped": "payload 已存在,去重", "group": group}
        pls.append(payload)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# 鉴权绕过 payload 库（自动回灌维护,只增不删）\n\n")
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
    return {"ok": True, "added": payload, "group": group}


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


def verify():
    """知识一致性体检:扫描 fingerprints.yaml 所有 playbook 引用,列出悬空(文件不存在)的。
    收尾/CI 用,主动发现"指纹指向的 playbook 文件不存在"的缝(playbook=null 视为有意留空,不算悬空)。
    读 fingerprints 复用 recon 的 load_fingerprints(pyyaml 优先,无则内置兜底),故本命令不强依赖 pyyaml。
    """
    sys.path.insert(0, _ENGINE_DIR)
    import recon as _recon
    fps = _recon.load_fingerprints()
    dangling = []
    ok = []
    for fp in fps:
        pb = fp.get("playbook")
        if not pb or pb == "null":
            continue   # 有意留空(如纯 infra 端口/尚无 playbook),不算悬空
        exists = os.path.exists(os.path.join(KNOW_DIR, pb))
        (ok if exists else dangling).append({"id": fp.get("id"), "playbook": pb})
    return {
        "checked": len([f for f in fps if f.get("playbook") and f.get("playbook") != "null"]),
        "ok_count": len(ok),
        "dangling": dangling,
        "verdict": ("全部指纹的 playbook 引用零悬空" if not dangling
                    else f"发现 {len(dangling)} 个悬空引用 -> reflow check 补建对应 playbook"),
    }


def main():
    ap = argparse.ArgumentParser(description="PESop 分层自动回灌(只增不删)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    fp = sub.add_parser("fingerprint", help="回灌新指纹(带 tag 分域 + match 匹配token)")
    fp.add_argument("--id", required=True)
    fp.add_argument("--tag", required=True, choices=VALID_TAGS, help="打法域:infra/framework/application")
    fp.add_argument("--signal", action="append", default=[], required=True, help="人读判据,可多次")
    fp.add_argument("--match", action="append", default=[], required=True, help="recon匹配token(小写子串),可多次")
    fp.add_argument("--identity", required=True)
    fp.add_argument("--confidence", default="medium", choices=["high", "medium", "low"])
    fp.add_argument("--playbook", default=None, help="不填按 tag 自动生成 domains/<tag>/<id>.yaml")
    fp.add_argument("--note", default="")

    ck = sub.add_parser("check", help="回灌新 check 到 domains/<tag>/ 下 playbook")
    ck.add_argument("--tag", required=True, choices=VALID_TAGS)
    ck.add_argument("--playbook", required=True, help="playbook 文件名(不含.yaml)")
    ck.add_argument("--check-id", required=True)
    ck.add_argument("--why", required=True)
    ck.add_argument("--how", required=True)
    ck.add_argument("--signal", required=True)
    ck.add_argument("--escalate", default="")
    ck.add_argument("--endpoint", action="append", default=[], help="可多次")

    wf = sub.add_parser("waf", help="回灌 WAF 指纹和/或绕过手法")
    wf.add_argument("--id", required=True, help="WAF id")
    wf.add_argument("--signal", action="append", default=[], help="WAF识别信号,可多次")
    wf.add_argument("--bypass-id", default=None, help="绕过手法 id")
    wf.add_argument("--bypass-why", default="")
    wf.add_argument("--bypass-how", default="")

    pl = sub.add_parser("payload", help="回灌绕过 payload 到指定组")
    pl.add_argument("--group", required=True, help="组名(如 shiro/spring-security/jwt/generic)")
    pl.add_argument("--payload", required=True)
    pl.add_argument("--why", default="")

    sg = sub.add_parser("suggest", help="从 run 产物提示可回灌线索")
    sg.add_argument("--target", required=True)

    sub.add_parser("verify", help="知识一致性体检:检查指纹→playbook 引用有无悬空")

    args = ap.parse_args()
    if args.cmd == "fingerprint":
        r = add_fingerprint(args.id, args.tag, args.signal, args.identity,
                            args.confidence, args.playbook, args.note, args.match)
    elif args.cmd == "check":
        r = add_check(args.tag, args.playbook, args.check_id, args.why, args.how,
                      args.signal, args.escalate, args.endpoint or None)
    elif args.cmd == "waf":
        bypass = None
        if args.bypass_id:
            bypass = {"id": args.bypass_id, "why": args.bypass_why, "how": args.bypass_how}
        r = add_waf(args.id, args.signal or None, bypass)
    elif args.cmd == "payload":
        r = add_payload(args.group, args.payload, args.why)
    elif args.cmd == "verify":
        r = verify()
    else:
        r = suggest(args.target)
    print(json.dumps(r, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
