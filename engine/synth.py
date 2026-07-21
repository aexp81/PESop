#!/usr/bin/env python3
"""
PESop engine · synth —— 情报组合装配台（把散落情报撮合成攻击链候选）

解决 TASK-006:情报收集了却各自停在"发现"层,没交叉组合成真实请求。
synth 读 intel(backends/endpoints/headers/secrets/hosts),按 knowledge/combine.yaml 的规则
把它们撮合成【完整请求候选链】(base+prefix+path+建议头/token),追踪每条链"发过没有",
新情报入库时可触发关联提示。

边界(骨架宪法):engine 只做【机械撮合 + 记账 + 提问】——
  - 不发包、不全排列爆炸(只按 combine.yaml 的有意义配对)、不替 AI 决定打哪条。
  - 只摆"装配好的候选链 + 为什么这么配(assembled_from) + 发没发过(consumed)",发不发/怎么改由 AI 定。

落盘: runs/<target>/chains.json

CLI:
  python engine/synth.py build   --target https://t.com   # 装配候选链
  python engine/synth.py pending --target https://t.com   # 看还没打过的链
  python engine/synth.py consume --target https://t.com --id chain-0001 --by "已发,返回401"
  python engine/synth.py relate  --target https://t.com --field secrets --value xxx  # 新情报能组合什么
"""

import argparse
import json
import os
import re
import sys

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
COMBINE_YAML = os.path.join(_PROJECT_ROOT, "knowledge", "combine.yaml")
RUNS_ROOT = os.path.join(_PROJECT_ROOT, "runs")

sys.path.insert(0, _ENGINE_DIR)
import intel as _intel        # noqa: E402

_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_AUTH_HINT = ("auth", "login", "signin", "token", "admin", "user", "account", "oauth", "sso")


def _slug(target):
    from urllib.parse import urlparse
    p = urlparse(target if "://" in target else "http://" + target)
    return f"{p.hostname or 'unknown'}{('_'+str(p.port)) if p.port else ''}".replace("/", "_")


def _chains_path(target):
    d = os.path.join(RUNS_ROOT, _slug(target))
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "chains.json")


def _load_chains(target):
    p = _chains_path(target)
    if not os.path.exists(p):
        return {"target": target, "chains": []}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _save_chains(target, data):
    with open(_chains_path(target), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _load_rules():
    if not os.path.exists(COMBINE_YAML):
        return []
    with open(COMBINE_YAML, encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml
        return (yaml.safe_load(text) or {}).get("combine_rules", [])
    except ImportError:
        return _minimal_parse_rules(text)


def _minimal_parse_rules(text):
    out, cur = [], None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        m_id = re.match(r'^\s*-\s*id:\s*(\S+)', line)
        if m_id:
            if cur:
                out.append(cur)
            cur = {"id": m_id.group(1).strip('"\''), "needs": []}
            continue
        if cur is None:
            continue
        m = re.match(r'^\s+(\w+):\s*(.*)$', line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k == "needs" and v.startswith("["):
            cur["needs"] = [x.strip().strip('"\'') for x in v.strip("[]").split(",") if x.strip()]
        elif k in ("rule", "desc"):
            cur[k] = v.strip('"\'')
    if cur:
        out.append(cur)
    return out


def _full_url(base_obj, path):
    base = base_obj.get("base", "").rstrip("/")
    prefix = (base_obj.get("prefix") or "").rstrip("/")
    p = path if path.startswith("/") else "/" + path
    # 若 path 已含 prefix 则不重复拼
    if prefix and not p.startswith(prefix + "/") and p != prefix:
        p = prefix + p
    return base + p


# --------------------------------------------------------------------------
# 组合算子:每个把 intel 情报撮合成若干 chain(dict)。engine 不发包。
# --------------------------------------------------------------------------
def _op_base_x_path(intel, backends, endpoints, headers, secrets, hosts):
    chains = []
    real_backends = [b for b in backends if not b.get("same_as_frontend")] or backends
    for b in real_backends:
        for ep in endpoints:
            path = ep.get("path") if isinstance(ep, dict) else str(ep)
            if not path:
                continue
            chains.append({
                "method": ep.get("method", "?") if isinstance(ep, dict) else "?",
                "url": _full_url(b, path), "headers": {}, "body_hint": None,
                "assembled_from": {"base": b.get("source"), "path": path},
                "rationale": "后端 base × 接口路径 = 完整候选 URL(勿拼前端)",
            })
    return chains


def _op_path_x_header(intel, backends, endpoints, headers, secrets, hosts):
    if not headers:
        return []
    hdr_map = {h["name"]: "<需填/复用抓包值>" for h in headers if isinstance(h, dict)}
    chains = []
    real_backends = [b for b in backends if not b.get("same_as_frontend")] or backends
    for b in real_backends:
        for ep in endpoints:
            path = ep.get("path") if isinstance(ep, dict) else str(ep)
            if not path:
                continue
            chains.append({
                "method": ep.get("method", "?") if isinstance(ep, dict) else "?",
                "url": _full_url(b, path), "headers": dict(hdr_map), "body_hint": None,
                "assembled_from": {"base": b.get("source"), "path": path,
                                   "headers": [h["name"] for h in headers if isinstance(h, dict)]},
                "rationale": "接口 × 拦截器注入头 = 带完整追踪/鉴权头的请求(EagleEye 等必带头一开始就加上)",
            })
    return chains


def _op_authpath_x_token(intel, backends, endpoints, headers, secrets, hosts):
    tokens = [s for s in secrets if isinstance(s, dict)
              and (s.get("type") in ("token", "jwt", "app_secret", "api_key")
                   or "token" in (s.get("name", "").lower()))]
    if not tokens:
        return []
    auth_eps = [ep for ep in endpoints if isinstance(ep, dict)
                and any(k in (ep.get("path", "").lower()) for k in _AUTH_HINT)]
    auth_eps = auth_eps or [ep for ep in endpoints if isinstance(ep, dict)]  # 无鉴权类则对全部
    real_backends = [b for b in backends if not b.get("same_as_frontend")] or backends
    chains = []
    for b in real_backends:
        for ep in auth_eps:
            path = ep.get("path")
            if not path:
                continue
            for tk in tokens:
                val = tk.get("value", "")
                for pos, hdrs in (("Authorization", {"Authorization": f"Bearer {val}"}),
                                  ("X-Token", {"X-Token": val}),
                                  ("Cookie", {"Cookie": f"token={val}"})):
                    chains.append({
                        "method": ep.get("method", "?"), "url": _full_url(b, path),
                        "headers": hdrs, "body_hint": None,
                        "assembled_from": {"base": b.get("source"), "path": path,
                                           "token": tk.get("name"), "token_position": pos},
                        "rationale": f"鉴权接口 × token 多位置复用({pos})——token 发现后必须尝试复用/绕过",
                    })
    return chains


_OPS = {
    "base_x_path": _op_base_x_path,
    "path_x_header": _op_path_x_header,
    "authpath_x_token": _op_authpath_x_token,
}


def _chain_key(c):
    """去重键:method+url+关键头位置。"""
    hk = ",".join(sorted(c.get("headers", {}).keys()))
    return f"{c.get('method')}|{c.get('url')}|{hk}"


def build(target):
    """读 intel + combine.yaml → 装配候选链 → 保留旧链 consumed 状态 → 落盘。不发包。"""
    d = _intel.load(target)
    fields = {k: d.get(k, []) for k in
              ("backends", "endpoints", "headers", "secrets", "hosts")}
    rules = _load_rules()

    new_chains = []
    for r in rules:
        needs = r.get("needs", [])
        if not all(fields.get(n) for n in needs):
            continue
        op = _OPS.get(r.get("rule"))
        if not op:
            continue
        new_chains.extend(op(d, fields["backends"], fields["endpoints"],
                             fields["headers"], fields["secrets"], fields["hosts"]))

    # 去重 + 保留旧 chains 的 consumed 状态
    old = {_chain_key(c): c for c in _load_chains(target)["chains"]}
    merged, seen = [], set()
    for i, c in enumerate(new_chains):
        k = _chain_key(c)
        if k in seen:
            continue
        seen.add(k)
        prev = old.get(k)
        c["id"] = prev["id"] if prev else f"chain-{len(merged)+1:04d}"
        c["consumed"] = prev["consumed"] if prev else False
        c["consumed_by"] = prev.get("consumed_by") if prev else None
        merged.append(c)

    _save_chains(target, {"target": target, "chains": merged})
    return {"target": target, "total": len(merged),
            "pending": len([c for c in merged if not c["consumed"]]),
            "by_rule": _count_by_rationale(merged)}


def _count_by_rationale(chains):
    out = {}
    for c in chains:
        key = c["rationale"].split("(")[0].split("——")[0][:20]
        out[key] = out.get(key, 0) + 1
    return out


def pending(target, limit=20):
    """摆出还没打过的候选链(给 AI 判断先打哪条,engine 不下指令)。"""
    chains = [c for c in _load_chains(target)["chains"] if not c.get("consumed")]
    return {"target": target, "pending_total": len(chains), "chains": chains[:limit]}


def consume(target, chain_id, by):
    """AI 发过某条链后回填 consumed(消费追踪:发没发过)。"""
    data = _load_chains(target)
    for c in data["chains"]:
        if c["id"] == chain_id:
            c["consumed"] = True
            c["consumed_by"] = by
            _save_chains(target, data)
            return {"ok": True, "consumed": chain_id}
    return {"ok": False, "reason": f"未找到 {chain_id}"}


def relate(target, field, value):
    """反馈触发:给定一条新情报,提示它能和哪些旧情报组合成新链(疑问式,不下指令)。"""
    d = _intel.load(target)
    hints = []
    if field == "secrets":
        neps = len(d.get("endpoints", []))
        hints.append(f"新凭证 {value[:24]}... × 已有 {neps} 个接口:它能以 Bearer/X-Token/Cookie 哪种位置解锁哪个接口?")
        if _UUID_RE.match(str(value)):
            hints.append("该值是 UUID 形态:能否作为 org_id/project_id/id 代入某个业务接口?")
    elif field == "backends":
        hints.append(f"新后端 {value} × 已挖的接口路径:哪些路径拼上它后值得优先打?")
    elif field == "headers":
        hints.append(f"新请求头 {value}:哪些接口的请求缺了它才被拦截(如 429/403)?带上重打?")
    elif field == "endpoints":
        hints.append(f"新接口 {value}:它是否需要鉴权?已发现的 token/头能否直接组合上去打?")
    hints.append("→ 想清楚后 synth build 重新装配,pending 会浮现新的未打链。")
    return {"target": target, "new": {field: value}, "relate_questions": hints}


def main():
    ap = argparse.ArgumentParser(description="PESop 情报组合装配台(撮合攻击链候选,不发包)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("build", "pending"):
        p = sub.add_parser(name); p.add_argument("--target", required=True)
    cs = sub.add_parser("consume")
    cs.add_argument("--target", required=True); cs.add_argument("--id", required=True)
    cs.add_argument("--by", required=True)
    rl = sub.add_parser("relate")
    rl.add_argument("--target", required=True); rl.add_argument("--field", required=True)
    rl.add_argument("--value", required=True)

    args = ap.parse_args()
    if args.cmd == "build":
        r = build(args.target)
    elif args.cmd == "pending":
        r = pending(args.target)
    elif args.cmd == "consume":
        r = consume(args.target, args.id, args.by)
    else:
        r = relate(args.target, args.field, args.value)
    print(json.dumps(r, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
