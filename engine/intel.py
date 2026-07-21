#!/usr/bin/env python3
"""
PESop engine · intel —— 情报库（架构维度二:共享供料 + 层间产物流动）

核心认知:侦察不是"一个阶段",而是一份持续累积、被所有打法域共享读写的情报。
一个域的产出(域A拿到内网IP、域B heapdump出AK/SK、域C挖出接口)都写进这里,
成为其它域的输入 —— 这就是"漏洞穿在一起"的工程载体。

落盘: runs/<target>/intel.json (单一事实源,各域随时读写)

结构:
  {
    "target": ...,
    "waf": {"present": bool, "id": ..., "evidence_id": ...},
    "system_type": ...,                 # 系统类型判定(供 application 域建模)
    "fingerprints": [ {id,identity,tag,confidence,evidence_id}, ... ],
    "ports": [ {port,service,vulns,source}, ... ],
    "hosts": [ ... ],                   # 发现的域名/内网IP
    "endpoints": [ {path,method,source}, ... ],  # 接口清单(js_harvester/actuator回灌)
    "secrets": [ {name,value,source,evidence_id}, ... ],  # 密钥/凭证/AK-SK/session
    "notes": [ ... ]                    # 自由情报条目
  }

CLI:
  python engine/intel.py show --target https://t.com
  python engine/intel.py add --target https://t.com --field secrets \
      --json '{"name":"OSS_AK","value":"LTAI...","source":"heapdump"}'
  python engine/intel.py set --target https://t.com --key system_type --value "订单系统"
"""

import argparse
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
RUNS_ROOT = os.path.join(_PROJECT_ROOT, "runs")

# 列表型字段(用 add 追加) vs 标量字段(用 set 覆盖)
LIST_FIELDS = ["fingerprints", "ports", "hosts", "endpoints", "secrets", "notes", "backends", "headers"]
SCALAR_FIELDS = ["system_type"]


def _slug(target):
    p = urlparse(target if "://" in target else "http://" + target)
    host = p.hostname or "unknown"
    port = f"_{p.port}" if p.port else ""
    return f"{host}{port}".replace("/", "_")


def _target_dir(target):
    d = os.path.join(RUNS_ROOT, _slug(target))
    os.makedirs(d, exist_ok=True)
    return d


def _path(target):
    return os.path.join(_target_dir(target), "intel.json")


def load(target):
    p = _path(target)
    if not os.path.exists(p):
        return {
            "target": target,
            "created": datetime.now(timezone.utc).astimezone().isoformat(),
            "waf": {"present": None, "id": None, "evidence_id": None},
            "system_type": None,
            "modeling": None,   # Q1-Q5 建模档产物(进 application 域前必须填)
            "fingerprints": [], "ports": [], "hosts": [],
            "endpoints": [], "secrets": [], "notes": [], "backends": [], "headers": [],
        }
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save(target, data):
    with open(_path(target), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def add(target, field, item, dedup_key=None):
    """向列表型字段追加一条情报(去重)。item 是 dict 或 str。"""
    if field not in LIST_FIELDS:
        raise ValueError(f"{field} 不是列表型字段,用 set。列表型:{LIST_FIELDS}")
    data = load(target)
    lst = data.setdefault(field, [])
    # 去重
    if dedup_key and isinstance(item, dict):
        if any(isinstance(x, dict) and x.get(dedup_key) == item.get(dedup_key) for x in lst):
            save(target, data)
            return {"ok": True, "skipped": "已存在,去重", "field": field}
    elif item in lst:
        return {"ok": True, "skipped": "已存在,去重", "field": field}
    # dict 型情报默认补 consumed=false(榨干下限的前提;向后兼容:老数据无此字段视为 false)
    if isinstance(item, dict) and "consumed" not in item:
        item = {**item, "consumed": False, "consumed_by": None, "consumed_at": None}
    lst.append(item)
    save(target, data)
    return {"ok": True, "added": item, "field": field, "count": len(lst)}


# 可被标记 consumed 的字段(用于"榨干下限"):secrets/hosts/endpoints
CONSUMABLE_FIELDS = ["secrets", "hosts", "endpoints"]
# 各字段用哪个键做匹配(consume 时定位条目)
_CONSUME_MATCH_KEYS = {
    "secrets": ["name", "value"],
    "hosts": ["host", "value", "name"],
    "endpoints": ["path", "value"],
}


def consume(target, field, match_value, by):
    """把某条已获取的情报标记为"已被利用"(consumed),供榨干下限判定。

    在 field 列表里找 dict 条目:其匹配键(见 _CONSUME_MATCH_KEYS)的值等于
    match_value,或该条目本身(str)等于 match_value,则标记
    consumed=True / consumed_by=by / consumed_at=now。
    找不到返回 {ok: False}。
    """
    if field not in CONSUMABLE_FIELDS:
        raise ValueError(f"{field} 不支持 consume 标记。可标记:{CONSUMABLE_FIELDS}")
    data = load(target)
    keys = _CONSUME_MATCH_KEYS.get(field, ["name", "value"])
    hit = None
    for x in data.get(field, []):
        if isinstance(x, dict):
            if any(x.get(k) == match_value for k in keys):
                hit = x
                break
        elif x == match_value:
            # 纯字符串条目:无法就地加标记,跳过(dict 条目才承载 consumed)
            continue
    if hit is None:
        return {"ok": False, "reason": f"未找到 {field} 中匹配 {match_value} 的条目", "field": field}
    hit["consumed"] = True
    hit["consumed_by"] = by
    hit["consumed_at"] = datetime.now(timezone.utc).astimezone().isoformat()
    save(target, data)
    return {"ok": True, "consumed": hit, "field": field}


def set_field(target, key, value):
    """设置标量字段 / waf 子字段。"""
    data = load(target)
    if key == "waf.present":
        data["waf"]["present"] = value in ("true", "True", True)
    elif key == "waf.id":
        data["waf"]["id"] = value
    elif key == "waf.evidence_id":
        data["waf"]["evidence_id"] = value
    else:
        data[key] = value
    save(target, data)
    return {"ok": True, "set": {key: value}}


def set_waf(target, present, waf_id=None, evidence_id=None):
    data = load(target)
    data["waf"] = {"present": present, "id": waf_id, "evidence_id": evidence_id}
    save(target, data)
    return {"ok": True, "waf": data["waf"]}


def set_modeling(target, q1, q2, q3, q4="", q5=""):
    """写入 application 域的 Q1-Q5 建模档产物。
    进 application 域测试前必须先填,run.py status 会检查有没有填。"""
    data = load(target)
    data["modeling"] = {
        "Q1_what_system": q1,
        "Q2_if_developer": q2,
        "Q3_where_fails": q3,
        "Q4_how_verify": q4,
        "Q5_iterate": q5,
        "filled_at": datetime.now(timezone.utc).astimezone().isoformat(),
    }
    save(target, data)
    return {"ok": True, "modeling": data["modeling"]}


def summary(target):
    d = load(target)
    # 各可标记字段里"拿到却没用"(consumed 非 True)的悬挂条目数,供榨干下限判定
    dangling = {}
    for f in CONSUMABLE_FIELDS:
        dangling[f] = sum(
            1 for x in d.get(f, [])
            if isinstance(x, dict) and not x.get("consumed", False)
        )
    return {
        "target": target,
        "waf": d["waf"],
        "system_type": d["system_type"],
        "modeling_done": d.get("modeling") is not None,
        "fingerprints": [f.get("id") for f in d["fingerprints"]],
        "counts": {k: len(d.get(k, [])) for k in LIST_FIELDS},
        "dangling": dangling,
        "secrets_names": [s.get("name") for s in d["secrets"] if isinstance(s, dict)],
    }


def main():
    ap = argparse.ArgumentParser(description="PESop 情报库(共享供料+层间产物流动)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("show"); s.add_argument("--target", required=True)
    m = sub.add_parser("summary"); m.add_argument("--target", required=True)

    a = sub.add_parser("add", help="向列表字段追加情报")
    a.add_argument("--target", required=True)
    a.add_argument("--field", required=True, choices=LIST_FIELDS)
    a.add_argument("--json", required=True, help="情报条目(JSON dict 或纯字符串)")
    a.add_argument("--dedup-key", default=None)

    st = sub.add_parser("set", help="设置标量/ waf 字段")
    st.add_argument("--target", required=True)
    st.add_argument("--key", required=True)
    st.add_argument("--value", required=True)

    md = sub.add_parser("model", help="写 Q1-Q5 建模档产物(进 application 域前必填)")
    md.add_argument("--target", required=True)
    md.add_argument("--q1", required=True, help="这是什么系统")
    md.add_argument("--q2", required=True, help="若我是开发者会怎么建")
    md.add_argument("--q3", required=True, help="最可能哪里失效(3-5假设)")
    md.add_argument("--q4", default="", help="怎么验")
    md.add_argument("--q5", default="", help="响应说明什么/怎么迭代")

    cs = sub.add_parser("consume", help="把已获取情报标记为已利用(榨干下限)")
    cs.add_argument("--target", required=True)
    cs.add_argument("--field", required=True, choices=CONSUMABLE_FIELDS)
    cs.add_argument("--match", required=True, help="条目匹配值(如 secrets 的 name/value)")
    cs.add_argument("--by", required=True, help="被谁/哪一步利用(如 '打通对象存储')")

    args = ap.parse_args()
    if args.cmd == "show":
        print(json.dumps(load(args.target), ensure_ascii=False, indent=2))
    elif args.cmd == "summary":
        print(json.dumps(summary(args.target), ensure_ascii=False, indent=2))
    elif args.cmd == "add":
        try:
            item = json.loads(args.json)
        except json.JSONDecodeError:
            item = args.json
        print(json.dumps(add(args.target, args.field, item, args.dedup_key),
                         ensure_ascii=False, indent=2))
    elif args.cmd == "set":
        print(json.dumps(set_field(args.target, args.key, args.value),
                         ensure_ascii=False, indent=2))
    elif args.cmd == "model":
        print(json.dumps(set_modeling(args.target, args.q1, args.q2, args.q3, args.q4, args.q5),
                         ensure_ascii=False, indent=2))
    elif args.cmd == "consume":
        print(json.dumps(consume(args.target, args.field, args.match, args.by),
                         ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
