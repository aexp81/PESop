#!/usr/bin/env python3
"""
PESop engine · floor_guard —— 下限守门层（A 阶段骨架核心）

骨架宪法(见 docs/ARCH-DECISIONS.md):
  engine 只守下限、不设上限;决策权归 AI。
  【重大转向】不再输出"缺口清单/该做什么"的指令(那会把 AI 训成填表的流水线工人:
  为消缺口而机械 consume,不为价值而思考)。改为:
    读态势 → ①facts 如实摆情报 ②open_questions 对未消化情报抛苏格拉底式问题,逼 AI
    判断"这意味着什么、能打进哪里、该往哪深钻"。verdict 只陈述深度状态,不下指令。
  它【不发包、不决策、不生成假设、不给待办清单】。

"走不通"的定义(2.1):  value_reached=False  且  floor_satisfied=True
  → 只有下限达标(努力充分)且没挖到中危+价值时,才允许判"走不通"、才发散/变思路。

CLI:
  python engine/floor_guard.py assess --target https://t.com
"""

import argparse
import json
import os
import re
import sys

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
FLOOR_YAML = os.path.join(_PROJECT_ROOT, "knowledge", "floor.yaml")

sys.path.insert(0, _ENGINE_DIR)
import intel as _intel        # noqa: E402
import evidence as _ev        # noqa: E402

# 价值达成的门槛:confirmed 且严重度 >= medium
_VALUE_SEVERITIES = {"medium", "high", "critical"}


# --------------------------------------------------------------------------
# 载入下限定义(pyyaml 优先,无则内置极简解析兜底,读失败不阻断)
# --------------------------------------------------------------------------
def _load_floor():
    """返回 (checks:list, note:str|None)。读失败返回 ([], 原因),由 assess 兜底。"""
    if not os.path.exists(FLOOR_YAML):
        return [], f"floor.yaml 不存在:{FLOOR_YAML}"
    try:
        with open(FLOOR_YAML, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        return [], f"floor.yaml 读取失败:{e}"
    try:
        import yaml
        data = yaml.safe_load(text) or {}
        return data.get("floor_checks", []), None
    except ImportError:
        return _minimal_parse_floor(text), None


def _minimal_parse_floor(text):
    """无 pyyaml 时兜底解析 floor.yaml 的固定结构:
      floor_checks:
        - id: xxx
          group: coverage|drain
          check: xxx
          args:
            k: v          # 或 args: {}
          gap_hint: "..."
    只认这几个键;args 支持 '{}' 内联空 dict 或缩进子键。
    """
    checks = []
    cur = None
    in_args = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if re.match(r"^\s*-\s+id:\s*", line):
            if cur is not None:
                checks.append(cur)
            cur = {"args": {}}
            cur["id"] = line.split("id:", 1)[1].strip().strip('"').strip("'")
            in_args = False
        elif cur is not None:
            # args: {}  或  args:
            m_args = re.match(r"^\s+args:\s*(.*)$", line)
            if m_args:
                rest = m_args.group(1).strip()
                if rest in ("{}", ""):
                    cur["args"] = {}
                    in_args = (rest == "")   # 空则后续缩进行是子键
                continue
            # args 下的子键
            m_sub = re.match(r"^\s{6,}(\w+):\s*(.*)$", line)
            if in_args and m_sub:
                cur["args"][m_sub.group(1)] = m_sub.group(2).strip().strip('"').strip("'")
                continue
            # 顶层字段
            m = re.match(r"^\s+(\w+):\s*(.*)$", line)
            if m and m.group(1) in ("group", "check", "question"):
                cur[m.group(1)] = m.group(2).strip().strip('"').strip("'")
                in_args = False
    if cur is not None:
        checks.append(cur)
    return checks


# --------------------------------------------------------------------------
# 价值判定:findings 里有无 confirmed 且严重度 >= medium
# --------------------------------------------------------------------------
def _value_reached(target):
    for f in _ev.list_findings(target):
        if f.get("status") == "confirmed" and f.get("severity") in _VALUE_SEVERITIES:
            return True
    return False


# --------------------------------------------------------------------------
# 四个原子 check 解释器:达标返回 True,否则 False
# --------------------------------------------------------------------------
def _check_fingerprint_tag_covered(args, isum, idata, target):
    """某 tag 有指纹命中,却没有该域对应的终态 finding(confirmed/disproved)→ 未覆盖。
    无该 tag 指纹 → 无攻击面,视为已达标(N/A)。v0.1 简化判据,后续按实战校准。"""
    tag = args.get("tag")
    has_tag = any(f.get("tag") == tag for f in idata.get("fingerprints", []))
    if not has_tag:
        return True  # 无该域攻击面,N/A
    terminal = any(
        f.get("status") in ("confirmed", "disproved")
        for f in _ev.list_findings(target)
    )
    return terminal


def _check_modeling_done(args, isum, idata, target):
    """有接口或 application 指纹却未建模 → 未达标。无 application 面 → N/A 达标。"""
    has_app = (isum["counts"]["endpoints"] > 0 or
               any(f.get("tag") == "application" for f in idata.get("fingerprints", [])))
    if not has_app:
        return True
    return bool(isum.get("modeling_done"))


def _check_endpoints_all_consumed(args, isum, idata, target):
    """intel.endpoints 有未 consumed 的接口 → 未达标。无接口 → N/A 达标。"""
    return isum["dangling"].get("endpoints", 0) == 0


def _check_intel_field_no_dangling(args, isum, idata, target):
    """某字段有"拿到却没用"(consumed=false)的悬挂项 → 未达标。"""
    field = args.get("field")
    return isum["dangling"].get(field, 0) == 0


_CHECK_DISPATCH = {
    "fingerprint_tag_covered": _check_fingerprint_tag_covered,
    "modeling_done": _check_modeling_done,
    "endpoints_all_consumed": _check_endpoints_all_consumed,
    "intel_field_no_dangling": _check_intel_field_no_dangling,
}


# --------------------------------------------------------------------------
# 对外主函数
# --------------------------------------------------------------------------
def assess(target):
    """读态势 → 如实摆事实 + 抛苏格拉底式问题(逼思考,不给指令清单)。

    骨架宪法转向:engine 不再输出"缺口清单/该做什么"(那会把 AI 训成填表工人),
    而是:①facts 如实呈现当前掌握的情报态势 ②open_questions 对未消化的情报抛出问题,
    逼 AI 判断"这意味着什么、该往哪深钻"。verdict 只陈述状态,不下指令。
    """
    checks, load_note = _load_floor()
    isum = _intel.summary(target)
    idata = _intel.load(target)

    # 事实层:如实摆出当前态势(不评判、不指令)
    facts = {
        "waf": isum["waf"],
        "fingerprints": isum["fingerprints"],
        "endpoints_total": isum["counts"]["endpoints"],
        "endpoints_unconsumed": isum["dangling"]["endpoints"],
        "secrets_total": isum["counts"]["secrets"],
        "secrets_unconsumed": isum["dangling"]["secrets"],
        "hosts_unconsumed": isum["dangling"]["hosts"],
        "modeling_done": isum.get("modeling_done", False),
        "findings_with_value": _value_reached(target),
    }

    # 未达标的下限 → 转成【问题】抛给 AI(而非"去补X"的指令)
    open_questions = []
    unmet = 0
    for c in checks:
        fn = _CHECK_DISPATCH.get(c.get("check"))
        if fn is None:
            continue
        try:
            ok = fn(c.get("args") or {}, isum, idata, target)
        except Exception:
            continue
        if not ok:
            unmet += 1
            q = c.get("question") or c.get("gap_hint") or ""
            if q:
                open_questions.append({"id": c.get("id"), "group": c.get("group"), "question": q})

    floor_satisfied = unmet == 0
    value_reached = facts["findings_with_value"]

    # verdict:只陈述"深度状态",不下指令。核心提醒——流程走完≠有纵深。
    if not floor_satisfied:
        verdict = ("还有情报没被消化、没被深钻。下面的问题不是待办清单,是要你回答的思考题——"
                   "先想清楚每条情报意味着什么、能打进哪里,再决定下一步。")
    elif value_reached:
        verdict = ("已挖到中危+价值。这条线是否已到你能想到的最深?还有没有未被验证的假设?"
                   "其它攻击面是否也都想过了?(收敛与否由你判断,不设上限)")
    else:
        verdict = ("现有情报都已消化但尚无中危+价值产出。是你的系统理解模型需要修正,"
                   "还是有维度还没切?(证伪≠系统安全,是模型要改)")

    result = {
        "target": target,
        "facts": facts,
        "value_reached": value_reached,
        "floor_satisfied": floor_satisfied,
        "open_questions": open_questions,
        "verdict": verdict,
    }
    if load_note:
        result["floor_load_note"] = load_note
    return result


def main():
    ap = argparse.ArgumentParser(description="PESop 下限守门(只读态势给缺口清单,不决策)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="下限体检:出缺口清单+三态裁决")
    a.add_argument("--target", required=True)
    args = ap.parse_args()
    if args.cmd == "assess":
        print(json.dumps(assess(args.target), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
