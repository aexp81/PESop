#!/usr/bin/env python3
"""
PESop engine · floor_guard —— 下限守门层（A 阶段骨架核心）

骨架宪法(见 docs/ARCH-DECISIONS.md):
  engine 只守下限、不设上限;决策权归 AI。守门层只做三件事:
    读态势(intel + findings) → 对照 knowledge/floor.yaml 的下限 → 出【缺口清单】。
  它【不发包、不决策、不下指令、不生成假设】。只陈述缺口和裁决,供 AI 使用。

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
            if m and m.group(1) in ("group", "check", "gap_hint"):
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
    """读态势 → 跑下限检查 → 出缺口清单 + 三态裁决。不发包/不决策/不下指令。"""
    checks, load_note = _load_floor()
    isum = _intel.summary(target)
    idata = _intel.load(target)

    gaps = []
    for c in checks:
        fn = _CHECK_DISPATCH.get(c.get("check"))
        if fn is None:
            # 未知 check 类型:不阻断,记为缺口提示(提醒该在 floor_guard 加解释器)
            gaps.append({"id": c.get("id"), "group": c.get("group"),
                         "gap_hint": f"未知 check 类型 '{c.get('check')}',需在 floor_guard 加解释器"})
            continue
        try:
            ok = fn(c.get("args") or {}, isum, idata, target)
        except Exception as e:
            gaps.append({"id": c.get("id"), "group": c.get("group"),
                         "gap_hint": f"检查执行异常:{e}"})
            continue
        if not ok:
            gaps.append({"id": c.get("id"), "group": c.get("group"),
                         "gap_hint": c.get("gap_hint", "")})

    floor_satisfied = len(gaps) == 0
    value_reached = _value_reached(target)

    if not floor_satisfied:
        verdict = "禁止判走不通 —— 下限未达标,还差以下缺口(补齐或说明N/A后再收敛)"
    elif value_reached:
        verdict = "下限已达标 且 已有中危+价值产出 → 可收敛;是否继续发散深挖由你定(不设上限)"
    else:
        verdict = "下限已达标 但 未挖到中危+价值 → 现在才允许判'走不通',发散/变思路由你定"

    result = {
        "target": target,
        "value_reached": value_reached,
        "floor_satisfied": floor_satisfied,
        "gaps": gaps,
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
