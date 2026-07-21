#!/usr/bin/env python3
"""
PESop engine · run —— 编排器(把三维流程 + 下限守门变可执行)

把标准流程骨架固化成命令,减少 AI 靠读 AGENT.md 自行拼工具的空间。
它不剥夺 AI 的判断(具体深钻/发散仍由 AI 做),只保证编排骨架被真正执行。

命令:
  init   —— 情报就位:自动串 waf.identify + recon(分诊+写intel),一条命令完成。
  status —— 全局态势:intel(WAF/指纹/接口/密钥/建模) + findings + 下一步建议
            + 下限体检(floor_guard:够不够收工/该不该判走不通)。
  next   —— 只输出"下一步该干什么"的建议(status 的精简版)。

用法:
  python engine/run.py init   --target https://t.com
  python engine/run.py status --target https://t.com
  python engine/run.py next   --target https://t.com
"""

import argparse
import json
import os
import sys

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ENGINE_DIR)
import waf as _waf        # noqa: E402
import recon as _recon    # noqa: E402
import intel as _intel    # noqa: E402
import evidence as _ev    # noqa: E402


def init(target, probe_paths=None):
    """情报就位:WAF识别 + 指纹分诊,全部自动写 intel。返回就绪态。"""
    waf_res = _waf.identify(target)                       # 写 intel.waf
    recon_res = _recon.recon(target, probe_paths)         # 写 intel.fingerprints + 分诊
    return {
        "step": "init 完成(waf识别 + 指纹分诊,已写入 intel)",
        "waf": {"present": waf_res["waf_present"], "id": waf_res["waf_id"]},
        "dispatch_by_tag": recon_res["dispatch_by_tag"],
        "next_action": recon_res["next_action"],
        "hint": "接下来:framework/infra 域反射档先打(读 domains/ playbook);"
                "进 application 域前先 run.py 的建模检查(intel model)。",
    }


def _next_advice(target):
    """基于当前 intel/findings 态势,给出下一步建议。"""
    isum = _intel.summary(target)
    fsum = _ev.summary(target)
    advice = []

    # WAF
    if isum["waf"]["present"] is None:
        advice.append("① 尚未做 WAF 识别 → 先 run.py init(或 waf.py identify)")
    elif isum["waf"]["present"]:
        advice.append(f"① 有WAF({isum['waf']['id']}) → 发payload前先 waf.py advise 拿绕过手法")

    # 指纹/分诊
    tags = {}
    for f in _intel.load(target)["fingerprints"]:
        tags.setdefault(f.get("tag"), []).append(f.get("id"))
    if not tags:
        advice.append("② 无指纹命中 → recon 未跑或目标无已知指纹;application域走Q1-Q5手工建模")
    else:
        for t in ["framework", "infra"]:
            if tags.get(t):
                advice.append(f"② {t}域(反射档)已命中 {tags[t]} → 读 domains/{t}/ playbook 直接展开攻击链")
        if tags.get("application"):
            advice.append(f"③ application域命中 {tags['application']}")

    # application 域建模检查(O5:进该域必须先建模)
    if isum.get("modeling_done"):
        advice.append("④ application域建模已完成(Q1-Q5)→ 可进未授权/绕过/FUZZ/越权")
    elif isum["counts"]["endpoints"] > 0 or tags.get("application"):
        advice.append("④ ⚠ 已有接口/application指纹但未建模 → 进application域前必须先 "
                      "intel.py model 填 Q1-Q5(否则违反建模档要求)")

    # 跨域产物流动提示
    if isum["counts"]["secrets"] > 0:
        advice.append(f"⑤ 已挖到 {isum['counts']['secrets']} 个密钥/凭证 "
                      f"{isum['secrets_names']} → 每个能解锁哪个系统?攻击面是什么?(想清楚再动手,别只记录不利用)")

    # 收尾
    if fsum["total"] > 0:
        st = fsum["by_status"]
        if st.get("suspected", 0) > 0:
            advice.append(f"⑥ 有 {st['suspected']} 个 suspected 未推到终态 → 继续钻或证伪")
        advice.append("⑦ 收尾看 evidence.py report(发现+情报聚合) → 写报告 → reflow 回灌")

    # —— 下限守门:如实摆事实 + 抛思考题(不给待办清单,逼 AI 动脑)——
    try:
        import floor_guard as _fg   # noqa: E402
        fa = _fg.assess(target)
        advice.append(f"⑧ 纵深自检:{fa['verdict']}")
        for q in fa.get("open_questions", []):
            advice.append(f"    ? [{q['group']}] {q['question']}")
    except Exception as e:
        advice.append(f"⑧ 纵深自检跳过(floor_guard 不可用:{e})")

    # —— 情报组合:摆出已装配的攻击链候选 + 反问(逼 AI 做组合推导,不下指令)——
    try:
        import synth as _synth   # noqa: E402
        pend = _synth.pending(target, limit=5)
        n = pend["pending_total"]
        if n > 0:
            advice.append(f"⑨ 已装配 {n} 条攻击链候选还没打过(情报已交叉组合,勿再各自孤立发):")
            for c in pend["chains"]:
                af = c.get("assembled_from", {})
                advice.append(f"    ↳ [{c['id']}] {c.get('method')} {c.get('url')} "
                              f"| 头:{list(c.get('headers',{}).keys()) or '无'} | 由 {af}")
            advice.append("    ? 你判断先打哪条最可能突破?为什么?发过的用 synth consume 标记。")
    except Exception as e:
        advice.append(f"⑨ 情报组合跳过(synth 不可用:{e})")

    return {"target": target, "next_advice": advice or ["态势为空,先 run.py init"]}


def status(target):
    return {
        "target": target,
        "intel": _intel.summary(target),
        "findings": _ev.summary(target),
        **_next_advice(target),
    }


def main():
    ap = argparse.ArgumentParser(description="PESop 编排器(固化三维流程骨架)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ["init", "status", "next"]:
        p = sub.add_parser(name)
        p.add_argument("--target", required=True)
        if name == "init":
            p.add_argument("--probe-paths", default=None)

    args = ap.parse_args()
    if args.cmd == "init":
        paths = [p.strip() for p in args.probe_paths.split(",")] if getattr(args, "probe_paths", None) else None
        print(json.dumps(init(args.target, paths), ensure_ascii=False, indent=2))
    elif args.cmd == "status":
        print(json.dumps(status(args.target), ensure_ascii=False, indent=2))
    elif args.cmd == "next":
        print(json.dumps(_next_advice(args.target), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
