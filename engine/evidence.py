#!/usr/bin/env python3
"""
PESop engine · evidence —— 结构化证据台账 / 发现登记

作用：把 "发现了什么" 与 "http_client 落盘的真实证据" 强绑定。
核心规矩（治 F2 谎报 / F1 半成品）：
  - 登记一个 "确认(confirmed)" 级别的发现时,必须挂 ≥1 个真实 evidence_id
    （即 runs/<target>/evidence/ 下真实存在的发包记录）。挂不上 → 拒绝登记为
    confirmed,自动降级 suspected,并在台账里记原因。
  - 这样 "确认漏洞" 不再是 AI 写一段文字,而是 "指向一条它真发过的请求/响应"。

发现状态机（对应 L1 三段生命）：
  unknown -> suspected -> confirmed(坐实,带证据) 或 disproved(证伪,带证据)
  只有 confirmed / disproved 是终态；suspected 是库存,不计入最终评级。

台账文件：runs/<target>/findings.json （单一事实源,可被人/AI 反复读写）

CLI 用法：
  # 登记发现(尝试 confirmed,但会校验证据是否真实存在)
  python engine/evidence.py add --target https://t.com \
      --title "IDOR:订单越权读取" --severity high --status confirmed \
      --evidence ev-20260717-abc123 --evidence ev-20260717-def456 \
      --hypothesis "普通用户可读他人订单" \
      --impact "可批量枚举全站订单" --note "已脚本跑通20个ID"

  python engine/evidence.py list --target https://t.com
  python engine/evidence.py show --target https://t.com --id find-0003
"""

import argparse
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
RUNS_ROOT = os.path.join(_PROJECT_ROOT, "runs")

VALID_STATUS = ["unknown", "suspected", "confirmed", "disproved"]
VALID_SEVERITY = ["info", "low", "medium", "high", "critical"]


def _now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()


def _slug(target: str) -> str:
    p = urlparse(target if "://" in target else "http://" + target)
    host = p.hostname or "unknown"
    port = f"_{p.port}" if p.port else ""
    return f"{host}{port}".replace("/", "_")


def _target_dir(target: str) -> str:
    d = os.path.join(RUNS_ROOT, _slug(target))
    os.makedirs(d, exist_ok=True)
    return d


def _findings_path(target: str) -> str:
    return os.path.join(_target_dir(target), "findings.json")


def _load(target):
    p = _findings_path(target)
    if not os.path.exists(p):
        return {"target": target, "findings": []}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _save(target, data):
    with open(_findings_path(target), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _evidence_exists(target, evidence_id) -> bool:
    """校验 evidence_id 是否真的对应一条落盘的发包记录。"""
    ev_path = os.path.join(_target_dir(target), "evidence", f"{evidence_id}.json")
    return os.path.exists(ev_path)


def add_finding(target, title, severity="info", status="suspected",
                evidence=None, hypothesis="", impact="", note=""):
    """
    登记一个发现。返回登记结果 dict。
    关键校验：status=confirmed 必须至少挂一个真实存在的 evidence_id,
    否则强制降级为 suspected 并记录原因（治谎报）。
    """
    evidence = evidence or []
    if severity not in VALID_SEVERITY:
        severity = "info"
    if status not in VALID_STATUS:
        status = "suspected"

    downgrade_reason = None
    # 核心硬约束：confirmed / disproved 都是 "带证据的终态",必须有真实证据
    if status in ("confirmed", "disproved"):
        real = [e for e in evidence if _evidence_exists(target, e)]
        missing = [e for e in evidence if not _evidence_exists(target, e)]
        if not real:
            downgrade_reason = (
                f"声明 {status} 但无任何真实证据(evidence_id 在 runs 下不存在:"
                f"{missing or '未提供'});按证据决定状态原则强制降级 suspected"
            )
            status = "suspected"
        elif missing:
            downgrade_reason = f"部分 evidence_id 不存在,已忽略:{missing}"
            evidence = real

    data = _load(target)
    fid = f"find-{len(data['findings']) + 1:04d}"
    record = {
        "id": fid,
        "created": _now_iso(),
        "title": title,
        "severity": severity,
        "status": status,
        "hypothesis": hypothesis,
        "impact": impact,
        "evidence_ids": evidence,
        "note": note,
        "downgrade_reason": downgrade_reason,
    }
    data["findings"].append(record)
    _save(target, data)
    return record


def list_findings(target):
    return _load(target)["findings"]


def show_finding(target, fid):
    for f in _load(target)["findings"]:
        if f["id"] == fid:
            return f
    return None


def summary(target):
    """按状态×严重度汇总,给收尾报告用。"""
    findings = list_findings(target)
    by_status = {}
    for f in findings:
        by_status.setdefault(f["status"], 0)
        by_status[f["status"]] += 1
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    return {
        "target": target,
        "total": len(findings),
        "by_status": by_status,
        "confirmed_count": len(confirmed),
        "confirmed_titles": [f"{f['severity'].upper()}: {f['title']}" for f in confirmed],
    }


def report(target):
    """收尾报告数据:发现台账 + intel 情报 聚合(修复审计 M7:两套存储打通,一处可见)。"""
    data = {"findings_summary": summary(target),
            "findings": list_findings(target)}
    # 关联 intel 情报(同 runs/<target>/ 下)
    try:
        import sys, os as _os
        sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
        import intel as _intel
        data["intel"] = _intel.summary(target)
    except Exception as e:
        data["intel_error"] = str(e)
    return data


def main():
    ap = argparse.ArgumentParser(description="PESop 结构化证据台账")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="登记发现")
    a.add_argument("--target", required=True)
    a.add_argument("--title", required=True)
    a.add_argument("--severity", default="info", choices=VALID_SEVERITY)
    a.add_argument("--status", default="suspected", choices=VALID_STATUS)
    a.add_argument("--evidence", action="append", default=[], help="真实 evidence_id,可多次")
    a.add_argument("--hypothesis", default="")
    a.add_argument("--impact", default="")
    a.add_argument("--note", default="")

    l = sub.add_parser("list", help="列出所有发现")
    l.add_argument("--target", required=True)

    s = sub.add_parser("show", help="查看单个发现")
    s.add_argument("--target", required=True)
    s.add_argument("--id", required=True)

    m = sub.add_parser("summary", help="汇总")
    m.add_argument("--target", required=True)

    rp = sub.add_parser("report", help="收尾报告:发现+情报聚合(打通evidence与intel)")
    rp.add_argument("--target", required=True)

    args = ap.parse_args()

    if args.cmd == "add":
        r = add_finding(args.target, args.title, args.severity, args.status,
                        args.evidence, args.hypothesis, args.impact, args.note)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        if r.get("downgrade_reason"):
            print("\n[!] 注意:" + r["downgrade_reason"])
    elif args.cmd == "list":
        print(json.dumps(list_findings(args.target), ensure_ascii=False, indent=2))
    elif args.cmd == "show":
        r = show_finding(args.target, args.id)
        print(json.dumps(r, ensure_ascii=False, indent=2) if r else "未找到")
    elif args.cmd == "summary":
        print(json.dumps(summary(args.target), ensure_ascii=False, indent=2))
    elif args.cmd == "report":
        print(json.dumps(report(args.target), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
