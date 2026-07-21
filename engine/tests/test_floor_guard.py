#!/usr/bin/env python3
"""
floor_guard + intel.consume 最小单元测试(A阶段安全承重墙护栏)。

设计:不发真包。用 tmp_path 把 intel/evidence 的 RUNS_ROOT 指到临时目录,
直接构造 intel.json / findings.json 态势,验证:
  1. intel.add 给 dict 条目自动补 consumed=false(向后兼容)
  2. intel.consume 能把条目标记 consumed=true
  3. floor_guard 三态 verdict:未达标 / 达标+有价值 / 达标+无价值(=走不通)
  4. 缺口清单只在未达标时出现,且含对应 gap_hint

运行: pytest engine/tests/test_floor_guard.py -v
"""
import os
import sys

import pytest

_ENGINE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ENGINE_DIR)
import intel          # noqa: E402
import evidence       # noqa: E402
import floor_guard    # noqa: E402
import reflow         # noqa: E402

TARGET = "https://t.example.com"


@pytest.fixture
def runs(tmp_path, monkeypatch):
    """把 intel / evidence 的 RUNS_ROOT 重定向到临时目录,互不污染。"""
    root = str(tmp_path / "runs")
    os.makedirs(root, exist_ok=True)
    monkeypatch.setattr(intel, "RUNS_ROOT", root)
    monkeypatch.setattr(evidence, "RUNS_ROOT", root)
    return root


# ---------------------------------------------------------------- intel.consume
def test_add_dict_gets_consumed_false_by_default(runs):
    intel.add(TARGET, "secrets", {"name": "OSS_AK", "value": "LTAI123"}, dedup_key="name")
    d = intel.load(TARGET)
    assert d["secrets"][0]["consumed"] is False
    assert d["secrets"][0]["consumed_by"] is None


def test_consume_marks_entry(runs):
    intel.add(TARGET, "secrets", {"name": "OSS_AK", "value": "LTAI123"}, dedup_key="name")
    res = intel.consume(TARGET, "secrets", "OSS_AK", by="打通对象存储")
    assert res["ok"] is True
    d = intel.load(TARGET)
    assert d["secrets"][0]["consumed"] is True
    assert d["secrets"][0]["consumed_by"] == "打通对象存储"


def test_consume_miss_returns_not_ok(runs):
    res = intel.consume(TARGET, "secrets", "NOPE", by="x")
    assert res["ok"] is False


def test_summary_dangling_counts(runs):
    intel.add(TARGET, "secrets", {"name": "A", "value": "1"}, dedup_key="name")
    intel.add(TARGET, "secrets", {"name": "B", "value": "2"}, dedup_key="name")
    intel.consume(TARGET, "secrets", "A", by="used")
    s = intel.summary(TARGET)
    assert s["dangling"]["secrets"] == 1   # 只剩 B 未榨干


# ------------------------------------------------- floor_guard 事实+提问形态
def test_unmet_floor_emits_questions_not_gaps(runs):
    # 有未榨干的 secret → drain-secrets 未达标 → 抛出【问题】(疑问句),不再是缺口指令
    intel.add(TARGET, "secrets", {"name": "DANGLING", "value": "x"}, dedup_key="name")
    r = floor_guard.assess(TARGET)
    assert r["floor_satisfied"] is False
    assert "gaps" not in r                      # 不再有缺口清单
    assert "open_questions" in r and r["open_questions"]
    qids = [q["id"] for q in r["open_questions"]]
    assert "drain-secrets" in qids
    # 问题是疑问句(逼思考),不是"去做X"的指令
    dq = next(q for q in r["open_questions"] if q["id"] == "drain-secrets")
    assert "?" in dq["question"] or "?" in dq["question"]
    # facts 如实摆出未消化情报
    assert r["facts"]["secrets_unconsumed"] == 1


def test_all_consumed_no_questions(runs):
    # 空态势:无指纹/接口/悬挂 → 无未达标项 → 无 open_questions
    r = floor_guard.assess(TARGET)
    assert r["floor_satisfied"] is True
    assert r["value_reached"] is False
    assert r["open_questions"] == []
    assert "模型" in r["verdict"] or "维度" in r["verdict"]   # 引导修正模型/切维度


def test_value_reached_verdict_asks_depth(runs):
    # 下限达标 + confirmed high finding → verdict 追问"是否已到最深/其它面想过没"
    ev_dir = os.path.join(evidence._target_dir(TARGET), "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    ev_id = "ev-20260101-abc123"
    with open(os.path.join(ev_dir, f"{ev_id}.json"), "w", encoding="utf-8") as f:
        f.write("{}")
    res = evidence.add_finding(TARGET, title="RCE", severity="high",
                               status="confirmed", evidence=[ev_id])
    assert res["status"] == "confirmed"
    r = floor_guard.assess(TARGET)
    assert r["floor_satisfied"] is True
    assert r["value_reached"] is True
    assert "最深" in r["verdict"] or "攻击面" in r["verdict"]


def test_coverage_question_when_framework_fp_but_no_terminal(runs):
    # 有 framework 指纹却无终态 finding → cover-framework 抛问题
    intel.add(TARGET, "fingerprints",
              {"id": "spring-boot", "tag": "framework"}, dedup_key="id")
    r = floor_guard.assess(TARGET)
    qids = [q["id"] for q in r["open_questions"]]
    assert "cover-framework" in qids
    assert r["floor_satisfied"] is False


# --------------------------------------------------- 无 pyyaml 兜底解析器
def test_minimal_parse_floor_matches_pyyaml():
    # 兜底解析器应能解出与 pyyaml 一致的 check 条数与关键字段(格式漂移守护)
    with open(floor_guard.FLOOR_YAML, encoding="utf-8") as f:
        text = f.read()
    import yaml
    expected = yaml.safe_load(text)["floor_checks"]
    got = floor_guard._minimal_parse_floor(text)
    assert len(got) == len(expected)
    for g, e in zip(got, expected):
        assert g["id"] == e["id"]
        assert g["check"] == e["check"]
        assert g["group"] == e["group"]
        assert (g.get("args") or {}) == (e.get("args") or {})


# --------------------------------------------------- reflow.verify 知识一致性
def test_verify_existing_fingerprints_no_dangling():
    # 存量指纹库的 playbook 引用应零悬空(守护:回灌不应引入坏引用)
    r = reflow.verify()
    assert r["dangling"] == [], f"存量出现悬空引用:{r['dangling']}"


def test_verify_detects_dangling(monkeypatch):
    # 人为构造一个指向不存在文件的指纹 → verify 必须抓出来
    fake_fps = [
        {"id": "good", "playbook": "domains/framework/spring-boot.yaml"},
        {"id": "bad", "playbook": "domains/framework/does-not-exist.yaml"},
        {"id": "nullpb", "playbook": None},   # 有意留空,不算悬空
    ]
    import recon
    monkeypatch.setattr(recon, "load_fingerprints", lambda: fake_fps)
    r = reflow.verify()
    dangling_ids = [d["id"] for d in r["dangling"]]
    assert dangling_ids == ["bad"]
    assert r["ok_count"] == 1        # 只有 good 存在
    assert r["checked"] == 2         # nullpb 不计入

