#!/usr/bin/env python3
"""
synth 组合装配台单元测试(不发包,纯装配逻辑)。

覆盖:
  1. base × path → 完整 URL(不拼前端)
  2. path × header → 候选链带上拦截器头
  3. authpath × token → token 多位置(Bearer/X-Token/Cookie)复用候选
  4. 消费追踪(consume) + pending 只出未打的
  5. build 保留旧链的 consumed 状态(不重置)
  6. relate 反馈触发(疑问式)
运行: pytest engine/tests/test_synth.py -v
"""
import os
import sys

import pytest

_ENGINE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ENGINE_DIR)
import intel    # noqa: E402
import synth    # noqa: E402

TARGET = "https://app.example.com"


@pytest.fixture
def runs(tmp_path, monkeypatch):
    root = str(tmp_path / "runs")
    os.makedirs(root, exist_ok=True)
    monkeypatch.setattr(intel, "RUNS_ROOT", root)
    monkeypatch.setattr(synth, "RUNS_ROOT", root)
    return root


def _seed_full(t):
    """造一份含 base+接口+头+token 的态势(模拟实战 30812/prod-api/account-auth 场景)。"""
    intel.add(t, "backends", {"base": "https://api.corp.com:30812", "prefix": "/prod-api",
                              "source": "axios.baseURL", "same_as_frontend": False}, dedup_key="base")
    intel.add(t, "endpoints", {"path": "/account-auth", "method": "POST"}, dedup_key="path")
    intel.add(t, "headers", {"name": "EagleEye-TraceID", "source": "interceptor"}, dedup_key="name")
    intel.add(t, "secrets", {"name": "feedbackPamsToken", "value": "5155567f383e",
                             "type": "token"}, dedup_key="value")


def test_base_x_path_full_url(runs):
    _seed_full(TARGET)
    r = synth.build(TARGET)
    ch = synth.pending(TARGET)["chains"]
    urls = {c["url"] for c in ch}
    # 必须拼成后端完整 URL,不是前端
    assert "https://api.corp.com:30812/prod-api/account-auth" in urls
    assert all("app.example.com" not in u for u in urls)


def test_path_x_header_attaches_trace_header(runs):
    _seed_full(TARGET)
    synth.build(TARGET)
    ch = synth.pending(TARGET)["chains"]
    # 至少有一条链带上了 EagleEye 头(治"头第N次才加")
    assert any("EagleEye-TraceID" in c.get("headers", {}) for c in ch)


def test_authpath_x_token_multi_position(runs):
    _seed_full(TARGET)
    synth.build(TARGET)
    ch = synth.pending(TARGET)["chains"]
    positions = set()
    for c in ch:
        h = c.get("headers", {})
        if "Authorization" in h:
            positions.add("bearer")
        if "X-Token" in h:
            positions.add("xtoken")
        if "Cookie" in h:
            positions.add("cookie")
    # token 至少尝试了多个位置(治"token没复用")
    assert {"bearer", "xtoken", "cookie"} <= positions


def test_consume_and_pending(runs):
    _seed_full(TARGET)
    synth.build(TARGET)
    before = synth.pending(TARGET)["pending_total"]
    assert before > 0
    cid = synth.pending(TARGET)["chains"][0]["id"]
    res = synth.consume(TARGET, cid, by="已发,返回401")
    assert res["ok"] is True
    after = synth.pending(TARGET)["pending_total"]
    assert after == before - 1        # 消费后 pending 少一条


def test_build_preserves_consumed(runs):
    _seed_full(TARGET)
    synth.build(TARGET)
    cid = synth.pending(TARGET)["chains"][0]["id"]
    synth.consume(TARGET, cid, by="x")
    # 重新 build(如新增情报后),已消费的链不该被重置
    synth.build(TARGET)
    data = synth._load_chains(TARGET)
    hit = [c for c in data["chains"] if c["id"] == cid]
    assert hit and hit[0]["consumed"] is True


def test_relate_uuid_suggests_param(runs):
    r = synth.relate(TARGET, "secrets", "ebcc45d2-638e-48cd-b66e-2e08ebdfc823")
    joined = " ".join(r["relate_questions"])
    assert "UUID" in joined and ("org_id" in joined or "project_id" in joined)


def test_no_chains_when_missing_intel(runs):
    # 只有接口没有 base → base_x_path 不触发(needs 不满足)
    intel.add(TARGET, "endpoints", {"path": "/x", "method": "GET"}, dedup_key="path")
    synth.build(TARGET)
    assert synth.pending(TARGET)["pending_total"] == 0
