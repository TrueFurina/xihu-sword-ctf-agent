# -*- coding: utf-8 -*-
"""held-out 选题「载荷完整性」护栏回归（2026-10-14）。

背景（磁盘实测，非推测）
------------------------
`scripts/_audit_corpus_integrity.py` 早就能判 `payload_missing`，但**能力分母的
生产入口 `select_candidates()` 从不查它** —— 于是「完整性结论」到不了「测量入口」：

  - 能力分母 heldout_candidates = 1，就是 `real_reverse_js`；而它的 flag 源头
    `index.html` 已在 10-12 删除事件中永久丢失 ⇒ 这道题**结构上不可解**。
  - 可选跑池 40 题里 `ext_gctf2024_otp` 声明 287 个附件、磁盘缺 286 个。

后果：被 payload 缺失题污染的题若进了跑批，0/N 会被读成「模型能力失败」，而真因是
**没数据** —— 与 reverse_js index.html 丢失同类的口径污染，也是 _benchmark_
`interpretable` 假绿的同一族病。

修复（本文件的语义）
--------------------
`select_candidates()` 逐题计算**缺失附件清单**（颗粒度到文件，不是「全缺才算」——
reverse_js 只缺 1/2 就够致命），写进候选记录；`require_payload=True` 时作为排除原因。
默认仍为 False＝**只标记不剔除**，避免未经授权改变能力分母口径（口径变更须用户拍板）。

变异纪律（㉚）：判定全部落在生产入口（`missing_attachments` + `select_candidates`），
用例不重写被测逻辑 —— 模仿实现的自检不算守卫。零 LLM 调用。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest  # noqa: E402

from scripts import benchmark_heldout as BH  # noqa: E402
from scripts._audit_corpus_integrity import missing_attachments  # noqa: E402

OK_ID = "test_pool_payload_ok"
BAD_ID = "test_pool_payload_missing"


def _write_pool(tmp_path):
    pool = tmp_path / "pool"
    pool.mkdir(parents=True, exist_ok=True)
    good = pool / "payload_present.txt"
    good.write_text("fixture payload\n", encoding="utf-8")

    cases = {
        OK_ID: [str(good)],
        BAD_ID: [str(good), str(pool / "flag_source_never_existed.bin")],
    }
    for qid, atts in cases.items():
        (pool / f"{qid}.json").write_text(
            json.dumps({
                "id": qid,
                "category": "misc",
                "difficulty": "MEDIUM",
                "description": "fixture for payload-integrity guard",
                "attachments": atts,
                "flag_sha256": "1f65f4b5" * 8,
                "provenance": "real_past_ctf",
            }, ensure_ascii=False), encoding="utf-8")
    return pool, str(pool / "flag_source_never_existed.bin")


def _recs(tmp_path, **kw):
    """调用生产入口选题，返回 {id: record}。"""
    pool, _missing = _write_pool(tmp_path)
    _cands, all_recs = BH.select_candidates(require_sha256=True,
                                            external_dir=pool, **kw)
    return {r["id"]: r for r in all_recs}


def test_synthetic_pool_is_actually_seen(tmp_path):
    """元自检：若合成题没被扫描到，其余用例全是空转 —— 先钉死这个前提。"""
    recs = _recs(tmp_path)
    assert OK_ID in recs and BAD_ID in recs, (
        f"合成题未进入选题流程，用例将空转。实际 id 数={len(recs)}")


def test_missing_attachments_helper_reports_per_file(tmp_path):
    """helper 必须逐文件报告（不是「全缺才算」——reverse_js 只缺 1/2 就致命）。"""
    pool, missing = _write_pool(tmp_path)
    q = json.loads((pool / f"{BAD_ID}.json").read_text(encoding="utf-8"))
    got = missing_attachments(q, pool / f"{BAD_ID}.json", pool, att_root=pool)
    assert any(os.path.normcase(str(m)) == os.path.normcase(missing) for m in got), (
        f"缺失附件未被逐文件报出：{got}")

    q_ok = json.loads((pool / f"{OK_ID}.json").read_text(encoding="utf-8"))
    assert missing_attachments(q_ok, pool / f"{OK_ID}.json", pool,
                               att_root=pool) == []


def test_select_records_payload_missing_field(tmp_path):
    """核心回归：默认口径下也必须把「缺哪些附件」写进记录（看得到才谈得上诚实）。"""
    recs = _recs(tmp_path)
    assert recs[OK_ID]["payload_missing"] == [], (
        f"健康题被误报载荷缺失（假红）：{recs[OK_ID]['payload_missing']}")
    bad = recs[BAD_ID]["payload_missing"]
    assert len(bad) == 1 and "flag_source_never_existed" in bad[0], (
        f"缺失附件未被记录：{bad}")


def test_require_payload_excludes_unmeasurable(tmp_path):
    """显式开关：require_payload=True 时，缺载荷题必须退出能力分母。"""
    recs = _recs(tmp_path, require_payload=True)
    assert recs[BAD_ID]["excluded"] == "payload-missing(unmeasurable)", (
        f"开关打开后缺载荷题未被排除：excluded={recs[BAD_ID]['excluded']!r}")
    assert recs[OK_ID]["excluded"] is None, "健康题不得被连带排除"


def test_default_caliber_unchanged(tmp_path):
    """反向守卫：默认不剔除 —— 能力分母口径未经授权不得静默变化。"""
    recs = _recs(tmp_path)
    assert recs[BAD_ID]["excluded"] is None, (
        "默认口径变了（会把能力分母从 1 打掉到 0），属口径变更须用户授权")


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
