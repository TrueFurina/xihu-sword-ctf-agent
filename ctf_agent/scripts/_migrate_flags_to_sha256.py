"""真 flag 红线迁移（2026-08-24）：把真题 JSON 明文 flag 迁出 git。

- 每个 real question JSON：flag 字段改为 sha256 占位，新增 flag_sha256 同值；
- 明文 flag 写入 data/results/verified_flags.json（gitignored，永不进历史）；
- 不改附件/描述，benchmark 后续用 sha256 比对（cases.Question.flag_matches）。
"""
from __future__ import annotations
import json
import glob
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QDIR = ROOT / "data" / "questions_real"
VF = ROOT / "data" / "results" / "verified_flags.json"
RX = __import__("re").compile(r"^[0-9a-fA-F]{64}$")

# 载入现有 verified_flags.json（保留已有条目）
verified: dict = {"note": "本地核验真值库（gitignored，永不进 git 历史）。sha256 用于无明文验证。"}
if VF.exists():
    try:
        _old = json.load(open(VF, encoding="utf-8"))
        if isinstance(_old, dict):
            verified.update(_old)
    except Exception:
        pass
flags_store = verified.setdefault("flags", {})

migrated = 0
for f in sorted(QDIR.rglob("*.json")):
    d = json.load(open(f, encoding="utf-8"))
    fl = d.get("flag")
    if not (isinstance(fl, str) and fl) or RX.match(fl):
        continue  # 已是占位或空
    qid = d.get("id") or f.stem
    h = hashlib.sha256(fl.encode("utf-8")).hexdigest()
    # 迁移：flag -> sha256 占位
    d["flag"] = h
    d["flag_sha256"] = h
    json.dump(d, open(f, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    # 明文进 gitignored 真值库
    rec = flags_store.get(qid, {})
    rec["flag_sha256"] = h
    rec["flag_plaintext_len"] = len(fl)
    flags_store[qid] = rec
    migrated += 1
    print(f"migrated {qid}: flag->{h[:12]}... (plaintext len={len(fl)})")

verified["flags"] = flags_store
json.dump(verified, open(VF, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"DONE: migrated {migrated} real question files; verified_flags.json updated ({len(flags_store)} entries)")
