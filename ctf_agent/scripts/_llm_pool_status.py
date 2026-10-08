#!/usr/bin/env python3
"""provider「存活」的唯一机器真值源（2026-10-08 建立）。

为什么存在
----------
此前「哪几个 provider 现在能用」这件事只存在于**人写的注释**里，典型形态有三种：
① 默认值后面挂一句「白名单成员 + 当日探过、可接受」；② 逃生开关处点名几个源写
「随时可顶上」；③ 竞速档位处写「某日全量探过、返回 200」。写的时候大概率是真的
（当天确实探过），但**可用性是随余额/欠费/平台策略漂移的状态**：某源 402 欠费、
某源 403 权限、某源 429 限流都是事后才成立的。于是同一句注释隔几周就从真话变成
假话，而代码默认值、注释、跑批配置三者都照它配 —— 这是本仓同一类故障第四次复发
（2026-08-21 / 08-28 / 09 / 10 各一次）。

处置：把「谁活着」从**注释**搬到底层**探测快照**。本模块只做三件事：
  1. 落盘：`write_record()` 把一次真实探测写成 `logs/llm_probe/<时间戳>.json`；
  2. 读取：`latest_record()` 只认 **新鲜** 快照（默认 72h），过期当没有；
  3. 回答：`is_live()` / `live_providers()` —— **没有任何新鲜快照时一律回答
     「不知道＝不活」**（fail-closed），绝不因读不到记录就假设某源可用。

诚实边界（不要过度解读）
  - 快照只证明「探测那一时刻该 provider 回过 200」；不证明下一分钟还可
    用，也不代表该源的解题能力。
  - 缺失快照 ≠ 该源不可用，而是「未知」。本模块把未知一律结论化为不可用，
    因为下游用途是选源/发请求，宁可不选也不能选到死源。
  - 快照是运行时产物（`logs/` 不入库，各机各算），CI 上必然读不到 → CI 上
    live_providers() 恒为空集。这是**设计如此**：CI 不需要知道谁活着，
    它只需要保证「没人再手写一句谁活着」。

用法
----
    python scripts/_llm_pool_status.py                  # 打印最近快照 + 存活集
    python scripts/_llm_pool_status.py --json           # 机器可读
    python scripts/_llm_pool_status.py --max-age-hours 6
    python scripts/_llm_pool_status.py --require glm    # 指定源是否可用（RC=0/1）

由 `scripts/_probe_providers.py` 在每次真实探测后自动调用 write_record()。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

SCHEMA = "llm_pool_probe/v1"

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
DEFAULT_RECORD_DIR = _REPO_ROOT / "logs" / "llm_probe"

# 新鲜窗口：provider 可用性随余额/欠费/平台策略漂移，超过该时长的快照一律作废。
DEFAULT_MAX_AGE_HOURS = 72

# 文件名：YYYYmmddTHHMMSS.json（本地时间，字典序 = 时间序，避免时区歧义）
_FNAME_RE = re.compile(r"^(\d{8}T\d{6})\.json$")

# 判定「探测成功」的状态码。（由生产者写入；本模块不做网络请求）
OK_STATUS = "OK"


def record_dir() -> Path:
    """快照目录（可用 CTF_AGENT_PROBE_DIR 覆盖，便于测试隔离）。"""
    custom = os.getenv("CTF_AGENT_PROBE_DIR", "").strip()
    return Path(custom) if custom else DEFAULT_RECORD_DIR


def write_record(results, ts: datetime | None = None, source: str = "",
                 directory: Path | None = None) -> Path:
    """把一次探测结果落盘为快照，返回写出的文件路径。

    Args:
        results: 每项至少含 `provider`；`status`（OK/HTTP403/NOKEY/EXC…）决定是否存活，
            `detail`/`model` 可选，`ok` 显式给出时优先于 status 推定。
        ts: 快照时刻默认 now()。
        source: 生产者标识（写进快照，便于追溯是谁探的）。
        directory: 目标目录，默认 `record_dir()`。
    """
    directory = Path(directory) if directory is not None else record_dir()
    directory.mkdir(parents=True, exist_ok=True)
    ts = ts or datetime.now()

    providers: dict[str, dict] = {}
    for item in results or []:
        name = str(item.get("provider", "")).strip().lower()
        if not name:
            continue
        status = str(item.get("status", "") or "")
        ok = item.get("ok")
        if ok is None:
            ok = status.upper() == OK_STATUS
        providers[name] = {
            "ok": bool(ok),
            "status": status,
            "model": str(item.get("model", "") or ""),
            "detail": str(item.get("detail", "") or "")[:300],
        }

    payload = {
        "schema": SCHEMA,
        "ts": ts.isoformat(timespec="seconds"),
        "source": source,
        "max_age_hours": DEFAULT_MAX_AGE_HOURS,
        "providers": providers,
    }
    out = directory / f"{ts.strftime('%Y%m%dT%H%M%S')}.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return out


def list_records(directory: Path | None = None) -> list[Path]:
    """列出快照文件，**按时间倒序**（最近一次在前）。"""
    directory = Path(directory) if directory is not None else record_dir()
    if not directory.is_dir():
        return []
    found = []
    for p in directory.glob("*.json"):
        if _FNAME_RE.match(p.name):
            found.append(p)
    return sorted(found, key=lambda p: p.name, reverse=True)


def _record_ts(record: dict, path: Path | None = None) -> datetime | None:
    """快照时刻：优先 JSON 内 ts 字段，缺失时回退文件名时间戳。"""
    raw = str(record.get("ts", "") or "")
    if raw:
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    if path is not None:
        m = _FNAME_RE.match(path.name)
        if m:
            try:
                return datetime.strptime(m.group(1), "%Y%m%dT%H%M%S")
            except ValueError:
                return None
    return None


def latest_record(max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
                  directory: Path | None = None,
                  now: datetime | None = None) -> dict | None:
    """返回**仍在新鲜窗口内**的最近快照；没有或已过期 → None（fail-closed）。"""
    now = now or datetime.now()
    for path in list_records(directory):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - 单张快照损坏不应连带废掉其它快照
            continue
        if not isinstance(record, dict) or "providers" not in record:
            continue
        ts = _record_ts(record, path)
        if ts is None:
            continue
        if ts.tzinfo is not None:  # 归一化到 naive 本地，避免 aware/naive 相减炸
            ts = ts.replace(tzinfo=None)
        if now - ts <= timedelta(hours=max_age_hours):
            record["_path"] = str(path)
            record["_ts"] = ts
            return record
    return None


def live_providers(max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
                   directory: Path | None = None,
                   now: datetime | None = None) -> set[str]:
    """新鲜快照里判定为可用的 provider 集合；无新鲜快照 → 空集（不是「全部可用」）。"""
    record = latest_record(max_age_hours=max_age_hours, directory=directory, now=now)
    if not record:
        return set()
    providers = record.get("providers") or {}
    return {name for name, info in providers.items()
            if isinstance(info, dict) and info.get("ok")}


def is_live(provider: str, max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
            directory: Path | None = None,
            now: datetime | None = None) -> bool:
    """某 provider 在新鲜快照里是否可用。**读不到记录一律回答 False**（未知＝不可用）。"""
    name = str(provider or "").strip().lower()
    if not name:
        return False
    return name in live_providers(max_age_hours=max_age_hours, directory=directory, now=now)


def describe(record: dict | None = None,
             max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
             directory: Path | None = None,
             now: datetime | None = None) -> str:
    """人类可读摘要。刻意区分「无快照（未知）」与「有快照但全死」——两者处置相同，
    但归因完全不同：前者要先跑 `_probe_providers.py`，后者先去充值。"""
    if record is None:
        record = latest_record(max_age_hours=max_age_hours, directory=directory, now=now)
    if record is None:
        return (f"⚠️ 无 {max_age_hours}h 内的探测快照——provider 存活状态未知，"
                f"一律按不可用处理。先跑：python scripts/_probe_providers.py")
    providers = record.get("providers") or {}
    live = sorted(name for name, info in providers.items()
                  if isinstance(info, dict) and info.get("ok"))
    dead = sorted(name for name in providers if name not in live)
    ts = record.get("_ts") or _record_ts(record)
    lines = [f"快照 {ts}（来源：{record.get('source') or '未标注'}）｜新鲜窗口 {max_age_hours}h",
             f"  可用 {len(live)}: {', '.join(live) or '（无）'}",
             f"  不可用 {len(dead)}: {', '.join(dead) or '（无）'}"]
    for name in sorted(providers):
        info = providers[name] or {}
        if not info.get("ok"):
            lines.append(f"    - {name}: {info.get('status', '?')} {str(info.get('detail', ''))[:90]}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="provider 存活状态（以真探测快照为唯一真值源）")
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    ap.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS)
    ap.add_argument("--record-dir", default="")
    ap.add_argument("--require", default="", help="指定 provider 是否可用（用于脚本判定）")
    args = ap.parse_args(argv)

    directory = Path(args.record_dir) if args.record_dir else None
    record = latest_record(max_age_hours=args.max_age_hours, directory=directory)
    if args.require:
        ok = is_live(args.require, max_age_hours=args.max_age_hours, directory=directory)
        print(f"{'✅' if ok else '❌'} {args.require}: "
              + ("新鲜快照内可用" if ok else "不可用或快照缺失/过期（未知一律按不可用）"))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({
            "fresh_record": bool(record),
            "record": record,
            "live_providers": sorted(live_providers(max_age_hours=args.max_age_hours,
                                                    directory=directory)),
        }, ensure_ascii=False, indent=1, default=str))
        return 0 if record else 1
    print(describe(record, max_age_hours=args.max_age_hours, directory=directory))
    return 0 if record else 1


if __name__ == "__main__":
    sys.exit(main())
