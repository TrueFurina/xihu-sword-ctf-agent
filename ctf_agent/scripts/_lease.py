# -*- coding: utf-8 -*-
"""多会话写租约：目录级多写者租约（G1 改造，2026-08-23）。

⚠️ 退役状态（2026-08-24 阶段5/物理层落地后）：**租约已降级为「车道边界提示」**。
worktree 车道（一人一 worktree）已从物理层隔离写冲突，本模块不再承担"唯一执法锁"
职责；仅保留为 pre-commit ③ 的兼容接口（scope 提示 + 身份映射审计）与历史回归。
**不再新增功能**（fencing/lease_version 自增等声明冻结，见下）。

背景：2026-08-22 多个 AI 会话无锁并发写同一仓库，引出"单写者"铁律；
初版 _lease.py 把它实现成**全局单写者互斥锁**（coordination.json 只存一个
session 字段，任何会话持任意 scope，其他会话全被拒，并行度恒为 1×）。

G1 改造：单写者互斥锁 → **目录级多写者租约**。核心变化——
- 数据结构：coordination.json 从单 session 改为 `{version, identity, leases}`，
  其中 `leases: {session -> {scope, last_active, last_commit, ttl_min, key_id, lease_version}}`。
- acquire：做 **scope 相交判定**（scopes_conflict），本会话 scope 与其他存活租约
  scope 不相交即放行——A 持 `agents/**` 与 B 持 `skills/**` 可**并行**写。
- 双时间戳：last_active（心跳续租，判定存活）/ last_commit（提交，归因与恢复点）。
- fail-closed：无租约默认拒绝（多会话环境），单人模式由 pre-commit hook 层的
  `CT_AGENT_SINGLE=1` 放行（不经过本函数）。
- ~~fencing：lease_version 在 --force 接管时自增~~（2026-08-24 冻结：实现恒为 0，
  与 docstring 声称不符——退役后不再实现该功能，此处如实标注，消除文档-实现漂移）。

用法（命令面不变，向后兼容）：
  python scripts/_lease.py acquire --session A --scope "agents/**" "tests/**" [--ttl-min 30]
  python scripts/_lease.py precommit --session A
  python scripts/_lease.py heartbeat --session A
  python scripts/_lease.py release --session A
  python scripts/_lease.py status
  python scripts/_lease.py acquire --session B --force --reason "..." --scope "data/**"
"""
import argparse
import fnmatch
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COOR_DEFAULT = os.path.join(ROOT, ".atomcode", "coordination.json")
DEFAULT_TTL_MIN = 30
LOCK_NAME = ".coordination.lock"

# 不计入 scope 越界的路径（协调机制自身/仓库元数据）
EXEMPT = [".atomcode/", ".git/", ".gitignore"]


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lock_path(coor_path: str) -> str:
    return coor_path + LOCK_NAME


def _pid_alive(pid: int) -> bool:
    """Windows 上检查 PID 是否存活。tasklist 输出 GBK，用 errors=ignore 解码（不抛异常）。"""
    if pid <= 0:
        return True  # 无效 PID 保守视为存活
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True, timeout=5,
        )
        text = out.stdout.decode("gbk", errors="ignore")
        return "没有运行的任务" not in text and str(pid) in text
    except Exception:
        return True  # 无法确认 → 保守视为存活


def _acquire_lock(coor_path: str, timeout: float = 10.0):
    """原子创建锁文件（O_CREAT|O_EXCL）；超时返回 False。Windows 无 flock，用此法。

    2026-08-23 死锁检测：锁文件持有 PID 已死（会话崩溃/异常退出残留）→
    os.replace 原子覆盖抢占，不再等满 10s 超时。根治「coordination.lock 残留卡死」老毛病。
    """
    os.makedirs(os.path.dirname(coor_path), exist_ok=True)
    lock = _lock_path(coor_path)
    deadline = _now() + timeout
    while _now() < deadline:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return True
        except FileExistsError:
            # 死锁检测：持有 PID 已死 → 原子覆盖抢占残留锁（unlink 可能被 sandbox 拦，用 rename）
            try:
                with open(lock, encoding="utf-8") as f:
                    raw = f.read().strip()
                if raw.isdigit() and not _pid_alive(int(raw)):
                    tmp = lock + f".{os.getpid()}.tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write(str(os.getpid()))
                    os.replace(tmp, lock)
                    return True
            except Exception:
                pass
            time.sleep(0.05)
        except OSError:
            time.sleep(0.05)
    return False


def _release_lock(coor_path: str) -> None:
    try:
        os.unlink(_lock_path(coor_path))
    except OSError:
        pass


def load(coor_path: str = COOR_DEFAULT):
    try:
        with open(coor_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _new_doc() -> dict:
    return {"version": 1, "identity": {}, "leases": {}}


def _lease_ts(lease: dict) -> float:
    """取租约的最后活跃时间戳（新字段 last_active，兼容旧 last_heartbeat）。"""
    return float(lease.get("last_active", lease.get("last_heartbeat", 0)))


def is_stale(lease: dict) -> bool:
    """租约是否过期：now > last_active + ttl。"""
    return _now() > _lease_ts(lease) + float(lease.get("ttl_min", DEFAULT_TTL_MIN)) * 60


def _write(coor_path: str, doc: dict) -> None:
    os.makedirs(os.path.dirname(coor_path), exist_ok=True)
    tmp = coor_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, coor_path)


def _norm_scope(scope: str) -> str:
    """把 scope 归一化为目录前缀（用于相交判定）。'agents/**' -> 'agents/'。"""
    s = scope.rstrip("/")
    if s.endswith("**"):
        s = s[:-2].rstrip("/")
    return s + "/" if s else "/"


def scopes_conflict(a_scopes, b_scopes) -> bool:
    """两个 scope 集合是否相交（任一归一化前缀相同或互为前缀）。"""
    pa = {_norm_scope(s) for s in a_scopes}
    pb = {_norm_scope(s) for s in b_scopes}
    for x in pa:
        for y in pb:
            if x == y or x.startswith(y) or y.startswith(x):
                return True
    return False


def acquire(session: str, scopes, coor_path: str = COOR_DEFAULT,
            ttl_min: int = DEFAULT_TTL_MIN, force: bool = False,
            reason: str = "") -> bool:
    """获取目录级写租约。本会话 scope 与其他存活租约 scope 不相交即放行。"""
    if not session:
        print("❌ acquire 需要 --session")
        return False
    # 2026-08-24 闸2（锐评 P1-3/并发有序化）：TTL 上限收紧——防全域长租约堵路。
    # 协议 R1 规定 TTL 30min；gu 曾持 TTL 120min 全域 scope，其他会话被堵 → 强制上限。
    if ttl_min > DEFAULT_TTL_MIN:
        print(f"❌ acquire 拒绝：TTL {ttl_min}min 超协议上限 {DEFAULT_TTL_MIN}min"
              "（2026-08-24 闸2：防全域长租约堵路，最多 30min）")
        return False
    if not _acquire_lock(coor_path):
        print("❌ 无法获取协调锁（另一会话正在操作协调文件），稍后重试")
        return False
    try:
        doc = load(coor_path) or _new_doc()
        # 兼容旧格式：单 session 字段 → 迁移为 leases 映射（保持不丢既有租约）
        if "leases" not in doc:
            old_session = doc.get("session")
            old = dict(doc)
            doc = _new_doc()
            if old_session:
                doc["leases"][old_session] = {
                    "scope": old.get("scope", []),
                    "acquired_at": old.get("acquired_at", _iso(_now())),
                    "last_active": old.get("last_heartbeat", _now()),
                    "last_commit": old.get("last_heartbeat", _now()),
                    "ttl_min": old.get("ttl_min", ttl_min),
                    "key_id": "",
                    "lease_version": 0,
                    "takeover_note": old.get("takeover_note", ""),
                }
        leases = doc.setdefault("leases", {})
        takeover_note = ""
        # 逐一检查其他存活租约是否与本次 scope 相交
        for other in list(leases.keys()):
            if other == session:
                continue
            lease = leases[other]
            if not scopes_conflict(scopes, lease.get("scope", [])):
                continue  # 不相交 → 可并行，跳过
            if is_stale(lease):
                if force:
                    takeover_note = f"接管 {other}（stale）" + (f"，原因：{reason}" if reason else "")
                    del leases[other]  # 抢占冲突的 stale 租约
                    continue
                # 2026-08-23 系统化：stale 租约 = 死会话。按 Lease 理论（Gray & Cheriton 1989：
                # 租约到期自动失效、资源可被重新分配），正常 acquire 自动接管，无需手动 --force。
                # --force 保留给"存活但需强制接管"的罕见场景。
                takeover_note = f"接管 {other}（stale 自动）"
                del leases[other]
                continue
            # 存活且相交 → 拒绝
            print(f"❌ scope 与 {other} 冲突（存活）："
                  f"{' '.join(lease.get('scope', []))}")
            print("   等它收口（release）或确认其挂死后用 --force 接管")
            return False
        leases[session] = {
            "scope": list(scopes),
            "acquired_at": _iso(_now()),
            "last_active": _now(),
            "last_commit": _now(),
            "ttl_min": ttl_min,
            "key_id": doc.get("identity", {}).get(session, {}).get("key_id", ""),
            "lease_version": 0,
            "takeover_note": takeover_note,
        }
        _write(coor_path, doc)
        print(f"✅ 租约已授予 {session}（scope: {' '.join(scopes)}，TTL {ttl_min}min）"
              + (f"｜{takeover_note}" if takeover_note else ""))
        return True
    finally:
        _release_lock(coor_path)


def heartbeat(session: str, coor_path: str = COOR_DEFAULT) -> bool:
    """续租：更新 leases[session].last_active。"""
    doc = load(coor_path)
    if not doc or session not in doc.get("leases", {}):
        print(f"❌ 心跳拒绝：当前无 {session} 的租约")
        return False
    lease = doc["leases"][session]
    lease["last_active"] = _now()
    _write(coor_path, doc)
    print(f"💓 心跳续租（{session}）")
    return True


def release(session: str, coor_path: str = COOR_DEFAULT) -> bool:
    """释放本会话租约；leases 清空后删除整个 coordination.json。"""
    doc = load(coor_path)
    if doc and session in doc.get("leases", {}):
        del doc["leases"][session]
        if doc.get("leases"):
            _write(coor_path, doc)
        else:
            try:
                os.unlink(coor_path)
            except OSError:
                pass
        _release_lock(coor_path)  # fix: 残留锁文件会卡死下一次 acquire
        print(f"🔓 租约已释放（{session}）")
        return True
    if doc and doc.get("leases"):
        print(f"❌ 释放拒绝：无 {session} 的租约")
    else:
        print("ℹ️ 无租约可释放")
    return False


def status(coor_path: str = COOR_DEFAULT) -> None:
    doc = load(coor_path)
    if not doc or not doc.get("leases"):
        print("（无租约——单人环境或尚未 acquire）")
        return
    leases = doc.get("leases", {})
    print(f"租约数：{len(leases)}")
    for session, lease in leases.items():
        stale = is_stale(lease)
        left = float(lease.get("ttl_min", DEFAULT_TTL_MIN)) * 60 - (_now() - _lease_ts(lease))
        print(f"  {session}: scope={' '.join(lease.get('scope', []))}  "
              f"stale={'是' if stale else '否'}（剩余 {max(0, left) / 60:.1f}min）"
              f"  lease_version={lease.get('lease_version', 0)}")
        if lease.get("takeover_note"):
            print(f"    takeover: {lease['takeover_note']}")


def path_in_scope(path: str, scope: list) -> bool:
    """path 是否落在 scope 任一模式内（** 跨目录；裸目录名前缀匹配）。"""
    for s in scope:
        if s in ("", "**"):
            return True
        if fnmatch.fnmatch(path, s):
            return True
        if fnmatch.fnmatch(path, s + "/**"):
            return True
        d = s.rstrip("/")
        if path.startswith(d + "/") or (d.endswith("/") and path.startswith(d)):
            return True
    return False


def _staged_files() -> list:
    """git diff --cached --name-only -z（NUL 分隔，UTF-8 原始路径，避免中文文件名八进制转义）。

    2026-08-27 修复（质检 R3 连锁）：git 仓库根 = 父目录（`E:/Program/西湖论剑`），
    `git diff` 返回的路径相对 toplevel（带 `ctf_agent/` 前缀），而 scope 相对 ctf_agent 根
    （ROOT）——两者基准不一致会导致 lease scope 门禁误拒。此处 strip `ctf_agent/` 前缀。
    """
    out = subprocess.run(["git", "diff", "--cached", "--name-only", "-z"],
                         cwd=ROOT, capture_output=True)
    files = [p for p in out.stdout.decode("utf-8", errors="ignore").split("\0") if p.strip()]
    prefix = "ctf_agent/"
    return [p[len(prefix):] if p.startswith(prefix) else p for p in files]


def _exempt(path: str) -> bool:
    return any(path.startswith(e) for e in EXEMPT)


def precommit(session: str, coor_path: str = COOR_DEFAULT) -> bool:
    """被 pre-commit hook 调用。True=放行，False=拒绝。

    G1 fail-closed：无租约 / 本会话无租约 → 拒绝（单人模式由 hook 层 CT_AGENT_SINGLE 放行）。
    有租约 → scope 越界拦截 + 续租 last_active/last_commit。
    """
    doc = load(coor_path)
    if not doc or not doc.get("leases"):
        print("❌ lease: 无租约文件，多会话环境禁止无租约提交（先 _lease.py acquire）")
        return False
    leases = doc.get("leases", {})
    my_lease = leases.get(session)
    if not my_lease:
        print(f"❌ lease: 会话 {session} 无租约，禁止提交（先 acquire 或换会话名）")
        return False
    files = _staged_files()
    bad = [p for p in files
           if not path_in_scope(p, my_lease.get("scope", [])) and not _exempt(p)]
    if bad:
        print(f"❌ lease: 暂存文件越出 {session} 的 scope（{' '.join(my_lease.get('scope', []))}）:")
        for p in bad[:20]:
            print(f"   {p}")
        print("   处置：git restore --staged <file> 移出，或扩大 scope 重新 acquire")
        return False
    my_lease["last_active"] = _now()   # 提交即活跃心跳
    my_lease["last_commit"] = _now()
    _write(coor_path, doc)
    print(f"✅ lease: scope 内提交（{len(files)} 文件），已续租（{session}）")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="多会话写租约（目录级多写者，G1）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("acquire", help="获取目录级写租约")
    pa.add_argument("--session", required=True)
    pa.add_argument("--scope", nargs="+", required=True)
    pa.add_argument("--ttl-min", type=int, default=DEFAULT_TTL_MIN)
    pa.add_argument("--force", action="store_true", help="接管过期/冲突的 stale 租约")
    pa.add_argument("--reason", default="", help="接管原因（记录到 lease）")
    pa.add_argument("--coor", default=COOR_DEFAULT)

    pm = sub.add_parser("precommit", help="hook 调用：scope 门禁")
    pm.add_argument("--session", required=True)
    pm.add_argument("--coor", default=COOR_DEFAULT)

    ph = sub.add_parser("heartbeat", help="手动续租")
    ph.add_argument("--session", required=True)
    ph.add_argument("--coor", default=COOR_DEFAULT)

    pr = sub.add_parser("release", help="释放租约")
    pr.add_argument("--session", required=True)
    pr.add_argument("--coor", default=COOR_DEFAULT)

    ps = sub.add_parser("status", help="查看租约")
    ps.add_argument("--coor", default=COOR_DEFAULT)

    a = ap.parse_args()
    if a.cmd == "acquire":
        return 0 if acquire(a.session, a.scope, a.coor, a.ttl_min, a.force, a.reason) else 1
    if a.cmd == "precommit":
        return 0 if precommit(a.session, a.coor) else 1
    if a.cmd == "heartbeat":
        return 0 if heartbeat(a.session, a.coor) else 1
    if a.cmd == "release":
        return 0 if release(a.session, a.coor) else 1
    if a.cmd == "status":
        status(a.coor)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
