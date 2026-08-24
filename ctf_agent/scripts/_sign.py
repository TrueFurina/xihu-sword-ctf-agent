# -*- coding: utf-8 -*-
"""会话身份：唯一 ID 生成 + 登记绑定（G2，2026-08-23）。

目标：堵住「裸字符串撞名 / 误认」。两个会话即使都叫 "gu"，init_session 也会
生成不同的唯一 id（gu-<8位hex>），租约与审计都以唯一 id 为准。

不上 ECDSA 签名——威胁模型是「会犯错的队友」而非「恶意攻击者」，唯一 ID 已足以
解决撞名；签名身份留到 G5（有真实跨组织协同需求时）。
"""
import json
import os
import secrets
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COOR_DEFAULT = os.path.join(ROOT, ".atomcode", "coordination.json")


def _load(coor_path):
    try:
        with open(coor_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _write(coor_path, doc):
    os.makedirs(os.path.dirname(coor_path), exist_ok=True)
    tmp = coor_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, coor_path)


def init_session(name: str, coor_path: str = COOR_DEFAULT) -> str:
    """生成唯一会话 id（<name>-<8位hex>）并登记到 identity 表。返回 sid。

    两次 init_session("gu") 会得到不同 sid（gu-abc12345 vs gu-9f8e7d6c），
    从根上杜绝「撞名」。
    """
    if not name:
        raise ValueError("name 不能为空")
    sid = f"{name}-{secrets.token_hex(4)}"
    doc = _load(coor_path) or {"version": 1, "identity": {}, "leases": {}}
    doc.setdefault("identity", {})[sid] = {
        "name": name,
        "public_key": "",  # 留空给 G5 签名
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _write(coor_path, doc)
    print(f"✅ 会话唯一 id 已登记：{sid}")
    return sid


def resolve_session(coor_path: str = COOR_DEFAULT) -> str:
    """解析当前会话唯一 id：优先环境变量 CT_AGENT_SESSION，否则取 identity 表
    中最新登记的一条（单人/单会话兜底）。"""
    env = os.environ.get("CT_AGENT_SESSION", "").strip()
    if env:
        return env
    doc = _load(coor_path)
    if not doc:
        return ""
    identity = doc.get("identity", {})
    if len(identity) == 1:
        return next(iter(identity))  # 唯一登记 → 就是当前会话
    return ""


def is_registered(sid: str, coor_path: str = COOR_DEFAULT) -> bool:
    """sid 是否已在 identity 表登记。"""
    doc = _load(coor_path)
    return bool(doc and sid in doc.get("identity", {}))


def current_git_author() -> str:
    """当前 git author（user.name），空则未设置。"""
    try:
        out = subprocess.run(
            ["git", "config", "user.name"], cwd=ROOT,
            capture_output=True, text=True,
        ).stdout
        return out.strip()
    except Exception:
        return ""


def bind_author(sid: str, coor_path: str = COOR_DEFAULT) -> bool:
    """把会话唯一 id 绑定到 git commit author（仓库级 user.name / user.email）。

    堵 P1-7：让 commit author 反映 session 身份，而非所有会话共用全局 author
    （否则「协调者唯一可动 main」在 git 层不可审计、租约持有者无法映射）。

    P0-2（2026-08-24）：bind 时在 coordination.json 的 identity 表记录 bind_at
    时间戳——身份覆盖留痕，供 pre-commit ④ 判断"当前 author 是谁在何时绑的"。
    """
    if not sid:
        print("❌ 无会话 id：先 _sign.py init 或 export CT_AGENT_SESSION=<sid>")
        return False
    if not is_registered(sid, coor_path):
        print(f"⚠️ {sid} 未登记 identity 表，仍执行 bind（建议先 _sign.py init --name <名字>）")
    try:
        subprocess.run(["git", "config", "user.name", sid], cwd=ROOT, check=True)
        subprocess.run(["git", "config", "user.email", f"{sid}@local"], cwd=ROOT, check=True)
        # P0-2：bind 留痕（bind_at + bound_author），身份覆盖可审计
        doc = _load(coor_path) or {"version": 1, "identity": {}, "leases": {}}
        doc.setdefault("identity", {}).setdefault(sid, {})
        doc["identity"][sid]["bind_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        doc["identity"][sid]["bound_author"] = sid
        _write(coor_path, doc)
        print(f"✅ git author 已绑定会话：{sid}（user.name / user.email，bind_at 已留痕）")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ bind 失败：{e}")
        return False


def last_bind(sid: str, coor_path: str = COOR_DEFAULT) -> str:
    """查询会话最后一次 bind 的时间戳（identity 表 bind_at，空串 = 从未 bind）。"""
    doc = _load(coor_path)
    if not doc:
        return ""
    ident = doc.get("identity", {}).get(sid, {})
    return ident.get("bind_at", "")


def author_matches(sid: str) -> bool:
    """当前 git author 是否 == sid（用于 pre-commit 校验）。"""
    return current_git_author() == sid


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="会话唯一 ID 登记（G2）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="生成唯一 id 并登记")
    pi.add_argument("--name", required=True)
    pi.add_argument("--coor", default=COOR_DEFAULT)

    pr = sub.add_parser("resolve", help="解析当前会话唯一 id")
    pr.add_argument("--coor", default=COOR_DEFAULT)

    pb = sub.add_parser("bind", help="把会话 id 绑定到 git commit author（堵 P1-7 脱钩）")
    pb.add_argument("--session", required=True)
    pb.add_argument("--coor", default=COOR_DEFAULT)

    pl = sub.add_parser("last-bind", help="查询会话最近一次 bind 时间戳（供 pre-commit ④ 审计）")
    pl.add_argument("--session", required=True)
    pl.add_argument("--coor", default=COOR_DEFAULT)

    a = ap.parse_args()
    if a.cmd == "init":
        init_session(a.name, a.coor)
        return 0
    if a.cmd == "resolve":
        sid = resolve_session(a.coor)
        print(sid if sid else "（无登记 / 无环境变量）")
        return 0
    if a.cmd == "bind":
        return 0 if bind_author(a.session, a.coor) else 1
    if a.cmd == "last-bind":
        ts = last_bind(a.session, a.coor)
        print(ts if ts else "（从未 bind 留痕）")
        return 0
    return 2


if __name__ == "__main__":
    import sys
    sys.exit(main())
