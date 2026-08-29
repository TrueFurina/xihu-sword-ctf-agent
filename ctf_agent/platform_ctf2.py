# -*- coding: utf-8 -*-
"""CTF² 平台适配器（ctf2.dasctf.com——BUUCTF 迁移题库）

用法：
    export CTF2_TOKEN="<Authorization Bearer token>"
    export CTF2_PRACTICE="b9bbb32f-f186-458f-b90b-12440c0f6aea"  # BUUCTF 练习场

    from platform_ctf2 import fetch_challenges, fetch_challenge, download_attachment, submit_flag
    chs = fetch_challenges(PRACTICE, page=1)          # 题目列表
    detail = fetch_challenge(PRACTICE, chs[0]["id"])  # 题目详情
    download_attachment(detail["files"][0]["download_url"], "out.zip")  # 附件
    submit_flag(PRACTICE, chs[0]["id"], "flag{...}") # 提交

API 结构（2026-08-29 实测）：
    GET  /api/v1/practice/{pid}/challenges/?page=N&page_size=20  题目列表（data.results）
    GET  /api/v1/practice/{pid}/challenges/{cid}/               题目详情（data：name/category/files）
    POST /api/v1/practice/{pid}/challenges/{cid}/submit/        body {"flag": "..."}
    认证：Authorization: Bearer <JWT>（登录后从请求头提取，exp 约 7 天）
注意：文件名避免用 platform/（Python 标准库 module 名冲突）。
"""
import json
import os
import urllib.request

API = "https://ctf2.dasctf.com/api/v1"
TOKEN = os.environ.get("CTF2_TOKEN", "")


def _req(method: str, path: str, body: dict = None, timeout: int = 20) -> dict:
    """带认证调 CTF² API（返回解包后的 JSON）。"""
    url = f"{API}{path}"
    headers = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_challenges(practice_id: str, page: int = 1, page_size: int = 20) -> list:
    """题目列表——返回 [{id, name, category, score, solve_count, ...}]。

    2026-08-29 实测：列表 API 返回 {data: {categories, data: [...], pagination}, success}——
    题目列表在 data.data（嵌套字段），非 results/items。
    """
    d = _req("GET", f"/practice/{practice_id}/challenges/?page={page}&page_size={page_size}")
    data = d.get("data") or {}
    return data.get("data") or []


def fetch_challenge(practice_id: str, challenge_id: str) -> dict:
    """题目详情——{name, category, description, files, ...}。"""
    d = _req("GET", f"/practice/{practice_id}/challenges/{challenge_id}/")
    return d.get("data") or {}


def download_attachment(url: str, out_path: str) -> str:
    """下载附件（ctf2-files.dasctf.com 直链）到本地。"""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def submit_flag(practice_id: str, challenge_id: str, flag: str) -> dict:
    """提交 flag——返回提交接口响应。"""
    return _req("POST", f"/practice/{practice_id}/challenges/{challenge_id}/submit/", {"flag": flag})
