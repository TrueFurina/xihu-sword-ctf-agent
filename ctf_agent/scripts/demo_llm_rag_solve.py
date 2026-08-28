"""⛔ RED-LINE QUARANTINE — NON-GENUINE DEMO（已严格纠正 2026-08-27）。

历史：本文件原版本（并行「真题库重建」自动化 2026-08-27 提交 5ba40da）明文硬编码了
real_crypto_10733 的真 flag（DASCTF{rabbits6sc5mpl8...}）与 n/HINT/C 参数，并把完整解法推导
直接写进 prompt 喂给 LLM，再以硬编码 EXPECTED 自比「✓ 真实验证通过」。这违反本项目 RDD 红线
（真实工具扩展非提示词空转 / 禁止泄露式假验证），据此宣称的「LLM 推理贡献从 0 突破」不实。

本修正版（严格纠正）：
  - 移除全部预植答案（无 EXPECTED）与泄露参数（无硬编码 n/HINT/C）；
  - 题目参数必须来自真实题面 JSON（--problem），绝不预植于脚本；
  - 仅保留 RAG 检索 + LLM 代码生成 + 执行展示结构；
  - 正确性验证必须经 gitignored 真值库 sha256 在独立脚本中核对，本文件不做任何「验证通过」声称。

用法（genuine 模式，需真实题面参数在盘）：
  python scripts/demo_llm_rag_solve.py --problem data/questions_real/crypto/<id>.json
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from knowledge.reason_with_rag import reason_with_rag, extract_code  # noqa: E402


def load_problem(path: str):
    """从真实题面 JSON 取参数（绝不预植）。返回 (prompt, flag_sha256)。"""
    with open(path, encoding="utf-8") as f:
        q = json.load(f)
    prompt = q.get("prompt") or q.get("description") or q.get("statement") or ""
    if not prompt:
        raise ValueError(f"题面 {path} 无 prompt/description 字段，无法 genuine 加载")
    return prompt, q.get("flag_sha256")


def main() -> bool:
    ap = argparse.ArgumentParser()
    ap.add_argument("--problem", help="真实题面 JSON 路径（参数须来自此处，不可预植）")
    args = ap.parse_args()
    if not args.problem:
        print("⛔ 必须提供 --problem <真实题面JSON>；本 demo 不预植任何答案或参数。")
        return False
    try:
        prompt, expected_sha = load_problem(args.problem)
    except (OSError, ValueError) as e:
        print("✗ 题面加载失败：", e)
        return False

    print("=== [1] RAG 检索 + LLM 推理 ===")
    resp, docs = reason_with_rag(prompt, k=3, llm_client=None, load_skills=True)
    print("检索到的 writeup：", [d["id"] for d in docs])
    code = extract_code(resp)
    print("\n=== [2] LLM 产出脚本（前 1500 字）===")
    print(code[:1500])

    if not code:
        print("✗ LLM 未产出可执行代码")
        return False

    print("\n=== [3] 执行脚本（仅展示输出，不做预植答案比对）===")
    try:
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=180,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
    except subprocess.TimeoutExpired:
        print("✗ 执行超时")
        return False
    if out.returncode != 0:
        print("✗ 执行失败：", out.stderr[-800:])
        return False

    m = re.search(r"(flag|DASCTF)\{[^}]*\}", out.stdout)
    flag = m.group(0) if m else None
    print("脚本输出 flag（仅展示）：", flag)
    if expected_sha:
        print(f"⚠️ 真值 sha256={expected_sha[:16]}…；genuine 验证须在独立脚本中以 "
              f"sha256(flag) 核对，本 demo 不做『验证通过』声称。")
    else:
        print("⚠️ 本题面无 flag_sha256，无法做 genuine 验证；本 demo 仅展示 RAG+LLM 结构。")
    return True


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
