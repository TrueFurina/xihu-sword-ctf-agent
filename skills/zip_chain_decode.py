"""Skill: 多层嵌套 zip 文件名链解码（兼容入口，逻辑复用 zip_filename_chain_decode）。

⚠️ 本文件是薄封装：核心实现在 zip_filename_chain_decode.py（多编码探测更完整，
已实测解出 10663）。保留本入口仅为兼容：
- core/main_agent.py 的 skill 映射（"zip"/"压缩" → "zip_chain_decode"）
- 旧调用方 `run({'path': ...})` 接口

输入: params = {"path": 最外层 zip 文件路径}（兼容 "zip_path"）
输出: {'ok': True, 'flag': ..., 'chain': [...], ...}
"""

import os

try:
    from zip_filename_chain_decode import zip_filename_chain_decode as _core
except ImportError:  # 作为包导入时的路径兜底
    from skills.zip_filename_chain_decode import zip_filename_chain_decode as _core


def run(params):
    """兼容旧接口：params={'path': ...} 或 {'zip_path': ...} → 复用新版核心。"""
    path = str(params.get("path") or params.get("zip_path") or "").strip()
    if not path:
        return {"ok": False, "error": "缺少 path 参数"}
    if not os.path.exists(path):
        return {"ok": False, "error": f"zip 文件不存在: {path}"}
    return _core({"zip_path": path, "max_layers": params.get("max_layers", 200)})


def zip_filename_chain_decode(params):
    """直接转发新版核心（供按新名调用）。"""
    return _core(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="多层 zip 文件名链解码（兼容入口）")
    parser.add_argument("--zip", required=True, help="zip 附件路径")
    args = parser.parse_args()
    import json

    print(json.dumps(run({"path": args.zip}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
