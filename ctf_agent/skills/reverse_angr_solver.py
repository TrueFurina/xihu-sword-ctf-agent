"""reverse_angr_solver skill：迷宫/校验类 reverse 的 angr 符号执行求解（2026-08-30）。

来源：借鉴 reverse-skill 路由矩阵 + R1 工具优先纪律（有现成工具绝不自研）。
目标：vnctf_babymaze 等迷宫类题目（输入校验/路径求解），angr 符号执行可自动求解
路径约束——替代 LLM 手推。

⚠️ 依赖检查：本机（2026-08-30）未安装 angr（pip show angr 为空）。本 skill 在
angr 可用时执行符号求解；未安装时降级返回"依赖缺失提示 + 方法论文档"，不误报结果。

安装：pip install angr（体积较大 ~500MB，含 z3/unicorn 等）。
"""

import os


def _try_import_angr():
    """尝试导入 angr，返回 (angr_module or None, error_msg)。"""
    try:
        import angr  # noqa: F401
        return angr, None
    except ImportError as e:
        return None, f"angr 未安装：{e}（pip install angr 后可用）"


def _solve_maze_with_angr(binary_path: str, find_addrs=None, avoid_addrs=None) -> dict:
    """angr 符号执行：找从程序入口到目标地址（含 flag 校验成功路径）的输入。

    params:
        binary_path: 目标二进制
        find_addrs:  目标地址列表（校验成功/打印 flag 处）
        avoid_addrs: 避免地址列表（失败分支）
    """
    angr, err = _try_import_angr()
    if angr is None:
        return {
            "solved": False,
            "flag": None,
            "reason": f"angr 依赖缺失：{err}",
            "methodology": (
                "迷宫/校验类 angr 流程："
                "1) angr.Project(binary, auto_load_libs=False) "
                "2) 找校验成功地址（find，通常是打印 flag 的 basic block）"
                "3) p.explore(find=find_addrs, avoid=avoid_addrs) "
                "4) 取 found_state.posix.dumps(0) 为输入序列 → flag 格式拼接"
            ),
        }
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        state = proj.factory.entry_state()
        sim = proj.factory.simulation_manager(state)
        sim.explore(find=find_addrs or [], avoid=avoid_addrs or [])
        if sim.found:
            found = sim.found[0]
            inp = found.posix.dumps(0)
            return {
                "solved": True,
                "flag": inp.decode("utf-8", errors="replace"),
                "reason": f"angr 找到路径，输入 {len(inp)} 字节",
                "methodology": "angr 符号求解成功",
            }
        return {"solved": False, "flag": None, "reason": "angr 未找到可行路径",
                "methodology": "尝试 find/avoid 地址校准或加符号约束"}
    except Exception as e:  # noqa: BLE001
        return {"solved": False, "flag": None,
                "reason": f"angr 执行异常：{e}",
                "methodology": "检查二进制架构/加固，或改手动逆向"}


def run(params: dict) -> dict:
    """迷宫/校验类 reverse 符号执行求解。

    params: {'path': 二进制路径, 'find_addrs'?: 目标地址列表, 'avoid_addrs'?: 避免地址}
    """
    path = params.get("path", "")
    find = params.get("find_addrs") or []
    avoid = params.get("avoid_addrs") or []
    if not os.path.exists(path):
        return {"solved": False, "flag": None, "reason": f"文件不存在：{path}"}
    return _solve_maze_with_angr(path, find, avoid)


if __name__ == "__main__":
    # 自检：angr 未装时输出降级提示（无则加勉）
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x7fELF test")
        p = f.name
    print(run({"path": p}))
    os.unlink(p)
