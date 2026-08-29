"""⚠️ 历史一次性修复脚本（2026-08-22 已执行）——仅保留作考古参考，不要重跑。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isfile(os.path.join(ROOT, "core", "presolve.py")):
    sys.exit("历史修复脚本，仅在ctf_agent根目录下有意义，已不建议重跑")


def edit(path, old, new, occ=1):
    full = ROOT + "\\" + path
    with open(full, "r", encoding="utf-8", newline="") as f:
        raw = f.read()
    nl = "\r\n" if "\r\n" in raw else "\n"
    content = raw.replace("\r\n", "\n")
    cnt = content.count(old)
    if cnt != occ:
        raise SystemExit(f"FAIL {path}: 期望 {occ} 实际 {cnt}")
    content = content.replace(old, new)
    with open(full, "w", encoding="utf-8", newline="") as f:
        f.write(content.replace("\n", nl))
    print(f"OK {path} x{occ}")


# presolve: gather → as_completed + cancel（保留短路语义）
edit(
    "core/presolve.py",
    '''    # 并发预扫（2026-08-22 锐评整改：6 路确定性嗅探一次性并发，最短解题时延=各路最大值而非求和）
    # 顺序不再决定优先级——任一路命中且通过答案校验即返回。
    _presolve_tasks = [
        _try_flag_scan(question, registry),
        _try_crypto_auto(question, registry),
        _try_math_engine(question),
        _try_fast_solve(question),
        _try_jpeg_png_embedded(question),
        _try_desc_answer(question),
    ]
    _presolve_results = await asyncio.gather(*_presolve_tasks, return_exceptions=True)
    for _r in _presolve_results:
        if isinstance(_r, Exception):
            logger.debug("[presolve] 并发嗅探异常: %s", _r)
            continue
        if _r and _passes_answer_check(question, _r, answers):
            return _r
    return None''',
    '''    # 并发预扫（2026-08-22 锐评整改：6 路确定性嗅探并发启动，先完成且通过答案校验者即返回，
    # 其余立即取消——既拿并发最低时延，又保留「命中即短路、不冗余烧墙钟」语义）
    _tasks = [
        asyncio.ensure_future(_try_flag_scan(question, registry)),
        asyncio.ensure_future(_try_crypto_auto(question, registry)),
        asyncio.ensure_future(_try_math_engine(question)),
        asyncio.ensure_future(_try_fast_solve(question)),
        asyncio.ensure_future(_try_jpeg_png_embedded(question)),
        asyncio.ensure_future(_try_desc_answer(question)),
    ]
    try:
        for _fut in asyncio.as_completed(_tasks):
            try:
                _r = await _fut
            except Exception as _e:
                logger.debug("[presolve] 并发嗅探异常: %s", _e)
                continue
            if _r and _passes_answer_check(question, _r, answers):
                return _r
        return None
    finally:
        for _fut in _tasks:
            if not _fut.done():
                _fut.cancel()''',
)

# 测试断言：并发 + 短路契约
edit(
    "tests/test_presolve_poller.py",
    '''    # flag_scan 实际嗅探：首次 1 次 + force 1 次 = 2；crypto_auto 未到（flag_scan 已命中）
    assert registry.calls["flag_scan"] == 2
    assert registry.calls["crypto_auto"] == 0''',
    '''    # 去重契约：flag_scan 实际嗅探 首次 1 次 + force 1 次 = 2（2nd 非 force 调用不重新嗅探）
    assert registry.calls["flag_scan"] == 2
    # 并发预扫 + 短路：首轮 6 路同时启动，flag_scan 命中即取消其余；crypto_auto 至多被短暂
    # 调度一次（取消前可能未及发请求），故断言 <= 1 而非旧串行契约的 == 0。
    assert registry.calls["crypto_auto"] <= 1''',
)
print("\nPRESOLVE CONCURRENCY + SHORT-CIRCUIT APPLIED")
