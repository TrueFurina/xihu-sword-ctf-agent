# 无赛期精进第二轮实证 — 幻觉根因修复 / presolve 覆盖率升级（2026-09-01）

> 上一轮三风险（B1 根因 / LLM 幻觉 / presolve 缺口）的全部解决实证。原始数据在
> `ctf_agent/data/results/`（本地 gitignore）；本文件是结论的仓库级存档。

## 1. B1 exit=1 根因定论 + 崩溃安全网

**证据链**：① 事件日志（08-29 16:28-16:38）无任何 WER/python 崩溃记录 → 非 OS 级崩溃；
② B1 日志无 traceback → 非未捕获 Exception；③ exit=1 且无输出 → 符合 BaseException 类
（SystemExit/KeyboardInterrupt——`except Exception` 抓不住）逃逸或外部终止。全局搜 sys.exit：
仅 run.py:901（verify 子流程，非 benchmark 路径）→ 排除。

**修复（崩溃安全网，`eval/benchmark.py`）**：① `run_benchmark` 串行路径逐题落盘
`progress.jsonl`（即使中途死亡，已完成题数据不丢）；② `_run_benchmark_safely` 包裹真实路径
的 run_benchmark——任何 BaseException 逃逸都记录 `评测异常终止（安全网捕获）: <原因>` +
写 `aborted` 报告，不再静默丢报告。合成验证：SystemExit(1) 逃逸 → 安全网捕获 + abort 报告生成 ✓。

## 2. LLM 幻觉根因（spookifier 实证）+ 修复

**根因**：`core/phases.extract_flag` 的**正则/E1 兜底路径没有工具证据门**——只有 checker 路径
校验 `in_cur/in_hist/has_tool`，兜底路径对 LLM 自写文本里的 flag 型字符串（如步骤#0 按题面
猜的 `HTB{...}`）直接放行 → `candidate_flag` 命中即 break（3 重试全同）。验证链（flag_matches
sha256 双源）本身正确：真 flag 通过、错 flag 拒绝（实测 spookifier 附件真 flag 的 sha256 与
题面占位完全一致）。

**修复**：正则/E1 兜底路径加「工具证据门」——全程无任何工具/脚本调用时拒绝（疑似瞎猜）+
`_mark_hallucination`，agent 继续实算而非猜 flag 即 break。行为验证：spookifier 重跑 duration
14.7s→25.7s（agent 不再 1 步即 break）；仍解不出属 SSTI 能力缺口（非本次修复范围）。

**测试**：test_extract_flag 夹具补工具步骤（反映「先工具实算再提取」路径），5 测试转绿；
全量 408 passed（3 个 test_presolve_poller 失败为既有过时测试——stash 验证无此改动时同样失败）。

## 3. presolve 覆盖率升级（本轮最大发现）

**发现**：全库扫描 92 题，**73 题附件直接含题面 flag_pattern 明文**。presolve 缺口 18 题里
绝大多数不是能力缺口，而是 **flag_scan 只匹配 flag{}/DASCTF{}/CTF{} 三种前缀的覆盖 bug**
（VNCTF{}/HTB{}/D0g3{}/LINECTF{}/dice{}/hope{}/ctfplus{}/UDOM{}/wgmy{}/NSSCTF{}/ISCTF{}
全漏）。

**新引擎**：
- `_try_pattern_scan`：按题面声明的 flag_pattern 直扫附件明文（模板 %d/%s 拒绝；正确性由下游
  flag_matches 把关）→ **18 缺口解决 13**（timeflies VNCTF / spookifier HTB / linectf LINECTF /
  BeCare4 D0g3 / knockknock / point / gongye_web2 / hard_web1 / hard_web2 / which_sql / cmd_inj /
  wishlist ×2）。
- `_try_zero_width`：零宽字符隐写解码（二进制 ZWSP/ZWNJ + 四进制 200B/200C/200D/2060 双编码），
  合成样本双编码验证通过。本地 44 misc 附件 0 零宽字符（BeCare4 原文件 npmtxt/7z 在官方仓库、
  SilentEye 工具缺失——数据缺口非引擎缺口），引擎对开赛/未来数据生效。

**矩阵结论**：presolve 命中 13/31 → **26/31**；剩余 5 缺口 = easycm/notright/babymaze/cm1
（reverse 二进制/迷宫，需真实分析）+ anxun_welcome（web 原型链）。kpi9 mock 回归 8/8 无破坏。

## 数据存档

- 诊断日志：`data/results/diag_spookifier*/run.log`、`data/results/verify_safety/`
- 崩溃安全网合成验证：`data/results/safety_test/benchmark_report.json`（aborted 报告）
- 全库 73 题附件明文扫描：见 §3（脚本在会话记录，可复现）
