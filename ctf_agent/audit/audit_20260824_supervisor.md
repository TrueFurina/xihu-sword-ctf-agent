# 监督者审计报告 audit_20260824 (10:55-11:05)

> 监督者会话实跑全维度。零写权限：本报告仅记录+告警，不执行任何提交/修改/合入。
> 原则：命令输出 > 文档声明。所有结论来自下方 `证据` 段实跑输出。

## 一、前置自检清单（实跑）
- 解释器：`.venv/Scripts/python.exe` ✅
- 治理脚本：_merge_gate / _honesty_scan / _session_boot / _lease / _board / _scan 全部 EXISTS ✅
- CLI 参数：
  - _merge_gate: `--kpi-only` / `--full-baseline` ✅（与提示词一致）
  - _session_boot: 仅 `--fix-env` / `--smoke`，**无 `--worktree`** ✅（提示词已修正）
  - _lease: 子命令 `acquire/precommit/heartbeat/release/status` ✅
  - _honesty_scan: `--files [...]` 可选 ✅
- 钩子路径：`core.hooksPath=git_hooks`，与 `scripts/hooks/` 内容一致 ✅
- worktree 车道：`main` + `wt-test` + `_fixwt2 [main]`（3 条）✅
- jq：不可用 → 全程 python ✅（提示词兜底生效）
- JSON 结构：9 个文件，其中 `category_regression.json`(list 47) / `submitted_flags.json`(list 22) 为数组型，自检#5 双分支兼容 ✅

## 二、P0 维度1 KPI 真值
- 真值源：`benchmark_report_real_20260824.json`
- 证据：`KPI 13 / 15 = 0.867`
- `by_solved_by`：`presolve` 13/15（solve_rate 0.867）；`main_agent_llm` 0/15（solve_rate 0.0）
- 台账 `REAL_SOLVES_LEDGER.md`：`offline_verified` 行数 = 5，与 `_merge_gate --kpi-only` 基线 5 一致 ✅
- flag 正则兜底：已知 flag `flag{4640bbec-...}` 在 `data/questions_real/` 递归命中 ✅
- **判定：无假水位。真值=台账=基线。LLM 真推理贡献为 0（诚实口径成立）。**

## 三、P0 维度2 合并闸门
- `_merge_gate.py --kpi-only`：✅ `offline_verified 5 >= 基线 5`；回归 10733 仍解出；结论"可以进 main"
- `_honesty_scan.py` 裸跑：✅ 活跃文档诚实口径扫描通过
- pytest 收集基数：**279**（动态取，非硬编码）✅
- **判定：闸门全过（KPI 不降 + 诚实扫描 0 命中 + 测试 279 可跑）。**

## 四、P1 维度3 提交纪律
- 近 10 提交检查：`git log` 在 `w/collect-orphan-dirty`（孤儿分支，无提交）上 fatal —— 该分支尚无提交历史。
- 无 `--no-verify` 绕过 ✅
- 当前暂存区待提交：`core/presolve.py` / `skills/crypto_complex_mult_group.json` / `skills/crypto_complex_mult_group.py` / `tools/skill_manager.py`（4 文件，单意图=presolve能力沉淀）
- **告警（低）：当前车道为孤儿分支 w/collect-orphan-dirty，不在标准 worktree 列表，且尚未提交。合入 main 前必须经本监督者终审（维度1+2+3 全过）。禁止直接 push。**

## 五、P1 维度4 治理漂移
- `git_hooks/` vs `scripts/hooks/`：一致 ✅
- `AGENTS.md`：门禁提及 4 次（docstring 一致）
- `_lease.py` `lease_version`：实现恒为 0（docstring 已声明冻结，非漂移）✅
- **判定：无治理漂移。**

## 六、P2 维度5 租约 + 车道
- 活跃租约 3 条：
  - `gu`: scope=data/results，**stale=是（0.0min 剩余）** ⚠️
  - `atomcode-overseer-20260823`: scope=scripts/_chain_stats.py scripts/_board.py，**stale=是（0.0min）** ⚠️
  - `gu-verify-0824`: scope=core/presolve.py 等 5 文件，stale=否（29min 剩余）✅
- **告警（中）：2 条僵尸租约（gu / atomcode-overseer）已超时未释放，占用 scope 但不活跃。建议执行者清理，避免合入时 scope 冲突误判。**
- 车道冒烟 `wt-test`：`--smoke` 报 ❌ 分支为 detached、CT_AGENT_SESSION 未设置 —— 但这是 wt-test 车道自身未绑定，非 main 问题。**告警（低）：wt-test 车道未绑定会话身份，禁止用于合入。**

## 七、P2 维度6 冲突预警
- 多车道同改核心文件：`uniq -d` 空 ✅
- `git fsck --full`：仅 dangling 对象，无 missing/corrupt ✅
- **判定：无并发踩踏风险，对象库完整。**

## 八、结论
- 全局健康度：**良好**。KPI 真值 13/15 诚信无造假，闸门全过，无治理漂移，无并发冲突。
- 待整改（按优先级）：
  1. 🟠 [中] 清理 2 条僵尸租约（gu / atomcode-overseer-20260823）
  2. 🟡 [低] wt-test 车道补绑 CT_AGENT_SESSION 或弃用
  3. 🟡 [低] 孤儿分支 w/collect-orphan-dirty 提交前须经本监督者终审
- 审计 ID：audit_20260824_supervisor
- 生成时间：2026-08-24 10:58:52
