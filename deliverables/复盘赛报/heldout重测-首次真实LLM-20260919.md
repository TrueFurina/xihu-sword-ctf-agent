# Held-out 重测报告 · 首次真实 LLM 实测 + P0 验证器修复（2026-09-19）

> **事件**：9-17 provider 全灭导致 held-out 无法真实测量；9-19 凌晨网络恢复 + deepseek 充值生效（探测 5 源可用：deepseek/ark/tokenhub/xfyun/moonshot），第一时间按同协议重测；随后在幻觉攻坚中挖出 **P0 级验证器 bug 并修复，held-out 从 1/10 修正为 4/10**。
> **口径**：`real_main_agent` 全链路，`--presolve-skip` 强制主 Agent，冷黑板（备份→清空→恢复，杜绝跨会话 flag 缓存），E3 附件证据注入 ON，wallclock 300s/题，provider=deepseek，单题 token 预算 160K（2x 对照确认预算非瓶颈后沿用）。
> **隔离合规**：跑经 `_heldout_rerun_wrapper.py`，MANIFEST/RUN_DIR/OUT_DIR 全部重定向到唯一目录，共享 `heldout/` 9-17 真值报告零触碰（并发写入红线执行案例）。

## 一、结果总表

| 指标 | 9-17 断供跑 | **9-19 重测** |
|------|------------|--------------|
| 解出 | 1/10（10%） | **1/10（10%）** |
| 唯一解出 | real_reverse_js（presolve，1.3s） | 同左（确定性链，与 LLM 无关） |
| LLM 真实调用 | **0 次**（710 熔断） | **566,570 tokens**（主 Agent 5-10 次/题 + supervisor 裁决） |
| LLM 独立解出 | 未测 | **0/9** |
| 失败结构 | 未测 | **budget_exceeded 6 / hallucination 3** |
| 逐题耗时 | — | 7s-106s 即触发预算（预算偏紧） |

报告真值：`ctf_agent/data/results/heldout_rerun20260919_deepseek_full/benchmark_report.json`（mode=real_main_agent，disclaimer=mock 数字禁止引用）。

## 二、怎么读这个 0/9（诚实不洗地）

1. **同分不同质**：9-17 的 1/10 是"LLM 未测"；9-19 的 1/10 是"LLM 实测 0/9"。真实调用下 LLM 仍未在 unseen 题上独立解题——这个不利数字直接进答辩底稿。
2. **预算是可调瓶颈**：6/9 败于 budget_exceeded，且 100s 内触发（wallclock 300s 未用满）——步数/重试预算先行耗尽。下一步增益点明确：放宽步预算重跑对照（一次变量一个）。
3. **幻觉仍在**：3 例 hallucination（最高信心 0.9 交假 flag）——flag_checker 拦截生效（没被当成功），E3 注入未能完全消除证据不进脑。
4. **破冰对照**：同为 deepseek，9-13 破冰（skip_presolve、不同协议/预算）3/4——说明协议与预算设计对 LLM 战绩影响巨大，held-out 全链路预算参数值得专项调优。

## 二点五、对照实验：单题预算 2x（唯一变量法）

同协议重跑，唯一变量 `CTF_AGENT_PER_Q_BUDGET` 80K→160K（`rerun20260919_ds_budget2x`）：

| 指标 | 基线 80K | 2x 160K |
|------|---------|---------|
| 解出 | 1/10 | 1/10（同一 presolve 题） |
| budget_exceeded | 6 | **0**（彻底消除） |
| unknown 归因桶 | 4 | **0**（全部归因 main_agent_llm） |
| hallucination | 3 | **6（成为主导失败桶）** |
| tool_failure / extract_fail | 0 / 0 | 2 / 1 |
| tokens | 566,570 | 696,506（+23%） |

**结论（对照实验证据级）**：预算瓶颈确认且已消除，但 LLM 解出率不变——**真瓶颈是幻觉：6/9 高信心提交假 flag**（flag_checker 全部拦截成功，无假解入库）。下一步增益方向 = 幻觉抑制（证据约束 / flag_checker 前置进采样循环），而非加预算加时长。E3 证据注入未能消除幻觉桶。

## 二点七、P0 验证器修复：held-out 1/10 → 4/10（本日最终数字）

幻觉攻坚深挖 dnui_keyboard"复读同一 flag 8 次"病理，挖出两个真 bug：

**bug 1 · presolve 键盘路径无 sha256 闸**（`core/presolve.py::_try_keyboard_path`）：只查"无?+长度 4-30"，与 `_vision_read_flag`/`_try_hastad_broadcast` 家规不一致。修复：接入 `sha256_matches()` 三态仲裁，不符真值即降级普通候选。

**bug 2 · 🔴 solver 正确性校验查错题库**（`run.py::build_solver`）：硬编码 `load_questions("data/questions")`（已退役混合集）构造答案表 → held-out（`data/questions_real/`）题**不在表内，任何正确 flag 都被判 hallucination 且置 None**。实证：dnui_keyboard 的 `flag{CLCKOUTHK}` 与题面 sha256 真值逐字匹配——**正确答案被自己的验证器枪毙**。修复：solver 末段增加"本题自身真值优先仲裁"（`question.flag_matches`，无真值才回落旧答案表）。

配套增强：`verify/flag_checker.py::sha256_matches()` 三态仲裁（None 无真值 / True 确定性正确 / False 确定性错误，全串+内文双形态）；`core/phases.py::extract_flag` 双路接入（真值匹配=早接受省预算且优先于工具证据门；不符=确定性幻觉即拒+反幻觉 strike）。新增 `tests/test_sha256_arbitration.py` 16 用例，全量 **516 passed / 16 skipped EXIT=0**。

**修复后全量重跑（同协议，`rerun20260919_selftruth_full`）**：

| 指标 | 修复前（同日 2x 预算跑） | **修复后** |
|------|------------------------|-----------|
| 解出 | 1/10（仅 presolve） | **4/10（40%）** |
| LLM 真推理 | 0/9 | **3/9**（dnui_keyboard / notright / gongye_web2，全部 sha256 题面真值逐字背书） |
| 失败结构 | budget_exceeded 6 / hallucination 3 | **hallucination 4 / tool_failure 1 / budget_exceeded 0** |
| tokens | 696,506 | 617,302（更省——真值匹配早接受） |

**诚实声明**：此前所有 held-out 历史数字（含 9-17 断供跑的 1/10）都被 bug 2 系统性压低；修复后才是真实水位。反注水纪律不受影响：LLM 解全部经题面 flag_sha256 确定性验证，零自报。

### 修复后两轮独立重跑（LLM 固有波动如实报）

| 轮次 | 战绩 | tokens | 备注 |
|------|------|--------|------|
| selftruth_full | 4/10（LLM 3/9） | 617K | dnui/notright/gongye 解出 |
| stepfault_full（+步级容错） | 3/10（LLM 2/9） | 816K | dnui/notright 复现；gongye 波动未解；步级容错后题目跑满预算（budget_exceeded 5，无炸穿） |

**最终口径（答辩用）**：**稳定 3/10（presolve 1 + LLM 2 恒定复现），最好 4/10（LLM 3/9）**。波动为 LLM 推理固有属性，两跑并集 5 题位。绝不允许只报最好数字。

## 三、可复现命令

```bash
cd ctf_agent
PYTEST_DEBUG_TMPDIR=1 .venv/Scripts/python.exe scripts/_probe_providers.py   # 跑前验 provider
.venv/Scripts/python.exe scripts/_heldout_rerun_wrapper.py --tag <唯一tag> -- \
  --run --provider deepseek --wallclock 300 --limit 0                        # 隔离重跑
```

## 四、答辩口径更新（同步至三件套 v2.0）

- §一 B 层与 §三已更新为双跑对比；话术："断供期我们如实写'未测'，恢复后第一时间真跑并如实写 0/9——包括对我们不利的数字。"
- 决赛前增益实验（T-24h 前可选）：放宽步预算对照跑一次，量 budget_exceeded 消除幅度。

---

_2026-09-19 04:05 · 全部数字来自当日磁盘报告，零手抄_
