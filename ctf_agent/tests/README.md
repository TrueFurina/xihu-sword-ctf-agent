# 测试说明（ctf_agent / tests）

## 运行

```bash
# 必须用项目内 venv 的解释器（见下方"环境坑"）
cd E:\Program\西湖论剑\ctf_agent
.venv\Scripts\python.exe -m pytest tests/ -q --timeout=60
```

- `--timeout=60` 依赖 pytest-timeout（pyproject `dev` 依赖已声明）。
  若报 `unrecognized arguments: --timeout`，先装：`pip install -e .[dev]` 或 `pip install pytest-timeout`。
- 只跑某文件：`pytest tests/test_platform_smoke.py -q`

## ⚠️ 环境坑：本机"系统 python"会吞输出（必须用 venv python）

当前 shell 环境下，**系统 python（非 .venv 的）跑任何脚本都静默无输出、退出码假 0**，
py_compile / pytest 结果不可信。验证一律使用：

```
.venv\Scripts\python.exe
```

若仍需在 Bash 工具里看输出，建议重定向到文件再读（stdout 通道偶发被吞）：

```
.venv\Scripts\python.exe -m pytest tests/ -q > out.txt 2>&1
```

## 测试文件清单（2026-08-21 P1 补强后）

| 文件 | 覆盖 |
|------|------|
| test_platform_smoke.py | dasctf 平台层：exercise-list 解析、429 退避、TTL 缓存、附件 fallback、submit_flag 外壳剥离、字段缺失健壮性 |
| test_poller_smoke.py | poller：run_forever 间隔决策（fast_interval 钳制/429 阶梯/列表失败倍增）、no-data 止损、[数据可达] 锚点、_validate_flag、_timeout_for |
| test_web_api_smoke.py | 看板 API：GET/POST /api/tasks、/api/metrics 字段完整性 |
| test_sandbox_guard.py | 沙盒安全：AST 校验、bash/cmd 命令注入拦截、zip-slip 成员校验、敏感环境变量剥离 |
| test_data_reachability_agg.py | 数据可达率聚合工具（scripts/agg_data_reachability.py）解析契约锁定 |
| 其余原有测试 | 墙钟止损 / 死锁 / RSA fallback / 数学引擎 / 报告诚实性 / eval 完整性 等 |

## 数据可达率（答辩硬证据）

poller 每题日志 `[数据可达] <id> desc=<N>字 att=<bool> endpoints=<N> has_instance=<bool>`，
聚合统计：

```bash
.venv\Scripts\python.exe scripts/agg_data_reachability.py data/results/race_20260821.log
```

- 完全可达 = 题面 desc>0 且 (有附件 或 有靶机 endpoints>0)。

### ⚠️ 口径提醒（答辩诚信分，产品官 2026-08-21 建议）

修复前日志跑出 **0 条 `[数据可达]` 行 ≠ 实测"可达率 0%"**——本质是"该指标修复前
不存在"（poller 锚点是 P0 修复后才加的）。答辩建议用**双证据组合**，避免评委质疑
"0% 是怎么测出来的"。

**修复前证据分三层标注（来源/场次必须写明，防止 50% 与 0/62 并排被问"哪个是真的"）：**

| 层 | 数据来源 | 场次 | 数字 |
|----|---------|------|------|
| ① 正式赛复盘 | data/results/race_cleanA/B_20260821*.log"累计已处理 62 题" + 平台 accepted=0 | 正式赛 | **0/62 解出（平台 accepted=0）** |
| ② 彩排/演练 | data/results/brush_log*.jsonl（70 条） | 开发彩排 | solved 35（50%）、stuck_loop 27、hallucination 4 |
| ③ 指标缺失 | 修复前日志无 `[数据可达]` 行 | 修复前 | 0 条锚点（≠ 实测 0%） |

答辩并列展示时须写"数据来源+场次"标签；①②是两套口径，不可混用。
**修复后聚合**：`scripts/agg_data_reachability.py` 产出 X%（真实场次或决赛彩排日志）。

口径：修复前 = "数据链路缺失导致 0 解出（正式赛）/ 演练 50%"；修复后 = "数据可达率 X% → 解出率 Y%"。
该项产出依赖平台 token + 一次实跑，列入决赛冲刺清单（QA/产品官协作）。
