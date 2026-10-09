# 外部未见题基准（external_unseen）

**这是什么**：从本项目多个外部题池中，用机器规则筛出的「载荷完整 + 无答案泄漏 + 真值可机器判定 +
本项目未解出」的题目集合。它是**目前唯一能诚实回答"模型在外部真题上能解多少"的分母**。

## 口径红线（引用前必读）

1. **不含明文答案**：每题只有 `flag_sha256` 占位（`flag` 字段承载 64 位 sha256 占位）。
2. **"未见"是机器判定的**：排除依据 = KPI 授权台账 + 已解出 ledger + 历史跑批 `solved` 记录。
   因此**任何一轮跑批解出后，下次重建会自动把它剔除**（分母会变小，这是正确行为，不是 bug）。
3. **不可与其他口径相加**：KPI 台账的 held-out 2 题、10-06 交付给 SecAutoMind 的 80 题基准、
   本基准——题池、分母、provider 均不同，禁止合并或并列比较。
4. **跑批前先验 provider，跑批后验结果有效性**：
   - `python scripts/_run_validity_guard.py --provider-check <name>`（不健康 rc=3，禁止开跑）
   - `python scripts/_run_validity_guard.py --results-dir <dir>`（污染超阈值 rc=2，解出率不可引用）
5. **确定性兜底与 LLM 能力必须分开报**：本引擎有"放弃前确定性兜底"，会把引擎解出率抬高数倍。

## 用法

```bash
# 重建（源池变动或跑批解出新题后）
python scripts/_build_external_benchmark.py
# 校验（CI 用；退出码 1 = 清单与磁盘不一致/载荷缺失/真值非法）
python scripts/_build_external_benchmark.py --check
# 跑盲测（纯 LLM 口径）
CTF_AGENT_INTERNAL_PRESOLVE=off CTF_AGENT_E3=1 CTF_AGENT_PER_Q_BUDGET=80000 \
  .venv/Scripts/python.exe -m eval.benchmark --questions-dir benchmarks/external_unseen/questions \
  --presolve-skip --provider <name> --wallclock 300 --results-dir data/results/<tag> --limit 0
# 跑完立刻验有效性
python scripts/_run_validity_guard.py --results-dir data/results/<tag>
```

## 现状（见 MANIFEST.json 的机器真值）

- 题数与题型分布以 `MANIFEST.json` 为准（含生成时间、git HEAD、排除统计）。
- 选池规则与逐条排除原因都在 MANIFEST 里，可复算。

_2026-10-10 · 维护：西湖论剑 CTF-Agent_
