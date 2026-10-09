# benchmarks/ —— 机器真值目录

本目录下的 JSON **全部是机器真值**（不是可再生的中间产物）：基准清单、健康基线、
provider 能力档案。每份都必须带 `schema` 字段（形如 `name/vN`），并经
`scripts/_truth_guard.py::write_truth()` 写入。

## 为什么有守卫（一次已发生的静默数据丢失）

- v1 单题探针档案与 v2 归档档案曾**共用** `provider_capability.json`，
  v2 跑一次就把 v1 的探针数据整段覆盖，工作树上无声丢数据，只在 git 历史里找得回。
- 引入守卫后审计立刻查出 `corpus_health_baseline.json` **根本没有 schema 字段**——
  一份机器真值完全不受保护。

共同形态：**同一路径被不同写入方先后使用，后跑的赢，先跑的结论无声消失**。

## 规则

1. 任何脚本**不得**直接 `write_text(benchmarks/*.json)`，必须走统一入口：
   ```python
   from _truth_guard import write_truth
   write_truth(ROOT / "benchmarks" / "xxx.json", doc,
               schema="name/vN", by="scripts/xxx.py")
   ```
2. 异构 schema 拒写；**无 schema 的既有文件也拒写**（须先人工确认来源并 `--migrate`）。
3. 同 schema 允许刷新（守卫不得退化成"冻结"），自动补 `written_at`/`written_by`/`git_head`。
4. `questions/**/*.json` 是逐题载荷、成批生成，不带 schema；其完整性由
   `python scripts/_build_external_benchmark.py --check` 负责。

## 审计与迁移

```bash
python scripts/_truth_guard.py --audit           # 报缺 schema / schema 撞车（rc=1 有发现）
python scripts/_truth_guard.py --migrate-legacy  # 列出待迁移文件
python scripts/_truth_guard.py --migrate benchmarks/x.json name/v1   # 逐个确认后迁移
```

退出码：`0` 通过 / `1` 审计有发现 / `4` 拒绝写入（专属码，与其它失败原因区分）。

## 当前真值文件

| 文件 | schema | 写入方 |
|------|--------|--------|
| `external_unseen/MANIFEST.json` | `external_unseen_benchmark/v1` | `scripts/_build_external_benchmark.py` |
| `corpus_health_baseline.json` | `corpus_health_baseline/v1` | `scripts/check_corpus_health.py` |
| `provider_capability.json` | `provider_capability_archive/v2` | `scripts/_provider_capability_archive.py` |
| `provider_probe.json` | `provider_capability/v1` | `scripts/_provider_toolcap_probe.py` |

_2026-10-10 · 维护：西湖论剑 CTF-Agent_
