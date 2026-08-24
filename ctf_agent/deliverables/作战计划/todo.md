# 🎯 西湖论剑 CTF-Agent · 决赛备战清单（v3.0 赛后重置）

> **状态**：初赛（8/21）已结束，进入决赛备战期（晋级名单 8/31 前，决赛 9 月底前）。
> **诚实水位**：真实 LLM 解题 ≈17%（初赛实测）；工具链离线 100%（本地图库 15/15，内容嗅探，非 LLM）。口径详见 `ctf_agent/data/results/诚实水位声明.md`。
> **测试基线**：178 passed, 3 skipped。

---

## 一、初赛复盘结论（详见 data/results/初赛64题0解出失败复盘-20260821.md）

- [x] 复盘完成：主要瓶颈是 LLM 推理决策质量与赛题交互（Web/多步链），不是工具链
- [x] 数据集去污：`answer_disclosed` 标记 + `data/answers/` 目录隔离 + 路径级护栏（tests/test_eval_integrity.py）
- [x] 提示词去泄漏：goal_directive 规则中删除了硬编码答案（js_secret_2026 等）
- [x] 卡死快速放弃：stuck_count≥4 触发放弃，不再空耗
- [x] 单题墙钟：300s（easy 120s）硬限
- [x] 工具链嗅探修复：Brainfuck 无循环程序漏判（misc-005）→ 15/15

## 二、决赛冲刺主线（按优先级）

### P0 — 提升真实 LLM 解出率（当前 17%，目标 ≥40%）
- [ ] 用初赛真题（已在 data/race_extract）建回归集，逐题跑主 Agent 全链路，记录失败模式分类（决策错 / 工具调用错 / 超时 / 提取错）
- [ ] 按失败模式改 prompts.py / phases.py，每次改动后真题回归（不跑 mock）
- [ ] Web 交互题：web_target_interact / web_source_audit 链路实测补强
- [ ] Reverse/Pwn 题型链路从"占位"升级为"可跑"（决赛可能考）

### P1 — 稳定性
- [ ] 全量 pytest 保持绿色（当前 178 passed）
- [ ] 沙盒超时/取消路径压力测试（长跑 2h 无泄漏）
- [ ] 平台 API 对接复核（dasctf.py / poller.py，决赛平台如有变更需适配）

### P2 — 答辩材料
- [ ] 赛后答辩材料.md 按诚实水位口径重写（禁止引用 mock 数字）
- [ ] 深刻评测报告 v2 补充本轮整改证据链

## 三、禁止事项（历史教训）

1. ❌ 任何报告引用 `--mock` 数字当战绩
2. ❌ 题库附件里出现明文 flag（有测试护栏，勿绕过）
3. ❌ 提示词里写任何具体题目答案
4. ❌ 一次性脚本散落 ctf_agent 顶层（归档到 scripts/analysis/）
