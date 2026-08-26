# 西湖论剑 CTF-Agent

> 一套“确定性优先”（deterministic-first）的 CTF 多智能体解题框架。
> A deterministic-first multi-agent CTF solving framework.

## 为什么做这个

大多数“CTF 解题智能体”只是 LLM 套一层 shell——结果不可复现、不可调试、还容易夸大能力。
本项目的核心判断：CTF 里大量题型（RSA 攻击、隐写提取、源码审计、多层编码）本质是可穷举的
**确定性套路**，不该交给会幻觉的 LLM。

因此采用 **deterministic-first**：先跑静态分析层并行扇出确定性技能，只有静态分析 miss 的题
才升级给 LLM，且 LLM 调用处于白名单、token 预算、墙钟止损三重约束之后。这与“LLM-first”路线
相反，是本项目最大的设计取舍。

## 系统结构

- **presolve 静态分析层**：并行扇出 49 个确定性解题技能（crypto / misc / web / reverse / pwn + 数学推理），
  优先于任何 LLM 调用。
- **supervisor 监督者**：负责步骤预算与“工具优先”纪律，约束主 Agent 不空转、不重复同动作。
- **5 类解题 Agent**：`crypto_toolkit` / `misc_toolkit` / `web_toolkit` / `reverse` / `pwn`，各管一类题型；
  底层 `math_engine` 补数学推理。
- **fail-closed 提交闸门**：请求出错即硬失败；配套合并闸门强制“KPI 不降 + 全量 pytest”。

## 诚实水位（重要）

本项目坚持“重要数字不凭空添加”。以下为 2026-08-26 实测口径：

- 历年真题集 15 道，presolve 静态分析器直出 **14/15（86.7%）**；
- 主 Agent（LLM）真实链路求解 = **0** —— 即本系统当前能力 ≈ 静态分析器覆盖率，而非 LLM 推理能力；
- 真实赛场线上 accepted = **0**；
- 主 Agent 失败子类分布（768 条样本）：方向决策错 54.6% > 证据不进脑 23.6% >
  模型能力不足 17.2% > flag 提取失败 4.3% > 输出格式崩 0.4%。

> 实验纪律：E3（附件证据强制注入）已实现，但因真题集对“主 Agent 改进实验”缺乏统计验收面，
> 结论为 **NOT VALIDATED（无法验证，非无效）**，不谎称其灵。

## 快速开始

```bash
bash setup.sh                              # 安装依赖 + 配置
./run.py --mode mock                       # 离线冒烟演示（不需要 API key）
# 真实解题（需配置 provider 环境变量，如 OPENAI_API_KEY / DASHSCOPE_API_KEY）
python -m eval.benchmark --questions-dir data/questions_real --provider qwen
```

## 仓库结构

```
core/              主 Agent、supervisor、presolve、action_executor
agents/            5 类解题 agent + math_engine
skills/            49 个确定性解题技能（统一 run(params)->dict 接口）
tools/             flag 提取守卫、确定性链等
data/questions_real/   历年真题集（flag 字段已脱敏为 <redacted>）
tests/             单元测试 + 诚实扫描（_honesty_scan）
scripts/           release_export.py（发布脱敏自检）
AGENTS.md          多角色治理纪律（裁判分离、工件可信、启动命令即门禁）
```

## 安全与治理

- 内部赛题资源、真 flag 附件、运行日志**不随本仓发布**；`scripts/release_export.py` 在发布前做
  fail-closed 脱敏自检（零真实 flag / 零 API key 才放行）。
- 真 flag 全部脱敏为 `<redacted>` / sha256 占位；密钥只走环境变量与白名单 provider。
- 详见 `AGENTS.md`。

## 当前状态与已知局限

- reverse 工具链（Ghidra 反编译）在当前环境集成未成功，reverse 题型覆盖有限；
- 主 Agent LLM 推理能力仍接近 0，扩题型主要靠写更多确定性技能；
- 欢迎提 issue / PR 改进（治理纪律见 `AGENTS.md`）。

## License

MIT — 张敏杰 (truefurina), 2026.
