# 西湖论剑 CTF-Agent (xihu-sword-ctf-agent)

> 第九届西湖论剑中国杭州网络安全技能大赛 · AI Agent 解题夺旗赛专项工具

一个面向 CTF 夺旗赛的 AI Agent 解题框架：以**确定性静态分析器（presolve）**为主、LLM 推理为辅，自动对历年真题/赛题做附件解析、密码学攻击、隐写提取、源码审计，并输出可复现的解题链路。

---

## ⚠️ 安全与合规声明（务必先读）

本项目**仅开源工程骨架与解题方法论**，严格遵循以下红线：

1. **真 flag 永不公开**：所有真题/赛题的真实 flag 明文均已从仓库移除，仅以 `<REDACTED>` 或 sha256 占位形式保留解题记录结构。真值文件（含明文 flag）均在 `.gitignore` 中屏蔽，不会进入版本库。
2. **密钥不入库**：LLM provider API Key、平台 Token 等一律通过环境变量 / 注册表注入，仓库内不含任何明文凭证。
3. **内部资源不公开**：真实赛事的题面内部资源、附件下载链接、签名等平台私有数据已在 `.gitignore` 屏蔽（`data/race_details/` 等）。
4. **诚实水位**：本项目真实能力 = 确定性静态分析器（presolve）的题型覆盖度，并非 LLM 自主推理能力。详见文档，勿夸大。

---

## 架构概览

```
ctf_agent/
├── core/              # 主循环、presolve 静态分析器、监督 Agent、墙钟止损
├── agents/            # 各题型求解器（crypto_toolkit / misc / web 等）
├── skills/            # 确定性解题 skill（run(params)->dict 接口）
├── llm/               # LLM 客户端（多 provider 白名单、fail-closed）
├── ctfplatform/       # 赛事平台对接（DasCTF 等）
├── sandbox/           # 代码执行沙箱（subprocess 隔离）
├── eval/              # 真题集 benchmark（诚实 KPI 度量）
├── data/questions_real/  # 历年真题题库结构（真值已占位脱敏）
├── config.py          # 配置（默认值 + 环境变量回退）
├── run.py             # 入口（--mode cli/web/mock）
└── setup.sh           # 环境初始化
```

## 解题链路

`main_agent.py` 主循环每步顶检墙钟（EASY 120s / MEDIUM 300s / HARD 600s），超时即分级止损。
`core/presolve.py` 并行跑多路确定性 skill（crypto / stego / 源码审计 / 嵌图 OCR 等），
命中即直出 flag；未命中才升级给 LLM 阶段。

## 快速开始

```bash
cd ctf_agent
bash setup.sh                      # 装依赖 + 预检 + 跑测试
export CTF_AGENT_LLM_PROVIDER=deepseek
export CTF_AGENT_LIGHT_MODEL=deepseek-chat
export DEEPSEEK_API_KEY=sk-xxx     # 你的密钥，勿提交
.venv/Scripts/python.exe run.py --mode mock --category crypto   # 离线冒烟
.venv/Scripts/python.exe run.py --mode cli   # 本地刷题
```

## 诚实 KPI（真题集口径）

对 `data/questions_real/` 15 道历年真题的真实链路 benchmark：
- **确定性管线（presolve 直出）**：14/15（93.3%）
- **LLM 真推理贡献**：0/1（仅 misc LSB 隐写 vnctf_flag 待解，且该题为数据集缺陷）

即：**能力 = 静态分析器覆盖度**，不是 LLM 推理。扩展题型 = 写更多确定性 skill。

## 文档索引

- `ARCHITECTURE_PLAN.md` — 架构规划
- `MODULE_DESIGN.md` — 模块设计
- `赛前作战手册_20260821.md` — 赛前作战手册
- `项目深度锐评报告-20260821_赛前夜复审.md` — 深度锐评（诚实水位）
- `HANDOVER.md` — 交接文档

## License

[MIT](LICENSE) — 开源用于学习与研究，请遵守各 CTF 赛事规则与平台条款。
