---
name: session-boot
description: 西湖论剑 CTF-Agent 会话启动标准流程（三铁律第 3 条：启动命令即门禁）；触发词：开工、启动会话、session boot、开工门禁
---
# 会话启动 SOP

## 开工固定顺序
1. 读根 `AGENTS.md` + `ctf_agent/AGENTS.md`（先读后写，强制）
2. 读 `plans/current.md`，总结当前进度，等用户下令
3. 在 `ctf_agent/` 内执行：`python scripts/_session_boot.py`
   - 不过四查（车道分支/身份/工作树/.venv）就换车道，不绕过
4. 会话结束前：更新 `plans/current.md`（已完成项 + 新理解任务）

## 分支纪律
- 任务分支命名 `w/<任务名>`（车道分支）
- commit 格式：`类型(范围): 描述 [无任务:治理]` 参照 git log 既有风格

## 收尾检查
- [ ] 产出全部落进对应子目录（无根级平铺）
- [ ] 叙事结论全部附带可复现命令 + 工件路径
- [ ] plans/current.md 已更新
