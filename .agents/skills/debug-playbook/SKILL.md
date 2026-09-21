---
name: debug-playbook
description: 西湖论剑 CTF-Agent 排障流程：会话启动门禁失败、闸门拦截、429 限流、pytest 失败的排查路径；触发词：排障、门禁失败、429、闸门拦截、排查
---
# 排障手册 — 西湖论剑 CTF-Agent

## 1. 会话启动门禁失败（_session_boot.py）
按四查顺序定位：
- 车道分支不对 → 切到 w/* 分支（`git checkout -b w/<任务名>`）
- 身份缺失 → 设 `CT_AGENT_SESSION` 环境变量
- 工作树脏 → 先提交或 stash，门禁要求干净
- .venv 缺失 → 跑 `setup.sh`

## 2. 合并闸门拦截（_merge_gate.py）
- KPI 不降断言失败 → 先跑 `count_offline_verified` 看计数变化，不许手工改 JSON
- 全量 pytest 失败 → 读失败用例，修代码不修断言（铁律：不许删测试）

## 3. LLM 请求 429/瞬时超时
- 已内置有界指数退避重试（efa3572）
- 若仍失败：检查 provider 配额（baidu/qwen），不要在会话里硬刷

## 4. 结构守卫拦截（_structure_guard.py pre-commit）
- 根级平铺文件被拒 → 移到对应子目录（对表 AGENTS.md 第 1 节目录分类）
- 白名单以 `ROOT_ALLOW` 为唯一真值，不绕过 hook

## 5. 诚实水位告警（_honesty_scan.py）
- 出现"已验证/已修复"但无工件 → 补可复现命令 + 落盘输出，否则结论记 0 分
