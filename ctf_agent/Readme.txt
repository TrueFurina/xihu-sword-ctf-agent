西湖论剑 CTF-Agent —— 目录说明

★ 开工前必读：AGENTS.md（治理铁律，每条对应一次真实事故）
★ 赛时启动：setup.sh（建 venv/依赖/白名单/网络三查/测试门禁）
  作战：.venv/Scripts/python.exe scripts/_race_start.py --compete
  e2e：.venv/Scripts/python.exe scripts/_e2e_verify.py
  网络三查：.venv/Scripts/python.exe scripts/_net_check.py

目录：core/ 主监督Agent  agents/ 领域工具包  ctfplatform/ 平台对接
      skills/ 确定性技能库  scripts/ 作战脚本  tests/ 测试（pytest.ini 门禁）
      data/ 题库与真题资产  docs/ 架构文档
SSOT：../deliverables/产品管理总纲-20260821-赛后.md（行动项唯一权威）
总索引：../_INDEX.md
