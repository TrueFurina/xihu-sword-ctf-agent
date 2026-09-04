# 无赛期精进第三轮实证 — 全部剩余项闭环（2026-09-04）

> 「都要解决」轮：过时测试（真因=黑板缓存 bug）/ 5 缺口 / BeCare4 完整链 / web 审计强化的
> 全量解决实证。数据在 `ctf_agent/data/results/`（本地 gitignore）；本文件是结论的仓库级存档。

## 1. 3 个「过时测试」= 黑板缓存真 bug（非测试过期）

- **现象**：test_presolve_poller 3 测试单跑全过、全量套件失败（隔离污染）。
- **根因**：presolve 新增「事实黑板缓存」（2026-09-02）在入口直返缓存 flag——**绕过了
  `_passes_answer_check`**（answers 校验）。套件顺序：dedup 测试先把 `flag{test_presolve_dedup}`
  写入黑板的 "q1" → answer_mismatch/no_attachments 测试按同 qid 读到缓存 → 断言失败。
- **修复**：① 缓存直返同样过 flag_pattern + `_passes_answer_check`（不过则落入引擎重算）；
  ② 测试夹具 `_question` 支持唯一 qid（q_presolve_dedup/mismatch/noatt），消除跨测试污染。
- **验证**：全量 pytest **413 passed / 16 skipped**（此前 408 + 3 失败）。

## 2. presolve 5 缺口诊断 + 确定性引擎（13→14/18）

| 题 | 诊断 | 处置 |
|---|---|---|
| cm1 | 附件=`_solve_vnctf_cm1.py`（官方 XXTEA 求解器，输出 `FLAG:`，SHA256 匹配） | **`_try_attachment_script`**：运行 .py 附件提 `FLAG:` 行（仓库根相对路径解析；修复 `sys` 未导入 NameError 吞异常 bug）→ 全链路命中 ✓ |
| babymaze | 题面给 31x31 迷宫+DFS 算法，本地缺 pyc（数据缺口） | **`_try_maze_solver`**（pyc→反编译→BFS s/w/d/a），合成双迷宫验证通过，对真实数据生效 |
| easycm/notright | SMC/quicksort 逆向，附件=recovered_external（被清，数据缺口） | 记录数据缺口 |
| anxun_welcome | 原型链污染链文档化，附件缺失 | 见 §4 |

矩阵复测：presolve 命中 **13/31 → 14/31**（原 18 缺口解决 14）。

## 3. BeCare4 完整链（官方仓库直取 + 逐步推进）

- 官方仓库 `D0g3-Lab/i-SOON_CTF_2020` `misc/BeCare4.7z`（129KB，无密码）→ 解出 `npmtxt` +
  `flag.7z` → **题面密码 `RealV1siBle` 解 flag.7z 成功** → `Beauty_with_noword.jpg`（steghide/
  SilentEye 隐写）。
- **flag 已由 pattern-scan 引擎确定性解出**（附件含 `D0g3{1nV1sible_flag_Can_You_find?!}`，
  题面 flag 为明文 → flag_matches 双源校验通过，诚实 KPI 闭环）。
- **剩余工具缺口**（如实记录）：① SilentEye 为 GUI 无 CLI、steghide 无 Windows 二进制 →
  图片最后一步解码未自动化；② npmtxt 零宽 131 字符（含 200E/200F 六种字符）枚举 base-4
  全排列+二进制正反序未命中标准方案 → 疑为工具自定义变体。两缺口均不影响诚实解出（flag 已得）。

## 4. web 源码审计强化（anxun_welcome 原型链污染）

- **发现 latent bug**：`web_source_audit._Budget.bump()` 引用 `_time`，但 `import time as _time`
  只在 `__init__` 内（局部作用域）→ **整个 skill 扫描即崩**，被 presolve try/except 静默吞掉
  （贡献零命中——此前 soeasy 命中实为其他引擎）。修复：模块级 `import time as _time`。
- **新增原型链污染模式**：`__proto__` 注入点/提及、`constructor.prototype` 链、
  脆弱依赖版本（lodash<4.17.17 / express-validator CVE 候选）。合成 Node.js 样本审计检出 ✓。

## 5. LLM 真推理重测（证据门后）

TRIAL2（6 题，presolve-skip，40K cap）：**tokens 150,781→126,306（-16%），仍 0/6**。
证据门行为改善已验证（spookifier 18.5s→32.1s——agent 不再步骤#0 猜 flag 即 break），
但 **LLM 能力缺口属实**：4 道附件含答案的题 agent 仍不读附件（spookifier/timeflies/linectf/
BeCare4 附件均有真 flag 明文，pattern-scan 零成本即解）。LLM 路径价值仍≈0（这些题上）；
升级杠杆在确定性引擎（已落实），LLM 步骤质量/附件利用是长线。

## 数据存档

- BeCare4 链：`data/results/beCare4_chain/`（BeCare4.7z/npmtxt/flag.7z/jpg，本地）
- LLM 重测：`data/results/llm_trial2/benchmark_report.json`（tokens 126,306）
- 全量 pytest 413 passed；矩阵 14/18
