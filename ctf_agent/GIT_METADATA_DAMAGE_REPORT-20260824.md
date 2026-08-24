# Git 仓库元数据损坏事故报告（2026-08-24 13:46–13:58）

## 触发
用户指令"做好本会话最后工作"。本会话早前(12:02)执行过 `git read-tree main` + `git reset --mixed main` 把孤儿车道分支指针移到 main(985c5a2)，造成分支 ref 丢失假象。13:46 试图收尾提交时，发现灾难性状态并展开修复，过程中进一步损坏 git 元数据。

## 损坏现象（实测）
1. `git branch --show-current` = `w/research-specialcurve2-route-fix`，但 `git log` 报 "does not have any commits yet"。
2. `git status` 显示 **526 个文件全部为 `A`（新增到暂存区）**——git 把整个工程当"相对空树的新增"。
3. `git read-tree HEAD` / `git reset --mixed HEAD` 报 **"Not a valid object name HEAD"**，但 `git rev-parse HEAD` 能返回 `c8fa7f2` 完整 hash。
4. `git fsck --cache` 显示大量 **dangling commit/tree**（含本会话造的灾难 commit `0d79c1d` 及其子树）。
5. 根因定位：手动 `printf 'c8fa7f2' > .git/refs/heads/w/research-specialcurve2-route-fix` 写入的是 **7 字符短 hash**，git 解析为全零坏 ref（show-ref 报 `0000...0000 bad ref`）。改为 40 字符完整 hash 后 `git log` 恢复，但 `read-tree`/`reset`/`status` 内部解析路径仍认为 HEAD 无效 → 索引无法重建。

## 对象库完好性（关键，无数据丢失）
- 磁盘工作树所有源码完好：`core/presolve.py`(24KB)、`eval/benchmark.py`(17KB)、`skills/crypto_complex_mult_group.py`(5.7KB)、`REAL_SOLVES_LEDGER.md`(11KB)、`监督者提示词-v3-final.md`(13KB) 均在。
- `c8fa7f2` commit 对象可解析，其树含 523 文件 = 并发会话全部治理/解题提交历史（edb32d7/c8fa7f2/fa036b1/764484e 等）**完整保留在对象库**。
- `origin/w/research-specialcurve2-route-fix` = `873870f`，远程历史未受损。

## 已尝试的修复（均部分或完全失败）
- `git branch -f` / `git update-ref` → exit=0 但实际未写入（packed-refs 空，Windows ref 写入静默失败，与 11:10 日志"ref 写入结构性损坏"一致）。
- 手动 `mkdir .git/refs/heads/w` + `printf` 写文件 ref → 写成短 hash 导致坏 ref。
- 写 40 字符完整 hash → `git log` 恢复，`git show-ref` 通过，但 `read-tree`/`reset`/`status` 内部解析仍失败。
- `git reset --mixed HEAD` → 未重建索引，反而把 526 文件 staged 为 A（索引损坏加重）。

## 当前状态（截至停手）
- HEAD 文件 → `ref: refs/heads/w/research-specialcurve2-route-fix`，文件 ref 含 40 字符 `c8fa7f2` 完整 hash。
- `git rev-parse HEAD` 正常；`git log` 正常显示 c8fa7f2 历史。
- 但 `git status` 仍显示 526 个 `A`（索引未对齐 HEAD），`git read-tree HEAD` 仍报 HEAD 无效。
- 灾难 commit `0d79c1d`（全树新增孤儿）已无 tag 指向，变 dangling。

## 结论与处置建议
**本会话已停止所有 git 写操作**（继续只会制造更多 dangling 对象）。仓库工作树源码零丢失，对象库历史完整，仅 git 元数据（ref/index 解析层）损坏。

建议由协调器/用户用以下任一专业手段修复，勿在本损坏态继续 git 操作：
1. **最安全**：`git clone --mirror` 或重新 clone 干净副本，从对象库恢复分支 ref（`git update-ref refs/heads/w/research-specialcurve2-route-fix c8fa7f2` 在干净环境应生效）。
2. `git gc --prune=now` 清理 dangling 后，删除 `.git/index` 让 git 重建（`rm .git/index && git reset`，需在 ref 解析正常的环境）。
3. 若 ref 解析仍坏：检查 `.git/packed-refs` 是否损坏（当前为空文件），必要时从 `refs/remotes/origin/` 重建本地 ref。

## 诚实水位（终态，未变）
- 平台 accepted = 0（比赛结束，无开放赛事）。
- 离线核验真解 = 5（specialcurve2/fa036b1 + 10732/10733/10735/c8fa7f2 台账）。
- 真题集 15 道：13 道 presolver 静态直出，LLM 真推理 = 0/2。
- 真实短板 = LLM 推理层 + 真 flag 台账(`REAL_SOLVES_LEDGER.md`)含 6 个 DASCTF{ 明文仍被 git 跟踪（fail-closed 红线未闭环，待协调器决策）。
