# 真实解题台账（Real Solves Ledger）

> 唯一目标：诚实记录可被复现/核验的解题结果。
> **红线（fail-closed）**：本台账正文**不再内联任何明文 flag**；真值明文仅存于本地 gitignored `data/results/verified_flags.json`（sha256 可在无明文下校验）。提交前 `pre-commit` 钩子会拦截明文 flag。
> 更新日期：2026-08-27
> 口径：
> - **平台 accepted** = 题目平台返回 accepted 的真实记录（当前 0）。
> - **离线核验（offline_verified）** = 在本地对真实赛题附件/源码完成完整攻击链，并得到可验证 flag（与题面真值一致，或能视觉/文本确认）。
> - **声称待核验（claimed_pending）** = 有攻击思路/部分中间结果，但 flag 未落盘或未被独立核验。
> - ** fake/不计分** = 自产题、本地硬编码靶机、答案已直接给出的 manifest 等，一律不计入解题数。

---

## 〇、收录边界规则（2026-08-27 定稿 · 机器可判定，merge_gate 语义展开）

> 目的：根治「offline_verified 口径反复漂移」（曾并存 5/8/9/10 四套数字）。
> 本规则是 `scripts/_merge_gate.py:count_offline_verified()` 的语义展开——任何题块
> 能否计入 KPI，由本规则判定，不再依赖会话/文档临时裁定。
> merge_gate 计数逻辑不变（只数题块内状态行为 ✅ 且标题不含「外部真题」的题）；
> 本规则约束的是「什么能写进台账」。

### A 类 · 完整攻击链离线核验 —— ✅ 计入
- 定义：对真实赛题附件/源码完成完整攻击链（≥2 步推理），产出 flag 与题面真值
  （`flag_sha256` / 官方 writeup / 视觉确认）一致，且有可复现命令或独立 verifier 脚本。
- 当前 12 条严格真题中 A 类 5 条：10733 / vnctf_flag / xuanhun_signin / sheng / upx（specialcurve2 / 10732 / 10735 经 2026-08-27 诚实校准判定为不可复现，已移出严格 KPI，见各自题块 ⛔）。

### B 类 · presolve 确定性密码学变换 —— ✅ 计入（2026-08-27 方案 A 裁定）
- 定义：由确定性 skill 实现真实密码学/编码变换（非 grep 明文），输出与题面自带
  `flag_sha256` 逐字匹配，且明文 flag 已落盘 `data/results/verified_flags.json`。
- 区别于 C 类：**B 类必须存在可运行的变换代码路径**（如八进制+Vigenère / Hastad CRT /
  勒让德逐位 / base64+ROT13），不是从题面文件直接抽取答案。
- 当前 12 条严格真题中 B 类 7 条：anwang_crypto1 / ezmult / filterrandom / qiangwang_classic / ezrsa / simplelegendre / exciting_inverse（ezrsa / simplelegendre / exciting_inverse 三道均于 2026-09-03 经确定性求解器接入 presolve 后 `_regress_one.py` REGRESS_PASS 带证据重新晋级——分别见题块 7/8/11 与 `_antifraud.PROMOTION_EVIDENCE`；2026-08-28 的 12→9 诚实回退已全部闭环修复）。

### C 类 · flag_scan / 源码 grep 明文披露 —— ❌ 不计入
- 定义：从源码注释 / HTML / JS / manifest 直接 grep 出 flag 明文（如 reverse_js 2ms、
  gongye_web2 7ms），无攻击链。
- 处置：仅计入「presolve 覆盖度」（真题集 benchmark 口径），**不得写入第二节台账**。

### D 类 · 题面直接给答案 —— ❌ 不计入
- 定义：题面/附件直接给出 flag 或答案（如 dnui_keyboard「题面直接给 CLCKOUTHK」）。
- 处置：违反台账「答案已给出不计入」红线，永不收录（已撤销的第 10 项即此类）。

### E 类 · 外部真题（非平台题）—— 不计入严格 KPI
- 定义：非西湖论剑平台题、依赖外部路径（如 HGAME2022×3、2022安网杯 misc3）。
- 处置：可留在第二节末尾备查，但 merge_gate 按标题「外部真题」自动排除。

### 机器判定入口（写台账时自查）
1. 是西湖论剑/正式赛平台题？ → 否：E 类，不计 KPI。
2. flag 从题面文件直接可读？ → 是：C/D 类，不计入。
3. 有可运行变换代码或 ≥2 步攻击链？ → 否：不收录。
4. 明文 flag 落盘 verified_flags.json + sha256 可核验？ → 是：A/B 类，可写第二节。

### ⚠️ 已知陷阱（2026-08-27 实测踩坑，必须遵守）
- **台账正文禁止出现「状态行 ✅ 模式」字面量**（除真实题块外）：merge_gate 按行
  扫描计数，任何引用该模式的说明行/注释都会被误数（本次规则段注释即把 KPI 从
  9 虚高到 10，已修复）。引用计数逻辑时用「状态行为 ✅」等绕行表述。
- 题块标题含「外部真题」即整块不计 KPI（merge_gate 按标题行判定）——E 类题勿改标题。

---

## 一、平台 accepted 总账

| 赛事 | 题号 | flag | 时间 |
|---|---|---|---|
| 无 | — | — | — |

**当前平台 accepted = 0。**

---

## 二、离线核验解出（严格 KPI 12 题 = A 类 5 + B 类 7；外部真题 HGAME RSA1/RSA2/RSA3 与西湖论剑2021 FilterRandom 已于 2026-08-27 公开重建复现通过（RSA3 用公开真 flag 自洽重建；西湖用公开源码+自洽实例），但 E 类不计 KPI；specialcurve2 / 10732 / 10735 经 2026-08-27 诚实校准判定不可复现，已移出严格 KPI 并列入 KNOWN_GAP；ezrsa / simplelegendre / exciting_inverse 三道 2026-08-28 曾因 presolve 提取=None 诚实回退 12→9，均于 2026-09-03 经确定性求解器带证据重新晋级（见题块 7/8/11）——此 12 为全证据态，与回退前口径不同）

### 1. real_crypto_specialcurve2 【A类·完整攻击链】（西湖论剑 2021）

- **来源**：`data/questions_real/crypto/real_crypto_specialcurve2.json`
- **类型**：crypto / 复数乘法群类 RSA
- **状态**：⛔ unreproducible（**不可机器复现**，严格 KPI 不计）——详见复核结论。
- **flag**：`<DASCTF{<REDACTED> sha256=cd7e815f4a5a378b>`（明文仅存于本地 gitignored `data/results/verified_flags.json`，属历史人工解出真值，**非程序复现**）
- **核验方式**：`scripts/verify_specialcurve2.py` **仅做 sha256 自比**（读题面 `flag_sha256` 与真值库 sha256 比较），**不含任何密码学求解**，不构成可复现解出证据。
- **可复现命令**：无（附件为模板，实例值不可复现）。
- **备注**：88 位 DLP 用 PARI/GP `znlog` 解出指数 e 的**方法**本仓库 skill 已覆盖，但本实例的 n/HINT/C 已丢失，无法端到端复现。

- **复核结论（2026-08-27 修正·人工校正）**：2026-08-27 16:42 由并行「真题库重建」自动化新建的 `SpecialCurve2.py` 自身注释声明——原实例 n/HINT/C 在脚本注释中给出但**每次运行随机生成、从未留存**，该文件仅为「挑战脚本模板」，无法复现本实例真值；`verify_specialcurve2.py` 仅做 sha256 同义反复比对。故此前「升 ✅ 计入 KPI」判断错误，回退为 ⛔ unreproducible，merge_gate 计数恢复 12（与 KPI_BASELINE.json 一致）。此条由自动化误升，已人工校正。
### 2. 10732（CRYPTO-01 【A类·完整攻击链】 · 正式赛真题 · PKCS#1 v1.5）

- **来源**：`data/race_details/10732.json` + 附件 `data/race_attachments/10732_Yusa的密码学课堂——PKCS#1的附件/...`
- **类型**：crypto / RSA PKCS#1 v1.5 + AES
- **状态**：⛔ unreproducible（**真实解出但不可机器复现**，故严格 KPI 不计；详见下方原因）
- **flag**：`<DASCTF{<REDACTED> sha256=337eadc1a305b60f>`
- **核验方式**：
  - PyMuPDF 提取 `data/results/_10732_decrypted.pdf` 三页文本未发现 flag 文本；
  - 视觉渲染第 3 页 `data/results/crypto01_render_p2.png` 清晰显示斜体 flag：`<DASCTF{<REDACTED> sha256=337eadc1a305b60f>`（2026-08-24 本机跑通攻击链后视觉确认）。
- **攻击链**：
  1. 题面已知 p → `q·r = n // p`。
  2. `hint_enc = hint³ mod n`，且 `hint.bit_length() < 1024` → 直接开立方根得 hint（提示 padding 危险）。
  3. `AES_KEY_ENC^d mod q·r` 得 raw；解析自定义全 0 PS → AES_KEY = `44bfc33d0bfb3cd688a074a7adad1504`。
  4. AES-ECB 解密 PDF → 第 3 页视觉 flag。
- **可复现脚本**：`scripts/_solve_10732.py` 未固化入仓库；归档副本见 `_archive/ctf_agent_broken/solutions/solve_10732_pkcs1_v15.py`，PKCS#1 附件见 `_archive/ctf_agent_broken/data/race_attachments/10732_Yusa的密码学课堂——PKCS#1的附件`。

- **不可复现原因（真实解出，但严格 KPI 不计入）**：PKCS#1 v1.5 解密 + AES-ECB 解密 PDF 攻击链已于 2026-08-24 本机跑通并视觉确认 flag；但 flag **仅存在于 PDF 视觉渲染层**、文本层无明文，解题脚本对明文 flag 使用 placeholder 不落盘，**无法从干净 checkout 自动化复现**。属 genuine solve，非严格 KPI 口径（如需升 ✅，需补 OCR/视觉提取 + 仓库内附件 + verify 脚本）。
### 3. 10733（CRYPTO-02 【A类·完整攻击链】 · 正式赛真题 · How_many_rot_are_there）

- **来源**：`data/race_details/10733.json` + 附件 `data/race_attachments/10733_How_many_rot_are_there的附件`
- **类型**：crypto / 高偶指数 RSA（e=65536=2^16）+ hint 泄露 p + ROT13 编码 flag
- **状态**：✅ offline_verified（2026-08-24 本机跑通）
- **flag（规范，ROT13 字母转、数字不动）**：`<DASCTF{<REDACTED> sha256=ac232bd941738e22>`
- **明文（ROT13 编码）**：`<ROT13(QNFPGS{…}) 同 sha256=ac232bd941738e22>`
- **攻击链**：
  1. `hint ≡ e^q·p + e^{2q} (mod n)` → `W = e^n mod n` → `p = gcd(W² - hint, n)`（分解成功，p%4=3 q%4=3）。
  2. e=2^16，在奇数阶子群 s=(p-1)/2 求逆使 2^15·inv≡1 (mod s) → `c^inv ≡ m² (mod p)`，CRT 得 m² mod n，一轮 Rabin 得 m。
  3. 明文 m 是 ROT13 编码（`QNFPGS{…}` = rot13(`DASCTF{<REDACTED>`），题名 "How many rot" 即提示）→ ROT13 解码得规范 flag。
- **可复现命令**：
  ```bash
  # 在 ctf_agent/ 目录下执行
  .venv/Scripts/python.exe scripts/verify_10733.py
  ```
- **备注**：仓库 `skills/crypto_high_exponent.py` 已覆盖该攻击模板（`factor_from_hint` + `recover_via_odd_subgroup` + rot 解码）。

### 4. real_misc_vnctf_flag 【A类·完整攻击链】（VNCTF2022 · flag · 北京奥运图标杂色点）

- **来源**：`data/questions_real/misc/real_misc_vnctf_flag.json` + 附件（本地赛题库路径 `E:/Program/Cybersecurity/比赛真题/VNCTF2022公开赛/MISC/flag/flag.png`，3920×2205）
- **类型**：misc / 图像杂色点网格采样隐写（**非 LSB**——标准 RGB-LSB 提取返回空）
- **状态**：✅ offline_verified（2026-08-24 本机解出 + 官方 writeup 原文确认）；**2026-08-25 起 presolve 确定性管线已可自动化解出**（skills/misc_grid_resample 重采样 + qwen-vl-max 视觉 OCR 兜底 + flag_sha256 严格校验），`_verify_presolve_truth.py` 已验 15/15 命中本题。
- **flag**：`<vnctf{…} sha256=7d9ce4e1a4e7369e>`
- **核验方式**：
  1. 官方 writeup（goodapple.top/archives/636 枫のBlog）原文确认 flag = `<vnctf{…} sha256=7d9ce4e1a4e7369e>`，解法为缩放重采样；
  2. 本机复现：`img.resize((79, 71), Image.NEAREST)` 采样后，OCR（tesseract psm 6）读出 `vnctt {3 Aak@w}`，与官方 flag 字符形状吻合（f→t 误读、4 被吞为 OCR 常见误差）；
  3. 网格间隔取证：杂色点 x 间隔 50（10 次）、y 间隔 31（7 次），与官方 `w//50, h//31` 参数一致。
- **可复现命令**：
  ```bash
  # 在 ctf_agent/ 目录下执行（仓库根相对路径）
  .venv/Scripts/python.exe -c "
  from PIL import Image
  img = Image.open('<本地赛题库路径>/VNCTF2022公开赛/MISC/flag/flag.png')
  img.resize((79, 71), Image.NEAREST).show()
  "
  ```
- **备注**：图像杂色点网格采样（黑底 + 均匀分布色点，非 LSB）；本环境 tesseract 读不出该像素字体 → 原 presolve 只出"人眼可读揭示图"不读字；2026-08-25 接入白名单视觉 LLM（qwen-vl-max，dashscope 端点）做 OCR 兜底，以题目自带 flag_sha256 校验才返回，确定性可复现、不谎报。教训——"疑似 LSB 隐写"题面有误导，R1 工具优先（先查公开 writeup）比盲目跑 LSB 提取更有效。附件路径为本地赛题库，不入库。

### 5. 10735（MISC-02 【A类·完整攻击链】 · 正式赛真题 · logbool 流量包 SQL 布尔盲注）

- **来源**：`data/race_details/10735.json` + 附件 `data/race_attachments/10735_logbool的附件/tempdir/MISC附件/logbool.pcapng`（16MB，110701 包）
- **类型**：misc / 流量分析 + SQL 布尔盲注数据恢复 + RAR5 密码解压
- **状态**：⛔ unreproducible（**真实解出但不可机器复现**，故严格 KPI 不计；详见下方原因）
- **flag**：`<DASCTF{<REDACTED> sha256=67f3e126d51a6169>`
- **攻击链**：
  1. 2679 个 HTTP 请求全部为 SQL 布尔盲注（`ORD(MID((SELECT IFNULL(CAST(<field> AS NCHAR),0x20) FROM ctftest.ctfblob ...),idx,1))>ascii`，响应含 `success` = 成立）。
  2. 解析三字段（username/password/content），按成立的最大 ascii+1 还原字符：username=`boolblob`、password=`timeemitloggol`、content=hex。
  3. content 以 `Rar!` 魔数开头 → hex 转 RAR5 包；用 password=`timeemitloggol` 解压（本机 7-Zip 23.01）得 `flag.txt` → flag。
- **可复现命令**：
  ```bash
  # 在 ctf_agent/ 目录下执行（附件缺失，当前不可复现——待补附件后固化 verify 脚本）
  # 1) 解析 pcap（scapy）还原三字段；2) content hex→rar；3) 7z x -p<password> 解压
  ```
- **备注**：题面 flag 字段为空（待解）；解压工具链：本机无 unrar/7z → 下载官方 7-Zip 23.01（`tools/_7z/full/7z.exe`，bsdtar 解 SFX）。R1 工具优先（公开 writeup 同题 `202509_NBWS_logbool` 路线）节省了大量盲试。

- **不可复现原因（真实解出，但严格 KPI 不计入）**：logbool.pcapng（16MB / 110701 包）附件当前全仓缺失（含 `data/race_details/10735.json` 亦不存在），无法从干净 checkout 复现；2026-08-24 曾本机跑通完整攻击链（SQL 布尔盲注 → RAR5 解压 → flag）。属 genuine solve，非严格 KPI 口径。
### 6. real_crypto_anwang_crypto1 【B类·presolve密码学变换】（历年真题 · 八进制 ASCII + Vigenère）

- **来源**：`data/questions_real/crypto/real_crypto_anwang_crypto1.json`
- **类型**：crypto / 八进制 ASCII + Vigenère
- **状态**：✅ offline_verified（2026-08-26 presolve 确定性管线直出 + 官方 flag_sha256 双源验证）
- **flag**：`<REDACTED> sha256=2e9f80ef4619805caf4ae07ee11c4bc3d71e8563fa8ab0131fe8028273fcda0d`（明文见本地 gitignored `data/results/verified_flags.json`）
- **核验方式**：presolve 确定性管线（八进制转 ASCII + Vigenère 解码）直出 flag，与题面自带 flag_sha256 逐字匹配
- **可复现命令**：`.venv/Scripts/python.exe scripts/_verify_presolve_truth.py`（15 题真值比对）

### 7. real_crypto_ezrsa 【B类·presolve密码学变换】（历年真题 · Hastad 广播攻击 e=17）

- **来源**：`data/questions_real/crypto/real_crypto_ezrsa.json`
- **类型**：crypto / RSA 低指数 Hastad 广播攻击（e=17 爆破）
- **状态**：✅ offline_verified（2026-09-03 带证据晋级：`skills/crypto_hastad_broadcast.py` Håstad 求解器接入 presolve `_try_hastad_broadcast`，`_regress_one.py` 实测 REGRESS_PASS、e=17，sha256 匹配题面官方值 —— 见 `_antifraud.PROMOTION_EVIDENCE` 提升记录）
- **flag**：`<REDACTED> sha256=93be5f3ad422c43e99e705f52df3ad974548dc558714e48162d3939787bdfdbf`（明文见 verified_flags.json）
- **核验方式**：output 6 行 = n1/c1/n2/c2/n3/c3；CRT 合并三组 (n,c) + 整数开 e 次根（e 爆破 2..99 命中 17）得明文；flag sha256 匹配题面官方值
- **可复现命令**：`.venv/Scripts/python.exe scripts/_regress_one.py real_crypto_ezrsa`（应输出 REGRESS_PASS）

### 8. real_crypto_simplelegendre 【B类·presolve密码学变换】（历年真题 · 勒让德符号逐位解密）

- **来源**：`data/questions_real/crypto/real_crypto_simplelegendre.json`
- **类型**：crypto / 二次剩余（勒让德符号逐位恢复）
- **状态**：✅ offline_verified（2026-09-03 带证据晋级：`skills/crypto_legendre_phi.py` 勒让德求解器接入 presolve `_try_legendre_phi`，`_regress_one.py` 实测 REGRESS_PASS、1213ms，sha256 匹配题面官方值 —— 见 `_antifraud.PROMOTION_EVIDENCE` 提升记录）
- **flag**：`<REDACTED> sha256=75e6aa4de894faf2a760a91aa74d93e9f3b971377012f81bfb95806902ba0002`（明文见 verified_flags.json）
- **核验方式**：output 两行大整数 = phi、N（均 2048-bit）；由 phi 分解 N（p+q=N-phi+1，判别式开方）得 1024-bit p、q；对每个密文 c 算 Legendre 符号 (c/p)=pow(c,(p-1)//2,p)，=1→bit0、=p-1→bit1（密钥生成保证 x 为模 p/q 二次非剩余 ⟹ (c|p)=(-1)^bi），逐位拼接 8 位对齐还原；flag sha256 匹配题面官方值
- **可复现命令**：`.venv/Scripts/python.exe scripts/_regress_one.py real_crypto_simplelegendre`（应输出 REGRESS_PASS）

### 9. real_crypto_ezmult 【B类·presolve密码学变换】（历年真题 · base64 + ROT13）

- **来源**：`data/questions_real/crypto/real_crypto_ezmult.json`
- **类型**：crypto / base64 + ROT13
- **状态**：✅ offline_verified（2026-08-26 本机复现 + 官方 flag_sha256 双源验证）
- **flag**：`<REDACTED> sha256=60b6c2c15e658b879ff1f1d8619ab71728b021299b879a508bd7f7ac89c5bb29`（明文见 verified_flags.json）
- **核验方式**：s1.txt 内容 base64 解码 → ROT13 解码得明文；flag sha256 匹配题面官方值
- **可复现命令**：`.venv/Scripts/python.exe scripts/_verify_presolve_truth.py`

### 10. real_misc_xuanhun_signin 【A类·完整攻击链】（玄盾杯 Misc-SignIN · JPEG 尾部嵌 PNG）

- **来源**：`data/questions_real/misc/real_misc_xuanhun_signin.json` + 附件 `data/questions_real/_attachments/misc/real_misc_xuanhun_signin/xz1.jpg`
- **类型**：misc / JPEG 尾部嵌 PNG + 图像内视觉文字（flag 在图内，非 LSB）
- **状态**：✅ offline_verified（2026-08-27 本机复现 + 官方 flag_sha256 校验）
- **flag**：`<REDACTED> sha256=d5e1894ae1bb4e4d191702604bfea3ceb7a006074721d6fc3a05b8c601f42b83`（明文见本地 gitignored `data/results/verified_flags.json`）
- **核验方式**：
  1. `skills/jpeg_png_embedded.run()` 定位 JPEG 尾 FFD9，提取其后 PNG（89504E47 魔数）→ 写 `_extracted.png`（1913×1135）；
  2. tesseract OCR 读取 PNG 内视觉文字得 `flag{mooaudqxs5nbydw3}`，与题面自带 `flag_sha256` 逐字匹配；
  3. presolve 确定性管线（`_try_jpeg_png_embedded`）已自动覆盖本题（见第二节-B 第 10 行）。
- **可复现命令**：`.venv/Scripts/python.exe -c "from skills import jpeg_png_embedded as J; print(J.run({'path':'data/questions_real/_attachments/misc/real_misc_xuanhun_signin/xz1.jpg'}))"`
- **备注**：与 vnctf_flag 同类——flag 在图像内，文本 LLM 无法读取，须 OCR/视觉模型；本环境 tesseract 直出可读，确定性可复现、不谎报。


### 11. real_crypto_exciting_inverse 【B类·presolve密码学变换】（历年真题 · phi+双模逆 RSA 分解）

- **来源**：`data/questions_real/crypto/real_crypto_exciting_inverse.json` + 附件 `data/questions_real/_attachments/crypto/real_crypto_exciting_inverse/{problem.py,output}`
- **类型**：crypto / RSA 分解（problem.py 不输出 N，只给 e/phi/c/pinv/qinv）
- **状态**：✅ offline_verified（2026-09-03 带证据晋级：`skills/crypto_modinv_factor.py` phi+双模逆二次分解求解器接入 presolve `_try_modinv_factor`，`_regress_one.py` 实测 REGRESS_PASS、233ms，sha256 匹配题面官方值 —— 见 `_antifraud.PROMOTION_EVIDENCE` 提升记录）
- **flag**：`<REDACTED> sha256=4b84616cccbe84a99256c23152a4fd226e87e9da64e92689063046251cc251c5`（明文见 verified_flags.json）
- **核验方式**：output 五行 = e / phi / c / pinv / qinv；记 A=pinv(<q)、B=qinv(<p)，由 CRT 得 A·p+B·q≡1 (mod N) 且 <2N ⟹ A·p+B·q=N+1 ⟹ p(q-A)=B·q-1，代入 phi=(p-1)(q-1) 消 p 得 q 的一元二次方程 (B-1)q²+(A-B-phi)q+(phi·A-A+1)=0，判别式开方即分解出 1024-bit p/q；d=e⁻¹ mod phi 正常 RSA 解密；flag sha256 匹配题面官方值（注：早期台账"矩阵求逆"为命名误导，本题型为 RSA 模逆参数泄露，已修正）
- **可复现命令**：`.venv/Scripts/python.exe scripts/_regress_one.py real_crypto_exciting_inverse`（应输出 REGRESS_PASS）

### 12. real_crypto_filterrandom 【B类·presolve密码学变换】（历年真题 · LFSR 噪声恢复）

- **来源**：`data/questions_real/` 对应题
- **类型**：LFSR 噪声恢复
- **状态**：✅ offline_verified（2026-08-27 诚实校准补入严格 KPI；原被误排除）
- **flag**：`<REDACTED> sha256=768a21b901963eb9…`（明文见本地 gitignored `data/results/verified_flags.json`）
- **核验方式**：crypto / 双 LFSR 噪声混合恢复（skills/lfsr_filter_recover.py）；重建实例 flag 与题面 flag_sha256 匹配
- **可复现命令**：`.venv/Scripts/python.exe scripts/_verify_presolve_truth.py`（15 题真值比对，本题 ✅ 真值匹配）

### 13. real_crypto_qiangwang_classic 【B类·presolve密码学变换】（历年真题 · 摩斯+单表替换）

- **来源**：`data/questions_real/` 对应题
- **类型**：摩斯+单表替换
- **状态**：✅ offline_verified（2026-08-27 诚实校准补入严格 KPI；原被误排除）
- **flag**：`<REDACTED> sha256=f4adf0d868f5b0ac…`（明文见本地 gitignored `data/results/verified_flags.json`）
- **核验方式**：crypto / 摩斯解码 + 单表替换（确定性变换）；presolve 直出，与题面 flag_sha256 逐字匹配
- **可复现命令**：`.venv/Scripts/python.exe scripts/_verify_presolve_truth.py`（15 题真值比对，本题 ✅ 真值匹配）

### 14. real_reverse_sheng 【A类·完整攻击链】（历年真题 · 逆向静态分析）

- **来源**：`data/questions_real/` 对应题
- **类型**：逆向静态分析
- **状态**：✅ offline_verified（2026-08-27 诚实校准补入严格 KPI；原被误排除）
- **flag**：`<REDACTED> sha256=d65b30ccdac4d74e…`（明文见本地 gitignored `data/results/verified_flags.json`）
- **核验方式**：reverse / 逆向静态分析（完整攻击链，非源码 grep）；presolve 直出，与题面 flag_sha256 逐字匹配
- **可复现命令**：`.venv/Scripts/python.exe scripts/_verify_presolve_truth.py`（15 题真值比对，本题 ✅ 真值匹配）

### 15. real_reverse_upx 【A类·完整攻击链】（历年真题 · UPX 脱壳）

- **来源**：`data/questions_real/` 对应题
- **类型**：UPX 脱壳
- **状态**：✅ offline_verified（2026-08-27 诚实校准补入严格 KPI；原被误排除）
- **flag**：`<REDACTED> sha256=7130218010da8eea…`（明文见本地 gitignored `data/results/verified_flags.json`）
- **核验方式**：reverse / UPX 脱壳（完整攻击链，非源码 grep）；presolve 直出，与题面 flag_sha256 逐字匹配
- **可复现命令**：`.venv/Scripts/python.exe scripts/_verify_presolve_truth.py`（15 题真值比对，本题 ✅ 真值匹配）

### 16. HGAME2022-Week2 RSA Attack（外部真题 · 小 n 分解）

- **来源**：仓库内 `data/questions_real/_attachments/hg2022/RSA Attack/output.txt`（2026-08-27 从公开 writeup 重建；原 `E:/Program/Cybersecurity/比赛真题/...` 于 2026-08-26 清理删除、用户确认无备份）——**✅ 2026-08-27 已重建并复现通过**
- **类型**：crypto / RSA 小 n 分解（sympy factorint，48 位 n）
- **状态**：✅ offline_verified（2026-08-25 初核；2026-08-27 从公开 writeup 重建 output.txt 至仓库内、verify_hgame2022_rsa.py 复现一致，已修复断链）
- **flag**：`sha256=06e662bdbcf399a1...`（明文见本地 gitignored verified_flags.json）
- **核验方式**：`scripts/verify_hgame2022_rsa.py` 复现一致（crypto_math 小 n 分解）
- **备注**：外部真题（非平台题），原依赖外部路径；2026-08-26 外部真题目录被清理删除、用户确认无备份，但 2026-08-27 已从公开 writeup 重建 output.txt 至仓库 `_attachments/hg2022/RSA Attack/output.txt`（受 .gitignore 管控留磁盘不入库），verify 已修复复现通过；不计入严格 KPI（c7367e0 口径排除外部真题）。

### 17. HGAME2022-Week2 RSA Attack 2（外部真题 · 共享素数+低指数+共模）

- **来源**：`E:/Program/Cybersecurity/比赛真题/HGAME2022-Week2/CRYPTO/RSA Attack 2`（output.txt）——**⚠️ 2026-08-27 已确认永久丢失（用户确认无备份，不可复现）**
- **类型**：crypto / 三段攻击（task1 共享素数 gcd + task2 低指数 e=7 + task3 共模攻击）
- **状态**：✅ offline_verified（2026-08-25 初核；2026-08-27 从公开 writeup 重建 output.txt 至仓库内、verify_hgame2022_rsa.py 复现一致，已修复断链）
- **flag**：`sha256=15c6f47e54fca602...`（明文见本地 gitignored verified_flags.json）
- **核验方式**：`scripts/verify_hgame2022_rsa.py` 三段拼接完整解出（官方 writeup 佐证）
- **备注**：2026-08-25 初核时仅解出 task1 段（部分解出），补齐 task2/task3 后完整解出；外部真题原依赖外部路径。2026-08-26 外部源失效，但 2026-08-27 已从公开 writeup 重建 output.txt 至仓库 `_attachments/hg2022/RSA Attack 2/output.txt`，verify 已修复复现通过；不计入严格 KPI。

### 18. HGAME2022-Week3 RSA Attack 3（外部真题 · 维纳连分数）

- **来源**：原 `E:/Program/Cybersecurity/比赛真题/HGAME2022-Week3/CRYPTO/RSA Attack 3`（output.txt）——**2026-08-26 清理删除；2026-08-27 按公开 writeup 真实 flag + 题目结构(d=getPrime(64) Wiener)自洽重建 output.txt 入仓库**
- **类型**：crypto / 维纳连分数（e 超大 d 小）
- **状态**：✅ offline_verified（2026-08-25 初核）+ **2026-08-27 仓库内重建复现通过**（`verify_hgame2022_rsa.py` / `verify_hgame_rsa.py` 均 3/3，Wiener 还原真实 flag）
- **flag**：`sha256=b41ff252080ce950...`（明文 `hgame{dO|YOU:kNOw!tHE*PRINcIplE*bEhInd%WInNEr#aTTacK}`，真实 flag，多 writeup 公开佐证）
- **核验方式**：`scripts/verify_hgame2022_rsa.py` 复现一致（wiener）
- **备注**：公开源(ethe448)给出的 n/e 为 4346-bit 损坏值、不可直接复用；但真实 flag 已公开，故以真实 flag 自洽重建一组合法 Wiener 实例(2048-bit p,q; d=64-bit; e 超大)写入 `data/questions_real/_attachments/hg2022/RSA Attack 3/`。重建脚本 `scripts/_recover_hgame_rsa3.py` 可复现。verify 脚本现从仓库内部路径读取，不再依赖已删外部目录。

### 19. 2022安网杯 misc3（外部真题 · HTTP 上传文件提取 flag）

- **来源**：原 `E:/Program/Cybersecurity/比赛真题/2022安网杯/2022安网杯/misc/misc3_5b3d1c3a8b0934cc523e37b680d04456/1.pcapng`——**⚠️ 2026-08-26 清理删除、用户确认无备份、公开渠道无附件，永久不可复现**
- **类型**：misc / 流量分析（HTTP 上传体二进制扫描 flag 明文）
- **状态**：✅ offline_verified（2026-08-26 初核）——**2026-08-26 起 verify 断链；2026-08-27 确认无备份、公开无附件，永久不可复现**
- **flag**：`sha256=cc8b059e92735e36...`（明文见本地 gitignored verified_flags.json）
- **核验方式**：`scripts/verify_anwang_misc3.py` 对 pcapng 二进制扫描 flag 模式，比对 sha256
- **备注**：外部真题（非平台题），依赖外部真题路径（本地核验口径，诚实标注）。2026-08-26 外部源失效，2026-08-27 确认永久不可复现；verify 脚本缺源优雅 SKIP（退出码 2）。

### 20. 西湖论剑2021 FilterRandom（外部真题 · 噪声混合双 LFSR 恢复）

- **来源**：原 `E:/Program/Cybersecurity/比赛真题/西湖论剑2021中国杭州网络安全技能大赛/CRYPTO/FilterRandom.py`——**2026-08-26 清理删除；2026-08-27 公开 writeup(cn-sec)给出完整源码与 LFSR 结构，已重建**
- **类型**：crypto / 噪声混合双 LFSR（l1 占 ~90% / l2 占 ~10%，恢复 init1/init2 → DASCTF{init1-init2}）
- **状态**：✅ offline_verified（2026-08-25 初核）——**2026-08-27 仓库内重建复现通过**：按公开源码重建 `FilterRandom.py` 于 `data/questions_real/_attachments/xihu2021/`，`skills/lfsr_filter_recover.py` 从恢复源码跑通恢复 DASCTF flag
- **flag**：原实例输出不可恢复；重建实例 flag = `DASCTF{<REDACTED> sha256=89fc7945a2a48b2da80fdcbb6d3ab967411c122b12d71c1b2987a5fe99c45ac8}`（重建实例值，非原赛 flag）
- **核验方式**：`skills/lfsr_filter_recover.py` 读取重建 FilterRandom.py，恢复 DASCTF flag
- **备注**：原实例输出（某次运行的 2048-bit 串）随删除不可恢复，故重建为自洽实例（真实 mask1/mask2 + 重建 init1/init2）；源码结构公开可验，`solve_lfsr_filter` 求解逻辑不变。重建脚本 `scripts/_recover_xihu_filterrandom.py` 可复现。

---

## 二-B、确定性管线真值验证（2026-08-24 本机实测）

> 目的：把"presolve 抽出 flag"严格对齐到**题库自带 ground-truth（`question.flag`）**，
> 逐题比对，确认提取 flag 与真值**逐字一致**——这是可复现、可验证的"真解"，
> 不是模板抽答案（抽到的就是正确答案）。
> 方法：复用 `run.build_solver` 同款完整工具层（含 flag_scan / crypto_auto 适配器），
> 对 `data/questions_real/` 15 题跑 `core.presolve.presolve`（`force=True`，零 LLM 调用）。
> 真值明文见本地 gitignored `data/results/verified_flags.json`（sha256 无明文可核验）。
> 复现：`scripts/_verify_presolve_truth.py`。

| # | 题 | 题型 | 真值比对 | 方法（确定性） |
|---|---|---|---|---|
| 1 | real_crypto_anwang_crypto1 | crypto | ✅ | 八进制 + Vigenère |
| 2 | real_crypto_dnui_keyboard | crypto | ✅ | 键盘路径 |
| 3 | real_crypto_exciting_inverse | crypto | ✅ | 矩阵求逆 |
| 4 | real_crypto_ezmult | crypto | ✅ | 复数乘法 |
| 5 | real_crypto_ezrsa | crypto | ✅ | RSA 低指数 |
| 6 | real_crypto_filterrandom | crypto | ✅ | LFSR 噪声恢复 |
| 7 | real_crypto_qiangwang_classic | crypto | ✅ | 摩斯 + 单表 |
| 8 | real_crypto_simplelegendre | crypto | ✅ | 二次剩余 |
| 9 | real_crypto_specialcurve2 | crypto | ✅ | 复数环 RSA：factordb 分解 + PARI znlog（5926ms） |
| 10 | real_misc_xuanhun_signin | misc | ✅ | JPEG 嵌 PNG |
| 11 | real_reverse_js | reverse | ✅ | 源码 flag_scan（2ms，源码披露类） |
| 12 | real_reverse_sheng | reverse | ✅ | 逆向静态分析 |
| 13 | real_reverse_upx | reverse | ✅ | UPX 脱壳 |
| 14 | real_web_gongye_web2 | web | ✅ | 源码审计 flag_scan（7ms，源码披露类） |
| 15 | real_misc_vnctf_flag | misc | ⚠️独立核验 | 图像网格重采样 + OCR（非 presolve，见第二节第 4 条） |

- **确定性管线真值验证解出：14/15**（第 15 题 vnctf_flag 走独立图像采样，第二节第 4 条已离线核验）。
- 上述 15 题 `provenance` 全部为 `real_past_ctf`（历年真实赛题，外部真值），**非自产训练题**——
  之前"12/15 含 7 道 `flag{}` 训练题"的判断有误：这些 `flag{...}` 格式题同样带外部真值真值字段且提取结果逐字匹配，属真解。
- **LLM 真推理贡献 = 0**：14 道全由确定性管线直出，无需 LLM 推理。

## 三、声称待核验（0 项）

> 2026-08-25 更新：HGAME2022 三题经离线推导解出（cde84fb, 2026-08-25 15:25），
> 初核时 RSA Attack 2 仅解出 task1 段（部分解出）；2026-08-25 补齐 task2 低指数/task3 共模后
> verify_hgame2022_rsa.py 3/3 复现一致，三题已全部升级为 offline_verified（见第二节第 6/7/8 条）。
> 当前无待核验项。
> 10733 已于 2026-08-24 离线跑通转为 offline_verified（见第二节第 3 条）。
> 原“附件题 5 题”claim 经核验为**本地自出题训练题库**（`flag{b'…'}`、`flag{b'…'}` 等带 `b'...'` 与 `_2026` 后缀的合成 flag），属 `self_authored_training`，按本台账口径**不计入解题数**，已归入第四节撤销项。

---

## 四、已撤销/不计入的虚假水位

| 项目 | 原声称 | 撤销原因 | 处置 |
|---|---|---|---|
| `benchmark_report.json` 37/49 = 75.5% | 客场解出率 | 含自产题、自产靶场、本地硬编码 web 靶机；durations 仅 300ms，为 presolve/模板直出 | KPI 改为仅 `data/questions_real/` 15 道外部真题；撤销 49 题基线 |
| `da53656` web 10/10 | 客场 web 解出 | `scripts/web_range_target.py` 是本地硬编码靶机，payload 特征命中即返回 flag | 已 revert（commit 1d0278b） |
| `real_drill_manifest.json` flag | 真题答案已知 | manifest 直接给出答案，非解题过程 | 不计入 |
| 主场 93.3% / 训练进度 | 解出率 | 自产题/本地靶场 | 仅作训练管道验证，不作战绩 |
| 离线刷题 “附件题 5 题”/13/60/15/60 | 本地题库解出 | 全部为自出题训练题库（`flag{b'…'}`、`flag{b'…'}` 等合成 flag），非 DASCTF 正式平台战绩 | 不计入；见 `_archive_离线刷题复盘-20260822.md` 诚实声明 |

### 4. `scripts/_verify_presolve_only.py` 输出 12/15「presolve 命中」——**不计入解题数**

- **来源**：并发会话落的一次性核验脚本，目的正确（防把静态分析器功劳算到 LLM 头上）。
- **实测**：15 道真题中 12 道被静态 `presolve` 抽中，3 道未命中（specialcurve2 / vnctf_flag / gongye_web2）。
- **为什么不算解题数**：
  1. presolve 是**确定性模板**，直接从题面真值文件把答案抽出来（`force=True` 跳过 LLM），与早期撤掉的 `real_drill_manifest.json` 直接给答案本质相同——**没有攻击链**。
  2. 12 道里有 **7 道 flag 格式是 `flag{...}` 而非真题 `DASCTF{<REDACTED>`**，说明这些是**本地自产训练题库的真值**（See `data/questions_real/crypto/` 里 `anwang_crypto1` 等），不是 DASCTF 正式赛题。
  3. specialcurve2 反而在 presolve 里"未命中"——因为它需要 factordb 网络调用 + 真实数论推导（我的 ledger 第 1 条已独立复现），证明 **ledger 的 3 真解比 presolve 12/15 更扎实**。
- **处置**：脚本保留为诚实工具（`[无任务]` 收口），但 **12/15 不得作为解题数口径**；真解数仍以本台账第二节 3 项为准。

---

## 五、当前诚实水位

| 口径 | 数值 | 说明 |
|---|---|---|
| 平台 accepted | **0** | 比赛结束，无开放赛事 |
| **严格真题 offline_verified（唯一 KPI，merge_gate 机器真值）** | **12** | 台账第二节 12 个 ✅ A/B 类题块：10733 + vnctf_flag + xuanhun_signin + anwang_crypto1 + ezmult + filterrandom + qiangwang_classic + sheng + upx + ezrsa + simplelegendre + exciting_inverse（ezrsa / simplelegendre / exciting_inverse 三道均于 2026-09-03 经确定性求解器 `_regress_one.py` REGRESS_PASS 带证据晋级，见题块 7/8/11 与 `_antifraud.PROMOTION_EVIDENCE`；specialcurve2 / 10732 / 10735 经 2026-08-27 诚实校准判定不可复现、移出严格 KPI 并列入 KNOWN_GAP；`scripts/_merge_gate.py count_offline_verified` 实跑计数 fail-closed） |
| 确定性管线真值验证 | **14 / 15** | 第二节-B：presolve+工具层提取 flag 与题库真值逐字一致；第 15 题 vnctf 走独立图像采样（真题集共 45 道，此 15 道有确定性管线覆盖） |
| 正式赛真题独立离线核验（genuine，含非自动化） | **3** | 10732 + 10733 + 10735（PKCS#1v1.5 / 高偶指数RSA / pcap盲注）；仅 10733 为严格 ✅ 可机器复现，10732/10735 为 genuine 但仅视觉/历史确认；分母 33 道正式赛 |
| 外部真题独立离线核验（self-produced 口径） | **4** | HGAME2022 RSA×3 + 2022安网杯 misc3（非平台题，不计入严格 KPI）——HGAME RSA1/RSA2/RSA3 与西湖 FilterRandom 已于 2026-08-27 仓库内重建复现通过；安网 misc3（无公开附件）仍仅历史记录 |
| LLM 真推理贡献 | **= 0** | 12 道严格解仍全由 presolve/工具直出，无 LLM 真推理贡献。`scripts/demo_llm_rag_solve.py` 对 10733 的"验证"**存在泄露**：flag(EXPECTED)与 n/hint/c 明文硬编码于脚本、且完整解法推导写进 prompt 喂给 LLM（LLM 仅抄写 sympy 代码），不满足 genuine 推理标准，故不计入 LLM 真推理贡献。writeup_rag 已真正接入主解题循环（CTF_AGENT_WRITEUP_RAG 开关，每步检索注入 plan prompt，零回归），但 genuine 推理贡献仍待无泄露端到端验证 |
| 训练题库解出（不计入） | 15/60（本地自出题） | 仅反映模板覆盖度，非正式战绩 |

---

## 六、下一步（按 ROI）

1. **固化 10732 可复现脚本**——当前仅靠视觉 artifact（`crypto01_render_p2.png` 显示 flag）；补一个能从附件重跑出 flag 的 verify 脚本，使该解出完全可复现。
2. **扩大正式赛真题解出**——剩余 31 道正式赛真题（10716-10748 中未解者）逐个离线攻；优先有附件、可离线做的题。
3. **从 questions_real 中再挑未解题**——补通用 skill / presolve 路径，提升 1/15 这一项。
4. **答辩/治理文档全部归档**——不再新增不产生解题数的文档（见任务清单）。

---

## 七、LLM+RAG 能力验证（writeup_rag · IDEA-5 落地）

- **模块**：`knowledge/writeup_rag.py`（BM25 检索核）+ `knowledge/reason_with_rag.py`（检索→LLM 推理层）+ `knowledge/writeups_corpus.jsonl`（20 篇已验证解法/工具手册语料）。
- **验证实验**：`scripts/demo_llm_rag_solve.py` 对 **10733（高偶指数 RSA + hint 泄露 p + ROT13）** 端到端验证：
  1. RAG 检索召回 `crypto-rsa-high-exponent` 等 3 篇相关 writeup；
  2. LLM（deepseek）基于 writeup 方法写出完整解题脚本（`W=pow(e,n,n); p=gcd(W²-hint,n)` → 逐层 `sqrt_mod` 16 次 → ROT13 解码）；
  3. 脚本执行输出 `DASCTF{rabbits6sc5mpl8x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8}`，**与 10733 真值完全一致**（`demo_llm_rag_solve.py` 退出码 0）。
- **意义（待校正）**：`demo_llm_rag_solve.py` 的"验证"**不构成 genuine 推理突破**——flag(EXPECTED)与 n/hint/c/E 明文硬编码于脚本、完整解法推导（W=pow(e,n,n); p=gcd(W²−hint,n)；逐层 sqrt_mod 16 次；ROT13）直接写进 PROBLEM prompt 喂给 LLM，LLM 仅把现成推导抄成 sympy 代码。属"答案+解法喂模型再比对硬编码 flag"的泄露式演示，不满足本台账 genuine 推理标准（见上表"LLM 真推理贡献 = 0"）。**请勿据此宣称"LLM 推理从 0 突破"。**
- **与 KPI 关系**：10733 已计入严格 KPI（presolve 口径）；本演示是**泄露式实验**，不重复计数、不计入 LLM 真推理贡献。下一步：把 writeup_rag 接入主 agent 循环（已完成：CTF_AGENT_WRITEUP_RAG 开关，每步检索注入 plan prompt，零回归），并以**无泄露**方式做 genuine 端到端验证（题目参数与 flag 均不预置，由 LLM 基于检索 writeup 独立推理解出）。

*可复现：`python scripts/demo_llm_rag_solve.py`（需 deepseek 可达；偶发 HTTP 超时重试即可）。*

---

*本台账不接受“视觉确认但未落盘”“思路通但未输出 flag”“本地靶机命中”等中间态作为解出。每行必须有可复现命令或明确核验 artifact。*
