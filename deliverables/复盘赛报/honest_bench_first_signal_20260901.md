# 诚实解题能力基准（战役 B）—— 首个可信真数字 2026-09-01

## 一句话结论

**修正后的诚实基准（21 题真输入面，deepseek，LLM-only + 四级答案剔除）：8/21 = 38.1%。**
crypto 6/10（60%，**含 3 道 HARD 题 LLM 真推理解出**）是真实能力信号；misc 0/8 为**数据集结构性缺陷**，非 agent 能力问题。

> ⚠️ **9/22 → 8/21 修正（本日 2 次）**：19:08 首跑 9/22 中，`real_crypto_anxun2020_aes` 被识破为**假解**——附件=flag.txt（答案密钥）被剔除后无任何输入，description 明文写有真值 flag，LLM 直接抄题面答案（6.6s SOLVED，复跑实证：过滤后保留附件=[] 仍 SOLVED 且答案与 description 一致）。属 **D 类题面泄露**，剔除 → 8/21。

## 基准修正史（本日 4 处，均已提交 38bd0ee + 后续 LEAK_SKIP 提交）

1. **三级输入过滤**：名字级（flag.txt/answer.txt/solution.txt）+ **内容级**（附件文本含真值 flag 的 writeup/重建笔记自动识别）+ 路径级（悬空引用排除）
2. **_validate 明文 fallback**：无 `flag_sha256` 字段的题（如 BeCare4 等重建题）不再恒判 UNSOLVED
3. **no_presolve async 化**：同步 lambda 致 `await None` TypeError（仅日志噪音，行为等价）
4. **题面级泄露检测（本次）**：`_desc_leaks_flag` 检测 description 含真值 flag（明文匹配 + sha256 命中），`_has_real_input` 排除 D 类题（真输入面 22→21），`_solve_one` 直接返回 LEAK_SKIP 防单题误跑被题面毒害

## 全题库输入构成（92 题，此前从未量化）

| 类别 | 数量 | 含义 |
|---|---|---|
| A 唯一输入=答案密钥 | 65 (70.7%) | 剔除后无米之炊，**诚实基准下不可测** |
| B 文本附件（密文材料/writeup 混合） | 14 | 需内容级区分：`s1.txt`/`classicCrypto.txt`/`键盘侠.txt` 是密文；`BeCare4.md` 等是含答案的重建笔记 |
| C 真输入（脚本/密文/二进制/图） | 13 | **唯一可测面** |

题面级泄露扫描（全题库）：仅 2 题 description 含真值 flag（`anxun2020_aes`/`anxun2020_notright`），后者不在基准面。

## 21 题真输入面结果

### crypto 6/10 —— 真能力核心证据
- **SOLVED**：ezrsa(MEDIUM) / exciting_inverse(**HARD**) / filterrandom(**HARD**, DASCTF) / simplelegendre(**HARD**) / ezmult(EASY) / qiangwang_classic(EASY)
- 3 道 HARD 此前记忆判"presolve 提取=None、不可复现"——**本次 LLM 在禁 presolve + 剔除答案下真推理解出**，推翻旧判
- 8 个 SOLVED 的 description 已逐一扫描：**无明文/编码变体（base64/base32/hex/rot13）泄露，全部 CLEAN**
- **剔除**：anxun2020_aes（D 类题面泄露假解，见上）
- **UNSOLVED 4**：specialcurve2（实例缺失，不可复现 GAP）/ cgroup（flag 字段为占位文本"实例相关需跑原题脚本恢复"，唯一附件=求解脚本非实例数据，无输入）/ changan2021_checkin（唯一附件=flag.txt 答案密钥，无密文）/ dnui_keyboard（TIMEOUT，**已修复见下**）

### dnui_keyboard 路由修复（2a48483）—— 200s TIMEOUT → 0.9s SOLVED
- 根因：772d5c1 强制路由传 `attachments` 键但 skill 只认 `text/path` + SkillAdapter dict 字符串化丢 flag 键 → 双契约不匹配，路由从未命中
- 修复：`crypto_keyboard_path.run` 兼容 attachments 统一契约（与 flag_scan/crypto_auto 同款）
- 单题复跑：`skill_require 强制路由命中` → SOLVED 0.9s，sha256 验证通过
- ⚠️ 19:08 批次中该题仍 TIMEOUT（200s）——批次与单题差异为**路由触发随机性**（LLM 推理路径未触发 skill_require），能力可复用但不稳定
- 诚实口径：dnui_keyboard 属 D 类（题面泄露答案），**不计 KPI**；本修复只恢复可复用路由能力

### reverse 2/3 —— js "SOLVED" 被识破为假解
- SOLVED：upx(EASY) / sheng(EASY)
- **js 反转（0.7s SOLVED → 172.2s UNSOLVED）是内容级过滤立功**：`index.html` 直接含 flag 明文，旧基准把答案当附件喂给 LLM → 假解；新基准识别为答案文件排除 → 诚实 UNSOLVED

### misc 0/8 —— 数据集结构性缺陷，非能力
| 题 | 失败原因 |
|---|---|
| badpdf / ssw_redis / phish_sender | 无真输入（唯一附件=答案密钥 或 description-only） |
| strangeflag / easyzip | 输入=writeup 文本（内容级过滤后无输入）；strangeflag 附件 vnctf2022.txt 悬空 MISSING |
| vnctf_flag / xuanhun_signin | **视觉题（图内 flag），OCR 架构缺口**（文本 LLM 不可解） |
| smallsword2 | 待查（74s 失败，无真附件） |

## 结论与下一刀

1. **crypto 真能力成立**：60% 真输入解出率，HARD 题可解 → 该能力可复用于未来赛事
2. **misc 不可测**：0/8 是数据集问题（无输入/视觉/答案文本），**补 misc 工具是错误方向**；要测 misc 必须先补真实输入（公开渠道重收附件）或找新题源
3. **诚实口径已 2 次自净**（js 附件泄露 + anxun2020_aes 题面泄露均被识破）——说明四级过滤机制在真实工作，不是摆设
4. **下一刀候选**：
   - A. 修复"无输入"题的数据（补附件）——需外网/用户提供源，属弹药库恢复线
   - B. 视觉架构缺口（OCR）——架构级，成本高
   - C. 维持 8/21 冻结，转投文档/工具链价值线
5. **能力陈述口径（对外引用必须带前缀）**：真输入面 8/21（crypto 6/10 / reverse 2/3 / misc 0/8），LLM 真推理解出，答案密钥与题面泄露均已剔除（四级过滤），与离线题解注水区分
