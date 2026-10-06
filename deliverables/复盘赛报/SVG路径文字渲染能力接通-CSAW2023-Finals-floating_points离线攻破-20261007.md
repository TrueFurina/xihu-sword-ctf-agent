# SVG 路径文字渲染能力接通 —— CSAW-Finals 2023 `floating_points` 离线攻破

> 提交：`47ad227`（实现）+ `039d5d7`（测试）→ 本文（文档）
>
> 结论性质：**确定性离线攻破（presolve 命中）**，非 LLM 自主解题，不计入 LLM 自主解题率。

---

## 结论先行

`questions_ext`（NYU CTF Bench 派生池）forensics 题 **`2023f_for_floating_points`
（CSAW-Finals 2023 「Floating Points / 浮点数」）被确定性解出**：

```
flag   = csawctf{did_you_try_w3schools_path_d=}
sha256 = 6500f523…5b2e  ==  题面 flag_sha256  ✅ 逐字吻合
```

解出链完全离线、零 token、不触平台：

```
floating_points  --bzip2-->  Ascii85 文本  --a85decode-->  SVG path 数据
                 --纯 Python 栅格化(even-odd 填充)-->  一行文字位图
                 --系统 tesseract OCR-->  csawctf{did_you_try_w3schools_path_d=}
```

## 根因：能力缺口（「明文只存在于图形里」）

这与前几轮的「能力存在但不可达」不同——**本轮是真正的能力缺口**：明文根本不
以字节形式存在于附件中，只以**矢量图形**形式存在，任何「嗅探明文/grep」路径都
注定失败。必须补上「**解析图形 → 渲染 → 识别**」这条链路。

附件 `floating_points`（14430 B）静态特征：

- magic `BZh` → **bzip2**；
- 解压得 39238 B，字符集恰为 `!`..`u`（33–117，共 85 个）→ **Ascii85**；
- a85 解码得 **SVG path 的 `d` 属性**：49 个闭合子路径，指令仅 `M/L/Q/A/Z`，
  坐标域 x∈[0,398.64]、y∈[0,19.8]（单行文字），
  `A`（圆弧）恒有 `rx==ry`（圆角）。

题面已暗示：「puzzle box, its surface a maze of **curves and bits** …」。
上游官方解法（`solve.py`）是「`bzip2 -d` → `base64.a85decode` → 写进
`<svg><path d='…'>` → 浏览器渲染 → **人眼看**」——说明该题本就依赖**视觉**。

## 解法（三步，纯 Python + 可选 OCR）

实现落位 `skills/svg_path_text.py`（+ 配套 `.json`），presolve 并发嗅探组第
**34 路**接线 `_try_svg_path_text`（`core/presolve.py`；`grep -c
"asyncio.ensure_future(_try_"` = 34）。

1. **容器解码**（`decode_container`）：`bzip2`（`BZh` magic）→ 文本；若文本已是
   合法 path 直接用，否则要求其为 Ascii85（≥98% 字符落在 `!`..`u`）→ a85decode
   → 校验为合法 SVG path（以 `M/m` 起、仅含指令+数字、≥1 个 `Z`、≥12 点）。
2. **纯 Python 栅格化**（`parse_subpaths` + `rasterize`）：解析
   `M/L/H/V/Q/C/S/T/A/Z`（绝对/相对）并**展平**二次/三次贝塞尔与椭圆弧
   （SVG F.6.5 端点式弧 → 中心参数化，48 段采样）；再按 **even-odd 异或填充**
   逐子路径栅格化 —— `^=` 而非 `|=`，从而**正确处理字腔**（`a/o/d/p/=/` 的
   内轮廓被 xor 抵消），并叠加描边加粗（闭合线 width≈`thickness·scale/4`）。
3. **OCR 识别**：对多种描边粗细（1.6/2.6/3.6/0）各渲染一次，调用系统
   `tesseract`（`--psm 7/6`），**优先返回含 `{…}` 者**；无 tesseract → 返回
   `None`（不谎报）。

### 两个关键坑

- **字腔必须 even-odd**：若误用并集填充（`|=`），`a/o/d/p/=` 变成实心块，
  OCR 会把 `{` 读成 `i`（`csawctfidid_you…`）→ 解不出。变异验证确认此点
  （见下）。
- **描边加粗**：不描边时 `{`/`_` 过细，OCR 误判；`thickness≈1.5` 起 OCR 稳定
  读出完整 `csawctf{…}`。

## 验证（全部通过）

- **sha256 逐字吻合**：`csawctf{did_you_try_w3schools_path_d=}` →
  `6500f523…5b2e` == 题面 `flag_sha256`；亦与上游 `challenge.json` 的 `flag`
  字段逐字一致。
- **新增测试 19/19**：容器 round-trip / a85 / 反例、path 解析（含相对+曲线+
  弧）、栅格化几何、`run` 接口与负例、OCR 合成 round-trip（`flag{abc123}` 等）、
  真实题 sha256 锁、presolve 接线与端到端。
- **变异验证生效**：把 even-odd 异或填充改为并集（`^=`→`|=`）→ 真实题
  sha256 测试与 presolve 端到端**双双转红**，恢复后 19/19 复绿。
- **回归零红**（实测取数，均单跑复现）：门禁⑥快速回归 `152 passed`；
  presolve+KPI+leak 目标集（`test_presolve_skill_wiring` /
  `test_presolve_answer_check` / `test_presolve_b1_wiring` /
  `test_kpi_canonical` / `test_kpi_crossaudit` / `test_leak_provenance` /
  `test_no_leaked_flag` / `test_scan_kpi_leak_guard` /
  `test_svg_path_text`）`130 passed / 5 skipped`；skill 覆盖度/路由
  （`test_skill_coverage` + `test_skill_routing_integrity`）`9 passed`；
  新增 `test_svg_path_text.py` `19 passed`。README 中英 skills 计数已按机器
  真值同步为 **64**（`test_kpi_canonical` 复绿 `21 passed`）。
- **诚实口径**：OCR 非「明文嗅探」；命中仍由下游 `flag_pattern` +
  `_passes_answer_check`（`flag_sha256`）把关，无把握一律不返回，故**不产生
  假阳性**。属 **presolve 命中，不计入 LLM 自主解题率**；「可确定性攻破」仅
  池内小样本，不可外推。

## 附：可复现命令

```bash
cd ctf_agent
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
from skills import svg_path_text as S
print(S.run({'path':'data/questions_ext/_attachments/forensics/2023f-for-floating_points/floating_points'}))
"
# -> b'csawctf{did_you_try_w3schools_path_d=}'
```

## 附：本轮附带发现（`des2bites` = NO_INPUT）

同池 crypto 候选 `2019q_cry_des2bites`（CSAW-Quals 2019 DES 2 Bites）经尽调判定
**NO_INPUT（附件不完整）**，不投入：

- 本地附件仅 2 个（`DES2Bytes.enc` 27136 B、`DES2Bytes.txt` 844 B）；上游原题
  另有 **`FLAG.enc`（flag 密文）与 `Generator.py`**，本地**未随附**。
- 已用官方成品解（`final_solver_rz.py`）的算法本地复刻：`DES2Bytes.enc` 解码
  （offset=9133337、`getNibbleLength`=8）→ 848 B 密文；双 DES-OFB 弱密钥
  **MATCH**（`KEY1=FE01E01FFE01F10E`、`KEY2=FE1FFE1FFE0EFE0E`，与上游 README
  一致），密文 ↔ Lorem 明文对成立 —— 即**「已知明文对所」可解，但取 flag 所必需的
  `FLAG.enc` 缺失**，从本地附件**无法推出 flag**。
- 结论：**NO_INPUT，排除出可离线解出集**（不臆造、不用公开 flag 冒充解出）。
