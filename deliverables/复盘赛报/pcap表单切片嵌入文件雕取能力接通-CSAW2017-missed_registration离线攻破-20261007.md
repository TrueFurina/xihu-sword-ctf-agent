# pcap 表单切片「嵌入文件雕取」能力接通 —— CSAW-Quals 2017 forensics `missed_registration` 离线攻破

> 提交：`ade6cfd`（实现）+ `1fd052b`（测试）→ 本文（文档）
> 日期：2026-10-07 ｜ 成本：**¥0**（纯离线确定性求解，不触平台闸口）

## 结论先行

全池 MISS 扫描中，`2017q_for_missed_registration`（CSAW-Quals 2017 forensics）被**离线确定性解出**：

```
FLAG{3Am_LaunDR3Y_FL4G_L34kz!}
```

与题面 `flag_sha256 = b0e408d1da7e9310fd1c9818c0690a3df85fe52bf609912e4688407432a5b22e`
**逐字吻合**，且与 OCR 独立复核结果一致。

ext 池 HITS **14 → 15**。并据此新增确定性能力 `skills/pcap_http_carve.py`（presolve 第 **36 路**）。

## 根因：明文不在题面、也不在报文里，而是**被切成 125 段塞进 HTTP 表单**

题面只有一句：「It's registration day! These forms just seem longer and longer... Use cap.pcap」。
`cap.pcap` 664 KB / 3885 包（全 IPv4）。纯 strings / grep **必然失败**——flag 只以**位图**形式存在，
而位图本身又被切碎、hex 编码、塞进「越来越长」的表单字段。

三步还原（全程零明文嗅探）：

1. **重组 TCP 流**：纯 Python 解析经典 libpcap（magic `d4c3b2a1`，linktype 1 = Ethernet），
   按方向四元组重组 payload，得 369 个 `POST / HTTP/1.1`（→ `192.168.0.21:8080`）。
2. **表单差分**：369 个表单里 **125 个多出一个字段 `x`**（urlencoded；其余 244 个只有
   `c/lname/major/n/name/s/school/text`）。`x` 的值是**偶数长度 hex + 尾部 NUL 填充**。
3. **切片拼接 → 还原文件**：按**抓包时间序**把 125 段 hex 拼起来，恰得 **13714 字节**，
   与首段 BMP 头里声明的 `filesize` **完全相等** —— 一张 323×39 的 8bpp BMP。
   渲染即 `FLAG{3Am_LaunDR3Y_FL4G_L34kz!}`。

首段以 `424d`（ASCII `"BM"`）开头、第三段起不再有文件头，正是「同一文件被逐段搬运」的铁证。

## 两个关键坑

- **不要把每条请求折叠成同一条流**：若按「仅端口对」做键，多次请求会并成一条流，第二份
  请求头会被当成第一份的 body，`x` 值被 `POST / HTTP/1.1...` 污染。必须用**方向四元组**
  `(src, sport, dst, dport)` 作键，并按**首包时间**排序。
- **重组流可能带前导 NUL**：实测流首为 `\x00\x00\x00\x00\x00\x00POST /`，`startswith(b"POST ")`
  恒假。HTTP 头定位必须在**前 16 字节内搜索**方法名，而非要求恰好从 0 开始。

## 能力落地

新增 `skills/pcap_http_carve.py`（+ `.json`），presolve 第 36 路 `_try_pcap_http_carve`：

- 纯 Python pcap 解析（**无 scapy 依赖**）：支持经典 libpcap（LE/BE、微秒/纳秒）、
  Ethernet(1) / Raw IP(101)、802.1Q VLAN、IPv4/TCP。
- 「长 hex 值 → 按字段名聚合 → 抓包时间序拼接 → 魔数自洽判定」的通用雕取范式；
  命中魔数（BMP/PNG/JPG/GIF/PDF/ZIP/7z/gz/BZh/ELF）才认，BMP/PNG 再按声明长度裁剪。
- 图片类走系统 tesseract OCR（复用 `skills.svg_path_text` 的定位逻辑，**可选依赖**，
  缺失即返回 None，不谎报）；非图片类直接在字节里搜 flag 形态。

诚实口径：本 skill 只做**确定性字节搬运与读图**——不做明文嗅探、不猜 flag；命中仍由下游
`flag_pattern` + 答案校验（题面提供时）把关，无把握一律返回 None。

## 验证清单

- 真题端到端：`carve` → 13714 B BMP → OCR → flag，sha256 逐字吻合。
- **零假阳性**：全库 53 个附件中仅 1 个 pcap（本题）命中；200 个非 pcap 附件 `carve` 全部 None。
- 新增测试 `19 passed`：合成 pcap 往返（多段切片 / 声明长度裁剪）、解析单测、
  `run` 接口与负例、真题 sha256 锁、presolve 接线与端到端。
- **变异验证**（内置可重复）：关 `_detect_kind`（魔数判定）或 `_hex_fragment`（片段提取），
  合成与真题**双双还原不出** —— 证明「是这些判据在解」。
- 回归：presolve+KPI+leak 目标集 **`130 passed / 5 skipped`**；KPI/覆盖度/路由/三新 skill
  **`88 passed`**；`_doc_consistency` 绿。README 中英 skills 计数按机器真值同步为 **66**。
- 生产路径：无 `TESSDATA_PREFIX` 时自动从 tesseract 二进制路径推导 tessdata，仍解出。

## 可复现命令

```bash
cd ctf_agent
TESSDATA_PREFIX=<tessdata> .venv/Scripts/python.exe -c \
  "import sys;sys.path.insert(0,'.');from skills import pcap_http_carve as P;\
print(P.solve('data/questions_ext/_attachments/forensics/2017q-for-missed_registration/cap.pcap'))"
```

## 附：本轮其他候选的处置（诚实记录）

| 题 | 判定 | 原因 |
|---|---|---|
| `bananascript` (2017q rev) | **未破** | 确认是「banana VM」程序：每个 7 字母 `bananas` 词以大小写编码 7 bit，`monkeyDo` 内含全部 128 组合；解码出 3480 字符指令流（`plv`/`vo4` 等助记符），需实现 VM 才能取 flag —— 深坑，暂缓 |
| `emoji` (2023f for) | **未破** | 20 个 distinct emoji、288 单元、成对（👍/👎 等）；png 无尾部藏数据；多位序/码点序/首字母等假设均未成 flag |
| `realism` (2017q rev) | **未破** | 512 B MBR，SSE（`movaps`/`pshufd`/`psadbw`）混淆校验，本机不可跑 qemu 验证 |
| `thoroughlystripped` (2017f for) | **未破** | ELF 头被故意破坏（e_type/e_machine/entry 全乱），需重建头 |
| `short_circuit` / `farmlang` | **暂缓** | 干净 jpg，无尾部藏数据，属视觉题 |
| `halfpike` (2019q rev) | **暂缓** | zip 内含 Intel 4004 模拟器 + ROM + `main.cpp` 源码，可移植但工作量大 |
| `simple_recovery` (2018q for) | **不可行** | 附件为 7z，本机无 `py7zr` / `7z` 二进制 |
| `m_ster_0f_prn9` / `free_as_in_freedom` | **不可行** | 分别需 Sage / radare2，本机缺失（按铁律不投入） |

## 诚实边界

- 本解属 **presolve 命中**，**不计入 LLM 自主解题率**（≠ 能力提升）。
- 该 skill 只覆盖「HTTP 表单承载切片 hex」这一范式；其他 pcap 题型（TLS、隧道、多协议）
  未覆盖，**不得外推**为「pcap 类可解」。
