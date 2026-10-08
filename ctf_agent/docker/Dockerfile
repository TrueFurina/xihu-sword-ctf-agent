# =============================================================================
# ctf-tools —— CTF-Agent 的 Linux 工具基线镜像
#
# ⚠️ 当前状态（2026-10-09 02:00 实测，务必先读）
# -----------------------------------------------------------------------------
# 本 Dockerfile **尚未在本机构建成功**。失败点不在配方，而在宿主环境：
#   容器 apt 下载进行到一半 → `unexpected EOF`
#   → 根因是**宿主机可用内存不足**（15.8G 物理，可用仅 1.8G，负载 88%），
#     WSL2 的 docker-desktop VM 被 OOM → engine 崩 → daemon 掉 → 连接被掐断。
#   实证：143 个包全部解析成功（包名清单有效），最小包集也照样断 → 非配方问题。
#
# 本机此刻实际可用的 `ctf-tools:1` 是**另一条路径**产出的：
#   `ziphard-tools:1`（本地已有 Debian13+g++/cmake/python3/unzip，无 patch/apt 依赖）
#   → 容器内 cmake 现场编译 bkcrack(1.6.1+crossfilter) / gcc 编译 crackcr.c
#   → `docker commit` 成 ctf-tools:1（690MB），已实跑验证：
#     bkcrack 1.6.1 + second-file cross-filter 存在 + crackcrc + unzip + python3。
#
# 因此本文件的定位是**离线可复现的正式配方**，不是「已验证通过的构建脚本」。
# 换到内存充足（≥8G 可用）的机器上应当可直接 `docker build`。在那之前，
# 「这样不行」和「这样做过了」必须分清楚，不许拿本文件冒充成功案例。
# =============================================================================
#
# 设计原则（与本项目护栏纪律一致）
# -----------------------------------------------------------------------------
# 1. **可离线复现**：bkcrack 源码 + 适配 patch 全部 (COPY) 进镜像，不在构建时联网
#    拉 GitHub。外部 Registry/网络会漂移，今天的 URL 明天 404，构建就断了。
# 2. **不把二进制产物 COPY 进镜像**：只 COPY 源码 + patch，一律在容器内**现场编译**。
#    手工编出来的 ELF 进不了仓库review，也无法证明它对应哪份源码。
# 3. **构建即自检**：编译完当场跑 `bkcrack --help` / `crackcrc`，build 成功 = 工具真能用。
#    （2026-10-08 的教训：镜像 build 成功但 bkcrack 根本不在里面，白欢喜。）
#
# 用法
# -----------------------------------------------------------------------------
#   docker build -t ctf-tools:1 ctf_agent/docker/
#   docker run --rm ctf-tools:1 ctf-selftest
#   docker run --rm -v "${PWD}:/work" -w /work ctf-tools:1 bash
# =============================================================================

# BASE_IMAGE 可替换：正常网络下默认 debian:13-slim 即可。
# 若所在机器 registry 不可达（例：Docker Desktop 配了 http://127.0.0.1:7890 代理
# 而代理未开 → pull 报 connectex refused），可改用**本地已存在**的镜像救急：
#   docker build --build-arg BASE_IMAGE=python:3.12-slim -t ctf-tools:1 .
# 注意：这只是离线兜底，别把它写成常态——不同 base 的系统库版本会让
# 「在我这儿编得出来」失效。换回默认前先确认 registry 可达。
ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# ── 基础工具集 ───────────────────────────────────────────────────────────────
# 注释里的每一条都对应本项目**实际用过或明确卡过**的能力，不堆无用品。
RUN apt-get update && apt-get install -y --no-install-recommends \
        # 编译 bkcrack / CTF 二进制所需
        build-essential \
        cmake \
        patch \
        pkg-config \
        # ── 坑位记录 ──
        # hard.sh（GCTF'23 crypto-ziphard 官方解）用的是 awk 的 strtonum()，
        # Debian 默认 awk = mawk **不支持 strtonum** → 该步会静默返回空值，
        # 后面 dd 的 skip/offset 全跟着错，且**没有任何报错**。
        # 必须显式装 gawk 并让它成为 awk。
        gawk \
        # MISC/取证常用
        unzip \
        zip \
        p7zip-full \
        file \
        xxd \
        binutils \
        binwalk \
        foremost \
        # ── 坑位记录（2026-10-09 实测逐个查过 trixie 源）──
        # radare2 / rizin / r2 在 Debian 13 trixie 官方源里**一个都没有**
        # （`apt-cache pkgnames | grep -x` 全为 0）。最初写 Dockerfile 时凭印象
        # 塞了 `radare2`，结果 apt-get 返回 100，整个构建炸在一个跟 CTF 无关的
        # 包名上；改猜 `rizin` 照样没有。**教训：包名必须查，不能凭印象。**
        # 需要 r2 时用 radare.org 官方源或源码编，别硬塞不存在的包名。
        # 静态逆向现状由 binutils（objdump/readelf/nm/strings）+ gdb 兜底。
        gdb \
        strace \
        ltrace \
        # 脚本/网络/杂项
        python3 \
        python3-pip \
        python3-venv \
        openssl \
        git \
        curl \
        ca-certificates \
        libbz2-dev \
        zlib1g-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# mawk -> gawk：strtonum 依赖（见上）
RUN update-alternatives --install /usr/bin/awk awk /usr/bin/gawk 50

# ── bkcrack：打了 cross-filter patch 的版本（不是上游原版）────────────────────
# 背景：GCTF'23 crypto-ziphard（Task ㉜）卡的正是它。
#   原版 bkcrack 要求「同一文件内 12 字节连续已知明文」；
#   该题的明文被拆在两个文件（flag.txt 8 字节 + junk.dat 5 字节），
#   需要官方提供的 patch 改成：用 flag.txt 生成候选密钥 → 用 junk.dat 过滤。
# 上游 patch 只到 v1.5.0；这里入库的 `bkcrack-1.6.1-crossfilter.patch` 是把它适配到
#   v1.6.1 的产物（v1.6.1 在 Data.cpp 里新增了 CONTIGUOUS_SIZE / ATTACK_SIZE 守卫，
#   直接沿用 1.5.0 的 patch 会算不出 plaintext 长度）。
COPY vendor/bkcrack-1.6.1.tar.gz            /opt/src/
COPY vendor/bkcrack-1.6.1-crossfilter.patch /opt/src/
COPY vendor/bkcrack-1.5.0.tar.gz            /opt/src/
COPY vendor/bkcrack-1.5.0.patch             /opt/src/
COPY vendor/crackcrc.c                      /opt/src/
COPY vendor/hard.sh                         /opt/src/

WORKDIR /opt/src

RUN set -eux; \
    tar xzf bkcrack-1.6.1.tar.gz; \
    cd bkcrack-1.6.1; \
    # -p1 剥一层：patch 里的路径是 a/bkcrack-1.6.1/src/... 。失败必须立即炸，
    # 不然后面 cmake 编译出来的是**没打 patch 的原版**——能跑、能解普通题，
    # 但缺 cross-filter，遇到 ziphard 这类双文件明文会假装无解（最阴的一类失败）。
    patch -p1 --dry-run < ../bkcrack-1.6.1-crossfilter.patch; \
    patch -p1 < ../bkcrack-1.6.1-crossfilter.patch; \
    # 自检：patch 真的进去了（防止 patch 静默跳过 → 编出假工具）
    grep -q "second-file cross-filter" src/main.cpp; \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; \
    cmake --build build -j"$(nproc)"; \
    install -m 0755 build/src/bkcrack /usr/local/bin/bkcrack; \
    # ── 构建即自检：二进制真能跑，而不是只存在于 filesystem ──
    bkcrack --version

# crackcrc：按 CRC32 逆推 junk.dat 的 4 字节明文（hard.sh 第 35 行调用）
RUN set -eux; \
    cd /opt/src; \
    gcc -O3 -o crackcrc crackcrc.c; \
    install -m 0755 crackcrc /usr/local/bin/crackcrc

# ── 自检脚本：docker run --rm ctf-tools:1 ctf-selftest ───────────────────────
# 存在的理由：上面每一条都可能在未来某次重建时 silently 失效（依赖没了、
# patch 对不上了、二进制编出来跑不动了）。开关一条命令验全套。
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -u' \
    'fail=0' \
    'check() { if command -v "$1" >/dev/null 2>&1; then echo "OK   $1"; else echo "MISS $1"; fail=1; fi; }' \
    'for t in bkcrack crackcrc unzip zip 7z objdump readelf gdb strings python3 gawk dd awk cmake g++; do check "$t"; done' \
    'echo "--- bkcrack 必须带 cross-filter（否则 ziphard 跑不出）---"' \
    'strings /usr/local/bin/bkcrack | grep -q "second-file cross-filter" && echo "OK   cross-filter" || { echo "MISS cross-filter"; fail=1; }' \
    'echo "--- awk 必须支持 strtonum（hard.sh 依赖，mawk 不支持）---"' \
    'echo "" | awk "{ print strtonum(\\\"42\\\") }" | grep -q 42 && echo "OK   strtonum" || { echo "MISS strtonum"; fail=1; }' \
    'exit $fail' \
    > /usr/local/bin/ctf-selftest && chmod +x /usr/local/bin/ctf-selftest

WORKDIR /work
CMD ["/bin/bash"]
