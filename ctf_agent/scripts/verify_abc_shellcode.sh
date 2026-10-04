#!/usr/bin/env bash
# 验证 abc-arm-and-amd polyglot shellcode（需 Docker Desktop 已启动 + qemu 模拟启用）
#
# 用法：bash scripts/verify_abc_shellcode.sh
# 前置：
#   1. Docker Desktop 已启动（daemon ready）
#   2. 启用跨架构模拟：docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
#   3. 已生成 payload：python scripts/build_abc_polyglot.py --out logs/abc_payload.bin
#
# 验证逻辑：把 payload + 一个内容已知的 'flag' 文件，在两个架构的容器里分别喂给
# 对应 chal 二进制，检查 stdout 是否打印出 flag 内容（x86-64 与 arm64 都通过才算解出）。

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAYLOAD="$ROOT/logs/abc_payload.bin"
CHAL_X86="$ROOT/data/questions_external/misc/ext_gctf2021_abc-arm-and-amd/_attachments/chal-x86-64"
CHAL_ARM="$ROOT/data/questions_external/misc/ext_gctf2021_abc-arm-and-amd/_attachments/chal-aarch64"

echo "=== 前置检查 ==="
docker ps >/dev/null 2>&1 || { echo "✗ Docker daemon 未就绪，请先启动 Docker Desktop"; exit 1; }
[ -f "$PAYLOAD" ] || { echo "✗ 缺 payload，先跑 build_abc_polyglot.py"; exit 1; }
[ -f "$CHAL_X86" ] && [ -f "$CHAL_ARM" ] || { echo "✗ 缺 chal 二进制"; exit 1; }

echo "=== 启用 qemu 跨架构模拟 ==="
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes 2>&1 | tail -3 || \
  echo "（qemu 注册可能已存在，继续）"

echo "=== 准备测试 flag ==="
TEST_FLAG="flag{test_verification_payload}"
echo -n "$TEST_FLAG" > /tmp/abc_test_flag.txt

echo
echo "=== 验证 x86-64 ==="
docker run --rm -i --platform linux/amd64 \
  -v "$CHAL_X86:/chal:ro" -v "$PAYLOAD:/payload.bin:ro" \
  -v /tmp/abc_test_flag.txt:/flag:ro \
  -w / alpine:latest sh -c \
  'cat /payload.bin | /chal; echo; echo "--- expected: $TEST_FLAG"' 2>&1 | head -20

echo
echo "=== 验证 arm64 ==="
docker run --rm -i --platform linux/arm64 \
  -v "$CHAL_ARM:/chal:ro" -v "$PAYLOAD:/payload.bin:ro" \
  -v /tmp/abc_test_flag.txt:/flag:ro \
  -w / alpine:latest sh -c \
  'cat /payload.bin | /chal; echo' 2>&1 | head -20
