"""Cybench 脚手架命令行入口。

用法：
    python -m benchmarks.cybench                  # 内置合成样本 dry-run（验证数据通路）
    python -m benchmarks.cybench --real           # 真实 ext_cybench_* 任务（需后续容器+密钥）
    python -m benchmarks.cybench --source <dir|file|glob>
"""
from benchmarks.cybench.runner import main

if __name__ == "__main__":
    main()
