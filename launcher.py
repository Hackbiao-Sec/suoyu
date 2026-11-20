# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 冷启动入口：from arlx.server import main; main()

单独做一个只 import 的脚本，避免打包时把 arlx/__main__.py 当成包入口导致相对导入失败。
"""
import multiprocessing
import os
import sys

# 冻结后 sys.stdout 是 None，uvicorn 打日志会炸；给个黑洞顶上
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

from arlx.server import main  # noqa: E402

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.argv = [sys.argv[0], "-m", "arlx"]
    main()
