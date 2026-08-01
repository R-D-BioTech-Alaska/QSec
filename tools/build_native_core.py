from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the standalone QSec native quantum law worker")
    parser.add_argument("--output", default="build/qsec-law-core")
    parser.add_argument("--compiler")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    source = root / "native" / "qsec_law_core.cpp"
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    output.parent.mkdir(parents=True, exist_ok=True)

    compiler = args.compiler or os.environ.get("CXX")
    if not compiler:
        compiler = next((item for item in ("c++", "g++", "clang++") if shutil.which(item)), None)
    if not compiler:
        raise SystemExit("no C++ compiler was found")

    command = [
        compiler,
        "-std=c++17",
        "-O2",
        "-Wall",
        "-Wextra",
        "-pedantic",
        str(source),
        "-o",
        str(output),
    ]
    subprocess.run(command, check=True)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
