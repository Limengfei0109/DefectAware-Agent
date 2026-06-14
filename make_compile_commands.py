#!/usr/bin/env python3
import argparse
import json
import os


SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a basic compile_commands.json for standalone C/C++ sources."
    )
    parser.add_argument("src_dir")
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--arg", action="append", default=[])
    args = parser.parse_args()

    root = os.path.realpath(args.src_dir)
    compiler = os.path.realpath(args.compiler)
    entries = []
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in {".git", "build", "dist"}]
        for name in files:
            source = os.path.realpath(os.path.join(current_root, name))
            extension = os.path.splitext(name)[1].lower()
            if extension not in SOURCE_EXTENSIONS:
                continue
            standard = "-std=c11" if extension == ".c" else "-std=c++20"
            arguments = [compiler, standard]
            arguments.extend(f"-I{os.path.realpath(path)}" for path in args.include)
            arguments.extend(args.arg)
            arguments.extend(["-c", source])
            entries.append(
                {
                    "directory": current_root,
                    "file": source,
                    "arguments": arguments,
                }
            )

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"Generated {len(entries)} compile commands: {args.output}")


if __name__ == "__main__":
    main()
