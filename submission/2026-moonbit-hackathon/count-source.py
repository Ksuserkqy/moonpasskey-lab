#!/usr/bin/env python3
"""Count committed, project-owned source lines without installing dependencies.

Physical and nonblank lines are inventory metrics, not organizer-approved LOC.
Usage: python3 submission/2026-moonbit-hackathon/count-source.py [commit]
"""
import collections
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[2]
revision = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
commit = subprocess.check_output(
    ["git", "rev-parse", "--verify", revision + "^{commit}"], cwd=root, text=True
).strip()
paths = subprocess.check_output(
    ["git", "ls-tree", "-r", "-z", "--name-only", commit], cwd=root
).decode().split("\0")
languages = {".mbt": "MoonBit", ".mjs": "JavaScript", ".js": "JavaScript",
             ".ts": "TypeScript", ".vue": "Vue", ".sh": "Shell"}
files = []
summary = collections.defaultdict(lambda: {"files": 0, "physical": 0, "nonblank": 0})
for path in sorted(filter(None, paths)):
    parts = pathlib.PurePosixPath(path).parts
    suffix = pathlib.PurePosixPath(path).suffix
    if suffix not in languages or any(part in {
        ".mooncakes", "node_modules", "_build", "target", "dist", "submission"
    } for part in parts):
        continue
    name = pathlib.PurePosixPath(path).name
    if "fixtures" in parts or "fixtures" in name:
        scope = "fixtures"
    elif name.endswith(("_test.mbt", "_wbtest.mbt", ".test.mjs", ".test.ts")) or any(
        part in {"test", "tests"} for part in parts
    ):
        scope = "tests"
    elif parts[0] in {"scripts", "deploy"} or name == "vite.config.ts":
        scope = "tooling"
    else:
        scope = "production"
    content = subprocess.check_output(["git", "show", commit + ":" + path], cwd=root)
    lines = content.decode("utf-8").splitlines()
    item = {"path": path, "language": languages[suffix], "scope": scope,
            "physical": len(lines), "nonblank": sum(bool(line.strip()) for line in lines)}
    files.append(item)
    total = summary[(item["language"], scope)]
    total["files"] += 1
    total["physical"] += item["physical"]
    total["nonblank"] += item["nonblank"]
print(json.dumps({"commit": commit,
    "method": "Committed own .mbt/.mjs/.js/.ts/.vue/.sh files; physical and nonblank lines include comments. Dependencies, generated interfaces/builds, assets/config/docs and submission tooling excluded. Fixture-named sources separate. No effective-LOC claim.",
    "summary": [{"language": key[0], "scope": key[1], **value}
                for key, value in sorted(summary.items())], "files": files}, indent=2))
