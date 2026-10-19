#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stop only the labelled development database recorded for this checkout."""
import json
from pathlib import Path
import re
import subprocess

folder = Path(__file__).resolve().parents[1] / "data" / "dev-console"
record = folder / "database-runtime.json"
metadata = json.loads(record.read_text())
if Path(metadata.get("databaseUrlFile", "")).resolve() != (folder / "database-url").resolve():
    raise RuntimeError("Database record belongs to another checkout")
name = metadata.get("container", "")
if metadata.get("developmentOnly") is not True or not re.fullmatch(r"keygate-dev-[0-9a-f]{16}", name):
    raise RuntimeError("Invalid development database identity")
state = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]
labels = state["Config"].get("Labels", {})
if labels.get("keygate.purpose") != "development" or labels.get("keygate.instance") != name:
    raise RuntimeError("Container does not belong to this development setup")
subprocess.run(["docker", "rm", "-f", name], check=True, stdout=subprocess.DEVNULL)
(folder / "database-url").unlink(missing_ok=True)
record.unlink()
print("独立开发数据库已删除")
