#!/usr/bin/env python3
"""生成开发账号摘要与独立私有登录资料，不输出口令，不覆盖既有文件。"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

parser = argparse.ArgumentParser(description="仅创建开发模拟人员的账号，生产账号须独立核验")
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
directory = Path(args.output_dir).absolute()
if directory.exists() and (directory.is_symlink() or directory.stat().st_mode & 0o077):
    raise SystemExit("输出目录必须为0700，且不能是符号链接")
directory.mkdir(mode=0o700, parents=False, exist_ok=True)
accounts_path = directory / "accounts.json"
access_path = directory / "access.txt"
if accounts_path.exists() or access_path.exists():
    raise SystemExit("账号文件已存在，禁止覆盖")
root = Path(__file__).resolve().parents[1]
accounts = []
access = ["ExKeyGate 本机开发测试账号（非生产凭据）", "TOTP请通过独立的私有MFA绑定文件导入各自验证器，不在此文件复制种子。", ""]
with tempfile.TemporaryDirectory(prefix="keygate-password-") as temporary:
    executable = str(Path(temporary) / "password-hash")
    subprocess.run(["go", "build", "-o", executable, "./cmd/keygate-password-hash"], cwd=root, check=True)
    for username, subject in [("admin", "demo-requester"), ("approver1", "demo-approver-1"), ("approver2", "demo-approver-2")]:
        value = secrets.token_urlsafe(24)
        encoded = subprocess.check_output([executable], input=value.encode(), cwd=root).decode().strip()
        accounts.append({"username": username, "subject": subject, "passwordHash": encoded})
        access.extend(["账号：" + username, "密码：" + value, "验证器绑定人员：" + subject, ""])
for path, content in [(accounts_path, json.dumps({"accounts": accounts}, ensure_ascii=False, indent=2) + "\n"), (access_path, "\n".join(access))]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
print("开发账号私有文件已生成：" + str(directory))
