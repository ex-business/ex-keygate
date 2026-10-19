#!/usr/bin/env python3
"""Create a private, development-only three-person TOTP enrollment plan."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets

parser = argparse.ArgumentParser(description="仅生成开发模拟人员的私有TOTP绑定文件；不能作为真实多人身份或离线核验记录")
parser.add_argument("--output", required=True)
args = parser.parse_args()
path = Path(args.output).absolute()
if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
    raise SystemExit("输出父目录必须是0700私有目录，不能是符号链接")
subjects = ["demo-requester", "demo-approver-1", "demo-approver-2"]
plan = {"witnessSubjects": subjects[:2], "evidenceHash": hashlib.sha256(b"DEVELOPMENT SIMULATION ONLY:" + secrets.token_bytes(32)).hexdigest(), "people": [], "approverSubjects": subjects[1:], "m": 2}
for subject in subjects:
    seed = base64.b32encode(secrets.token_bytes(32)).decode().rstrip("=")
    plan["people"].append({"subject": subject, "policy": {"m": 1, "rules": [{"method": "totp", "m": 1, "n": 1, "required": True}]}, "factors": [{"id": "authenticator", "method": "totp", "label": "本人TOTP动态码", "reference": "", "totpSeed": seed}]})
# O_EXCL避免覆盖既有绑定；只打印路径，种子及otpauth不能写入终端、仓库或公开元数据。
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    json.dump(plan, stream, ensure_ascii=False, indent=2)
    stream.write("\n")
print("开发专用私有绑定配置已创建：" + str(path))
print("请用受控本机工具读取各人的totpSeed导入验证器；不要共享或提交此文件。")
