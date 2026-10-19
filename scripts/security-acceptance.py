#!/usr/bin/env python3
"""Run development security acceptance; never certify a production deployment."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
STEPS = [
    ("diff", ["git", "diff", "--check"]),
    ("vet", ["go", "vet", "./..."]),
    ("javascript", ["node", "--check", "internal/webauth/manage.js"]),
    ("signature-vector", [sys.executable, "scripts/signature-vector.py"]),
    ("database-script-boundaries", [sys.executable, "scripts/test-dev-db-scripts.py"]),
    ("postgres-race-and-failover", [sys.executable, "scripts/test-postgres.py"]),
    ("known-vulnerabilities", ["go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.9.0", "./..."]),
]

def main():
    # 独立私有结果目录，拒绝链接目录；报告和日志不写入版本控制。
    parent = ROOT / "data"
    if parent.is_symlink():
        raise RuntimeError("验收目录不能是符号链接")
    parent.mkdir(mode=0o700, exist_ok=True)
    if parent.stat().st_mode & 0o077:
        raise RuntimeError("验收目录必须为私有目录")
    output = Path(tempfile.mkdtemp(prefix="security-acceptance-", dir=parent))
    report = {
        "scope": "development-software-single-authoritative-postgresql",
        "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "workingTreeDirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "engineeringStatus": "FAIL",
        "productionStatus": "BLOCKED",
        "productionPrerequisites": [
            "真实 OIDC/MFA、人员授权治理与最小权限运行身份",
            "KMS/HSM 和跨节点一致的托管根配置验收",
            "数据库同步复制、旧主物理隔离、主备切换及提交不明演练",
            "真实负载均衡、TLS 入口、网络分区、多中心及 RTO/RPO 验收",
            "独立不可变归档、告警、渗透测试及组织安全评审",
        ],
        "steps": [],
    }
    try:
        for name, command in STEPS:
            start = time.monotonic()
            log = output / (name + ".log")
            fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                try:
                    result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=420)
                    code = result.returncode
                except subprocess.TimeoutExpired:
                    code = 124
            report["steps"].append({"name": name, "exitCode": code, "seconds": round(time.monotonic()-start, 3)})
            print(name + (": PASS" if code == 0 else ": FAIL"), flush=True)
            if code != 0:
                return 1
        report["engineeringStatus"] = "PASS"
        return 0
    finally:
        report["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        path = output / "report.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print("report: " + str(path), flush=True)

if __name__ == "__main__":
    sys.exit(main())
