#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Create one isolated development database; never print its random password."""
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time

def terminate(signum, frame):
    raise KeyboardInterrupt("Development database setup interrupted")

signal.signal(signal.SIGTERM, terminate)

root = Path(__file__).resolve().parents[1]
folder = root / "data" / "dev-console"
folder.mkdir(parents=True, exist_ok=True, mode=0o700)
if folder.stat().st_mode & 0o077:
    raise RuntimeError("Development database output directory must be private")
url_file = folder / "database-url"
runtime_file = folder / "database-runtime.json"
if url_file.exists() or runtime_file.exists():
    raise RuntimeError("Development database already configured; reuse it or stop it before removing its files")
name = "keygate-dev-" + secrets.token_hex(8)
env = os.environ.copy()
env["POSTGRES_PASSWORD"] = secrets.token_hex(32)
created = False
owned_files = []
try:
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name,
                    "--label", "keygate.purpose=development",
                    "--label", "keygate.instance=" + name,
                    "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB=keygate_dev",
                    "-p", "127.0.0.1::5432", "postgres:16-alpine"],
                   env=env, check=True, stdout=subprocess.DEVNULL)
    created = True
    for attempt in range(60):
        status = subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres", "-d", "keygate_dev"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if status.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("Disposable development database did not become ready")
    state = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]
    port = state["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
    dsn = "postgres://postgres:" + env["POSTGRES_PASSWORD"] + "@127.0.0.1:" + port + "/keygate_dev?sslmode=disable"
    fd = os.open(url_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    owned_files.append(url_file)
    with os.fdopen(fd, "w") as output:
        output.write(dsn)
    fd = os.open(runtime_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    owned_files.append(runtime_file)
    with os.fdopen(fd, "w") as output:
        json.dump({"developmentOnly": True, "container": name, "databaseUrlFile": str(url_file)}, output)
    print("开发数据库已创建，私有配置文件：" + str(url_file))
except BaseException:
    if created:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for owned in owned_files:
        owned.unlink(missing_ok=True)
    raise
