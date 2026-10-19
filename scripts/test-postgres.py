#!/usr/bin/env python3
"""Run integration tests using a new disposable, loopback-only database."""
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time

def terminate(signum, frame):
    raise KeyboardInterrupt("Test interrupted")

signal.signal(signal.SIGTERM, terminate)

root = Path(__file__).resolve().parents[1]
name = "keygate-test-" + secrets.token_hex(8)
env = os.environ.copy()
env["POSTGRES_PASSWORD"] = secrets.token_hex(32)
try:
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name,
                    "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB=keygate_test",
                    "-p", "127.0.0.1::5432", "postgres:16-alpine"],
                   env=env, check=True, stdout=subprocess.DEVNULL)
    for attempt in range(60):
        ready = subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres", "-d", "keygate_test"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ready.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("Disposable database did not become ready")
    state = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]
    port = state["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
    env["KEYGATE_TEST_DATABASE_URL"] = "postgres://postgres:" + env["POSTGRES_PASSWORD"] + "@127.0.0.1:" + port + "/keygate_test?sslmode=disable"
    # 各测试包执行全库迁移、故障注入及停服恢复，使用独立数据库避免跨包共享维护状态。
    packages = subprocess.check_output(["go", "list", "./..."], cwd=root, text=True).splitlines()
    for index, package in enumerate(packages):
        database = "keygate_test"
        subprocess.run(["docker", "exec", name, "dropdb", "-U", "postgres", database], check=True)
        subprocess.run(["docker", "exec", name, "createdb", "-U", "postgres", database], check=True)
        env["KEYGATE_TEST_DATABASE_URL"] = "postgres://postgres:" + env["POSTGRES_PASSWORD"] + "@127.0.0.1:" + port + "/" + database + "?sslmode=disable"
        subprocess.run(["go", "test", "-race", "-count=1", package], cwd=root, env=env, check=True, timeout=180)
finally:
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
