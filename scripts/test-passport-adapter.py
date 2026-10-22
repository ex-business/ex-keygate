#!/usr/bin/env python3
"""Verify approvals against the actual sibling Passport on disposable local services."""
import json
import os
import re
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request

root = Path(__file__).resolve().parents[1]
passport = Path(os.environ.get("KEYGATE_PASSPORT_CHECKOUT", root.parent / "ex-passport")).resolve()
name = "keygate-passport-" + secrets.token_hex(6)
children = []
started = False

def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]

def run(args, cwd, env):
    return subprocess.run(args, cwd=cwd, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

try:
    with tempfile.TemporaryDirectory(prefix="keygate-passport-") as tmp:
        work = Path(tmp)
        password = secrets.token_hex(24)
        docker_env = os.environ.copy()
        docker_env["POSTGRES_PASSWORD"] = password
        run(["docker", "run", "--rm", "-d", "--name", name, "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB=keygate_test", "-p", "127.0.0.1::5432", "postgres:17-alpine"], root, docker_env)
        started = True
        for _ in range(100):
            ready = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError("disposable PostgreSQL not ready")
        state = json.loads(run(["docker", "inspect", name], root, docker_env).stdout)[0]
        db_port = state["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
        run(["docker", "exec", name, "createdb", "-U", "postgres", "passport_test"], root, docker_env)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PASSPORT_", "KEYGATE_TEST_"))}
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env["PASSPORT_DATABASE_URL"] = f"postgres://postgres:{password}@127.0.0.1:{db_port}/passport_test?sslmode=disable"
        for command, package in [("passport", "passport"), ("migrate", "migrate"), ("keygen", "keygen"), ("executor", "executor-client")]:
            run(["go", "build", "-o", str(work / command), "./cmd/" + package], passport, env)
        run([str(work / "migrate")], passport, env)
        run([str(work / "keygen"), "-out", str(work / "signing.pem")], passport, env)
        issued = json.loads(run([str(work / "executor"), "-operation", "create", "-client-id", "keygate-test", "-actions", "create,rotate,disable", "-targets", "trade-api", "-audiences", "trade"], passport, env).stdout)
        credential = work / "executor.secret"
        credential.write_text(issued["client_secret"])
        credential.chmod(0o600)
        redis_port, business_port, management_port = port(), port(), port()
        with (work / "redis.log").open("wb") as log:
            child = subprocess.Popen(["redis-server", "--bind", "127.0.0.1", "--port", str(redis_port), "--save", "", "--appendonly", "no", "--dir", tmp], env=env, stdout=log, stderr=log)
            children.append(child)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", redis_port), .2):
                    break
            except OSError:
                time.sleep(.05)
        env.update(PASSPORT_ADDR=f"127.0.0.1:{business_port}", PASSPORT_MANAGEMENT_ADDR=f"127.0.0.1:{management_port}", PASSPORT_REDIS_URL=f"redis://127.0.0.1:{redis_port}", PASSPORT_ISSUER="https://passport.example", PASSPORT_AUDIENCE="trade", PASSPORT_KEY_ID="adapter-test", PASSPORT_SIGNING_KEY_FILE=str(work / "signing.pem"))
        with (work / "passport.log").open("wb") as log:
            child = subprocess.Popen([str(work / "passport")], env=env, cwd=passport, stdout=log, stderr=log)
            children.append(child)
        base = f"http://127.0.0.1:{management_port}"
        for _ in range(100):
            try:
                with urllib.request.urlopen(base + "/health/ready", timeout=.3) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(.1)
        else:
            raise RuntimeError("disposable Passport not ready")
        env.update(KEYGATE_TEST_DATABASE_URL=f"postgres://postgres:{password}@127.0.0.1:{db_port}/keygate_test?sslmode=disable", KEYGATE_TEST_PASSPORT_URL=base, KEYGATE_TEST_PASSPORT_BUSINESS_URL=f"http://127.0.0.1:{business_port}", KEYGATE_TEST_PASSPORT_EXECUTOR_SECRET_FILE=str(credential))
        result = run(["go", "test", "-race", "-count=1", "./internal/storage", "-run", "^TestPassportRealManagement$", "-timeout", "90s"], root, env)
        print(result.stdout.decode(), end="")
        print("PASS: actual Passport create/rotate/disable, encrypted delivery, lost-response query recovery and target isolation")
except subprocess.CalledProcessError as error:
    # Do not dump subprocess commands, environment or credential output.
    diagnostic = error.stdout.decode(errors="replace") + error.stderr.decode(errors="replace")
    if password:
        diagnostic = diagnostic.replace(password, "<redacted>")
    if "issued" in globals():
        diagnostic = diagnostic.replace(issued["client_secret"], "<redacted>")
    diagnostic = re.sub(r"(?:epi_|epe_)[A-Za-z0-9_-]{43}", "<redacted>", diagnostic)
    print(diagnostic[-4000:])
    raise SystemExit("Passport adapter verification failed")
finally:
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    if started:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
