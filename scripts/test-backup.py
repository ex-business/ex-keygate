#!/usr/bin/env python3
"""Use a new disposable PostgreSQL and real pg_dump/restore; never touch a running demo database."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
name = 'keygate-backup-drill-' + secrets.token_hex(8)
env = os.environ.copy()
env['POSTGRES_PASSWORD'] = secrets.token_hex(32)
with tempfile.TemporaryDirectory(prefix='keygate-backup-drill-') as directory:
    private = Path(directory)
    binary = private / 'keygate-backup'
    subprocess.run(['go', 'build', '-o', str(binary), './cmd/keygate-backup'], cwd=ROOT, check=True)
    started = False
    try:
        subprocess.run(['docker', 'run', '-d', '--rm', '--name', name, '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=keygate_test', '-p', '127.0.0.1::5432', 'postgres:16-alpine'], env=env, check=True, stdout=subprocess.DEVNULL, timeout=45)
        started = True
        for _ in range(60):
            r = subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'keygate_test'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if r.returncode == 0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError('临时恢复演练库未就绪')
        state = json.loads(subprocess.check_output(['docker', 'inspect', name], timeout=10))[0]
        port = state['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        env['KEYGATE_TEST_DATABASE_URL'] = 'postgres://postgres:' + env['POSTGRES_PASSWORD'] + '@127.0.0.1:' + port + '/keygate_test?sslmode=disable'
        env['KEYGATE_BACKUP_CLI'] = str(binary)
        # Docker只接收环境变量名称；密码值不进入exec命令参数。快照属于同一临时数据库。
        for program in ['pg_dump', 'pg_restore', 'psql']:
            wrapper = private / program
            wrapper.write_text('#!/usr/bin/env python3\nimport os,sys,time\nfrom pathlib import Path\ngate=os.getenv("KEYGATE_BACKUP_DRILL_GATE")\nif gate and '+repr(program)+'=="pg_dump":\n Path(gate,"snapshot-ready").touch(mode=0o600)\n deadline=time.monotonic()+15\n while not Path(gate,"continue").exists():\n  if time.monotonic()>deadline: sys.exit(1)\n  time.sleep(.02)\nos.environ["PGHOST"]="127.0.0.1"\nos.environ["PGPORT"]="5432"\nargs=["docker","exec","-i"]\nfor key in ("PGHOST","PGPORT","PGDATABASE","PGUSER","PGPASSWORD","PGCONNECT_TIMEOUT","PGAPPNAME","PGSSLMODE"):\n if key in os.environ: args += ["-e",key]\nos.execvp("docker",args+[' + repr(name) + ',' + repr(program) + ']+sys.argv[1:])\n')
            wrapper.chmod(0o700)
            env['KEYGATE_BACKUP_' + program.upper()] = str(wrapper)
        subprocess.run(['go', 'test', '-race', '-count=1', '-v', '-run', '^TestBackupRestoreDrill$', './internal/storage'], cwd=ROOT, env=env, check=True, timeout=180)
    finally:
        if started:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
