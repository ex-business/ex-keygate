#!/usr/bin/env python3
"""Isolated real HAProxy, synchronous PostgreSQL, network faults and authentication load; no production rollout."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'keygate-ha-' + secrets.token_hex(6)
OUTPUT = ROOT / 'data' / PREFIX
OUTPUT.mkdir(mode=0o700)
PRIVATE = tempfile.TemporaryDirectory(prefix=PREFIX + '-')
PRIVATE_ROOT = Path(PRIVATE.name)
NAMES = {key: PREFIX + '-' + key for key in ['primary', 'standby', 'db-router', 'lb', 'app-a', 'app-b']}
FRONT = PREFIX + '-front'
DATA = PREFIX + '-data'
env = os.environ.copy()
env['POSTGRES_PASSWORD'] = secrets.token_hex(32)
password = env['POSTGRES_PASSWORD']
containers = []
networks = []

def command(args, *, text=None, timeout=45, capture=False, extra=None):
    result = subprocess.run(args, input=text, text=text is not None, env=extra or env,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError('演练命令失败：' + args[0] + ' ' + args[1])
    return result.stdout

def sql(container, statement):
    return command(['docker', 'exec', '-i', '-e', 'PGPASSWORD', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'keygate_test', '-v', 'ON_ERROR_STOP=1', '-At'], text=statement, capture=True, timeout=15).strip()

def wait(predicate, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(.3)
    raise RuntimeError('演练资源就绪超时')

def port(name, internal):
    value = json.loads(command(['docker', 'inspect', name], capture=True))[0]
    return value['NetworkSettings']['Ports'][str(internal) + '/tcp'][0]['HostPort']

def create(name, args):
    command(['docker', 'create', '--name', name, '--label', 'ex-keygate.ha-run=' + PREFIX, '--restart=no'] + args)
    containers.append(name)

report = {'scope': 'local-isolated-docker-synchronous-postgresql-haproxy', 'status': 'FAIL', 'productionStatus': 'NOT_VALIDATED'}
try:
    command(['docker', 'info'], timeout=8)
    for image in ['postgres:16-alpine', 'haproxy:3.2-alpine']:
        try:
            command(['docker', 'image', 'inspect', image], timeout=5)
        except RuntimeError:
            command(['docker', 'pull', image], timeout=180)
    # Linux测试节点使用真实认证执行器；软件根仅经匿名stdin传递。
    worker = PRIVATE_ROOT / 'worker'
    build_env = env.copy()
    build_env.update(CGO_ENABLED='0', GOOS='linux', GOARCH='arm64' if os.uname().machine == 'arm64' else 'amd64')
    command(['go', 'test', '-c', '-o', str(worker), './internal/storage'], extra=build_env, timeout=180)
    worker.chmod(0o755)
    for network in [FRONT, DATA]:
        command(['docker', 'network', 'create', '--label', 'ex-keygate.ha-run=' + PREFIX, network])
        networks.append(network)
    create(NAMES['primary'], ['--network', DATA, '--network-alias', 'primary', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=keygate_test', '-p', '127.0.0.1::5432', 'postgres:16-alpine', '-c', 'wal_level=replica', '-c', 'max_wal_senders=5', '-c', 'max_replication_slots=5', '-c', 'shared_buffers=32MB', '-c', 'max_connections=80'])
    command(['docker', 'start', NAMES['primary']])
    wait(lambda: sql(NAMES['primary'], 'SELECT 1;') == '1')
    sql(NAMES['primary'], "CREATE ROLE keygate_repl WITH REPLICATION LOGIN PASSWORD '" + password + "';")
    command(['docker', 'exec', '-i', NAMES['primary'], 'sh', '-c', 'cat >> "$PGDATA/pg_hba.conf"'], text='\nhost replication keygate_repl 0.0.0.0/0 scram-sha-256\n')
    sql(NAMES['primary'], 'SELECT pg_reload_conf();')
    create(NAMES['standby'], ['--network', DATA, '--network-alias', 'standby', '--user', 'postgres', '-p', '127.0.0.1::5432', 'postgres:16-alpine', 'sh', '-c', 'while [ ! -f /tmp/basebackup-ready ]; do sleep 0.1; done; exec postgres -D "$PGDATA" -c shared_buffers=32MB -c max_connections=80'])
    command(['docker', 'start', NAMES['standby']])
    command(['docker', 'exec', '--user', 'root', NAMES['standby'], 'sh', '-c', 'chown postgres:postgres "$PGDATA"; chmod 700 "$PGDATA"'])
    command(['docker', 'exec', '-i', '--user', 'postgres', NAMES['standby'], 'sh', '-c', 'umask 077; cat > /tmp/replication.pass'], text='primary:5432:*:keygate_repl:' + password + '\n')
    command(['docker', 'exec', '--user', 'postgres', NAMES['standby'], 'pg_basebackup', '-d', 'host=primary port=5432 user=keygate_repl passfile=/tmp/replication.pass application_name=keygate_standby', '-D', '/var/lib/postgresql/data', '-Fp', '-Xs', '-R', '--checkpoint=fast'], timeout=90)
    command(['docker', 'exec', '--user', 'postgres', NAMES['standby'], 'touch', '/tmp/basebackup-ready'])
    wait(lambda: sql(NAMES['standby'], 'SELECT pg_is_in_recovery();') == 't')
    wait(lambda: sql(NAMES['primary'], "SELECT count(*) FROM pg_stat_replication WHERE application_name='keygate_standby' AND state='streaming';") == '1')
    sql(NAMES['primary'], "ALTER SYSTEM SET synchronous_standby_names='FIRST 1 (keygate_standby)'; SELECT pg_reload_conf();")
    wait(lambda: sql(NAMES['primary'], "SELECT count(*) FROM pg_stat_replication WHERE application_name='keygate_standby' AND sync_state='sync';") == '1')
    router_dir = PRIVATE_ROOT / 'router'
    router_dir.mkdir(mode=0o755)
    (router_dir / 'haproxy.cfg').write_text('global\n  maxconn 512\ndefaults\n  mode tcp\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\nfrontend database\n  bind *:5432\n  default_backend authority\nbackend authority\n  server authority primary:5432 check inter 300ms fall 2 rise 2\n')
    create(NAMES['db-router'], ['--network', DATA, '--network-alias', 'db-router', '-v', str(router_dir) + ':/cfg:ro', 'haproxy:3.2-alpine', 'haproxy', '-db', '-f', '/cfg/haproxy.cfg'])
    command(['docker', 'start', NAMES['db-router']])
    env.update(KEYGATE_TEST_DATABASE_URL='postgres://postgres:' + password + '@127.0.0.1:' + port(NAMES['primary'], 5432) + '/keygate_test?sslmode=disable', KEYGATE_HA_STANDBY_URL='postgres://postgres:' + password + '@127.0.0.1:' + port(NAMES['standby'], 5432) + '/keygate_test?sslmode=disable', KEYGATE_HA_WORKER_URL='postgres://postgres:' + password + '@db-router:5432/keygate_test?sslmode=disable')
    env.update(KEYGATE_HA_RUN=PREFIX, KEYGATE_HA_FRONT=FRONT, KEYGATE_HA_DATA=DATA, KEYGATE_HA_NAMES=json.dumps(NAMES), KEYGATE_HA_WORKER=str(worker), KEYGATE_HA_ROUTER_CONFIG=str(router_dir / 'haproxy.cfg'), KEYGATE_HA_OUTPUT=str(OUTPUT))
    # Go管理应用与入口容器；退出时仅清理本轮唯一标签对应的资源。
    log = OUTPUT / 'deployment.log'
    with log.open('wb') as stream:
        os.chmod(log, 0o600)
        result = subprocess.run(['go', 'test', '-count=1', '-v', '-run', '^TestHADeployment$', './internal/storage'], cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
    if result.returncode:
        raise RuntimeError('实际部署演练失败，详情保存在私有deployment.log')
    report.update(json.loads((OUTPUT / 'measurements.json').read_text()))
    report['status'] = 'PASS'
    report['images'] = {image: json.loads(command(['docker', 'image', 'inspect', image], capture=True))[0]['Id'] for image in ['postgres:16-alpine', 'haproxy:3.2-alpine']}
    print('实际负载均衡、断网、同步数据库切换、旧节点隔离和容量测试：PASS')
except Exception as error:
    report['error'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    print('实际部署演练：FAIL（详情见私有报告）')
finally:
    for name in list(NAMES.values()):
        try:
            owner = command(['docker', 'inspect', '--format', '{{index .Config.Labels "ex-keygate.ha-run"}}', name], capture=True, timeout=5).decode().strip()
            if owner == PREFIX:
                command(['docker', 'rm', '-f', '-v', name], timeout=15)
        except Exception:
            pass
    for network in reversed(networks):
        try:
            command(['docker', 'network', 'rm', network], timeout=10)
        except Exception:
            pass
    PRIVATE.cleanup()
    (OUTPUT / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    os.chmod(OUTPUT / 'report.json', 0o600)
    print('report: ' + str(OUTPUT / 'report.json'))
if report['status'] != 'PASS':
    raise SystemExit(1)
