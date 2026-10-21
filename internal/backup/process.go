package backup

import (
	"context"
	"ex-keygate/internal/access"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// PostgreSQL凭据只通过子进程环境传递，不进入参数、日志或错误输出；清理继承的PG变量，拒绝未声明连接选项。
func pgEnv(dsn string) ([]string, string, error) {
	u, e := url.Parse(dsn)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.User == nil || u.Fragment != "" {
		return nil, "", ErrBackup
	}
	name := strings.TrimPrefix(u.Path, "/")
	if !access.ValidID(name) {
		return nil, "", ErrBackup
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	password, _ := u.User.Password()
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "PG") {
			env = append(env, v)
		}
	}
	env = append(env, "PGHOST="+u.Hostname(), "PGPORT="+port, "PGDATABASE="+name, "PGUSER="+u.User.Username(), "PGPASSWORD="+password, "PGCONNECT_TIMEOUT=5", "PGAPPNAME=keygate-backup", "PGPASSFILE="+os.DevNull)
	allowed := map[string]string{"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "connect_timeout": "PGCONNECT_TIMEOUT"}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return nil, "", ErrBackup
	}
	for key, values := range q {
		mapped, ok := allowed[key]
		if !ok || len(values) != 1 {
			return nil, "", ErrBackup
		}
		env = append(env, mapped+"="+values[0])
	}
	return env, name, nil
}
func dump(ctx context.Context, program, dsn, snapshot string, w io.Writer, key []byte) error {
	job, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(job, program, "--format=custom", "--no-owner", "--no-privileges", "--schema=keygate", "--snapshot="+snapshot)
	env, _, e := pgEnv(dsn)
	if e != nil {
		return e
	}
	cmd.Env = env
	cmd.Stderr = io.Discard
	r, e := cmd.StdoutPipe()
	if e != nil {
		return ErrBackup
	}
	if e = cmd.Start(); e != nil {
		return ErrBackup
	}
	e = encrypt(w, r, key)
	if e != nil {
		cancel()
	}
	wait := cmd.Wait()
	if e != nil || wait != nil {
		return ErrBackup
	}
	return nil
}

// 手动BEGIN只在导出、快照核对和隔离全部成功后追加COMMIT；任何中断/SQL失败都由连接关闭回滚，不存在已提交未隔离窗口。
func restore(ctx context.Context, program, psql, dsn string, r io.Reader, key []byte, postlude string) error {
	job, cancel := context.WithCancel(ctx)
	defer cancel()
	env, name, e := pgEnv(dsn)
	if e != nil {
		return e
	}
	decode := exec.CommandContext(job, program, "--no-owner", "--no-privileges", "--exit-on-error", "--file=-")
	decode.Env = env
	decode.Stderr = io.Discard
	input, e := decode.StdinPipe()
	if e != nil {
		return ErrBackup
	}
	sqlOutput, e := decode.StdoutPipe()
	if e != nil {
		return ErrBackup
	}
	apply := exec.CommandContext(job, psql, "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--dbname", name)
	apply.Env = env
	apply.Stdout = io.Discard
	apply.Stderr = io.Discard
	sqlInput, e := apply.StdinPipe()
	if e != nil {
		return ErrBackup
	}
	if e = apply.Start(); e != nil {
		return ErrBackup
	}
	if e = writeAll(sqlInput, []byte("BEGIN;\nSET LOCAL statement_timeout='30min';\n")); e != nil {
		cancel()
		sqlInput.Close()
		apply.Wait()
		return ErrBackup
	}
	if e = decode.Start(); e != nil {
		cancel()
		sqlInput.Close()
		apply.Wait()
		return ErrBackup
	}
	feedDone := make(chan error, 1)
	go func() {
		e := decrypt(input, r, key)
		if e != nil {
			cancel()
		}
		input.Close()
		feedDone <- e
	}()
	_, copyErr := io.Copy(sqlInput, sqlOutput)
	if copyErr != nil {
		cancel()
	}
	decodeErr := decode.Wait()
	feedErr := <-feedDone
	if copyErr == nil && decodeErr == nil && feedErr == nil {
		e = writeAll(sqlInput, []byte("\n"+postlude+"\nCOMMIT;\n"))
	} else {
		e = ErrBackup
	}
	// 失败路径从不写COMMIT，psql即使正常读到EOF也只会回滚仍打开的事务。
	sqlInput.Close()
	applyErr := apply.Wait()
	if e != nil || applyErr != nil {
		return ErrBackup
	}
	return nil
}
