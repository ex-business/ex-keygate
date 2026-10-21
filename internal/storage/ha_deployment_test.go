package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"ex-keygate/internal/config"
	"ex-keygate/internal/httpsign"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/pluginmock"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type haSpec struct {
	processSpec
	Certificate, PrivateKey []byte
}

// 仅测试二进制提供TLS节点，生产AuthenticateProbe/节点租约直接处理真实网络请求；测试根只经匿名stdin传递。
func TestHAHTTPWorker(t *testing.T) {
	if os.Getenv("KEYGATE_HA_WORKER") != "1" {
		t.Skip("仅实际部署演练使用")
	}
	var spec haSpec
	if json.NewDecoder(os.Stdin).Decode(&spec) != nil {
		t.Fatal("节点测试装配无效")
	}
	defer clear(spec.Material)
	defer clear(spec.PrivateKey)
	db, e := sql.Open("pgx", os.Getenv("KEYGATE_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal("节点连接配置无效")
	}
	defer db.Close()
	db.SetMaxOpenConns(24)
	db.SetMaxIdleConns(8)
	raw, _ := New(db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	join, stop := context.WithTimeout(ctx, 5*time.Second)
	trace, e := controlID()
	if e != nil {
		t.Fatal("节点请求标识生成失败")
	}
	node, e := raw.AcquireNode(join, spec.Cluster, spec.Config, spec.Node, "join-"+trace)
	stop()
	if e != nil {
		t.Fatal("节点加入失败")
	}
	control, e := NewDevelopmentControl(config.Test, spec.Environment, spec.Profile, node)
	if e != nil {
		t.Fatal("节点授权域无效")
	}
	keys, e := NewDevelopmentKeys(control, spec.Root, spec.Material, "login-root")
	clear(spec.Material)
	if e != nil {
		t.Fatal("节点根装配无效")
	}
	cert, e := tls.X509KeyPair(spec.Certificate, spec.PrivateKey)
	clear(spec.PrivateKey)
	if e != nil {
		t.Fatal("节点TLS装配无效")
	}
	go node.RunNodeLease(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-KeyGate-Test-Node", spec.Node)
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		job, stop := context.WithTimeout(r.Context(), time.Second)
		defer stop()
		if node.CheckReadiness(job) != nil || keys.CheckHealth(job) != nil {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("POST /api/auth/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-KeyGate-Test-Node", spec.Node)
		if r.Host != "localhost:8443" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			w.WriteHeader(400)
			return
		}
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if e != nil {
			w.WriteHeader(400)
			return
		}
		job, stop := context.WithTimeout(r.Context(), 3*time.Second)
		defer stop()
		e = keys.AuthenticateProbe(job, r, body, "keygate-probe")
		if e == nil {
			w.WriteHeader(200)
		} else if errors.Is(e, ErrDenied) {
			w.WriteHeader(401)
		} else {
			if errors.Is(e, ErrFenced) {
				w.Header().Set("X-KeyGate-Test-Fenced", "true")
			}
			w.WriteHeader(503)
		}
	})
	server := &http.Server{Addr: ":8443", Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second}
	listener, e := net.Listen("tcp", ":8443")
	if e != nil {
		t.Fatal("节点监听失败")
	}
	fmt.Println("HA_READY")
	if e = server.ServeTLS(listener, "", ""); e != nil && !errors.Is(e, http.ErrServerClosed) {
		t.Fatal("节点监听异常")
	}
}

type haHarness struct {
	t                                *testing.T
	names                            map[string]string
	run, front, data, worker, router string
	ca                               []byte
	spec                             haSpec
	processes                        map[string]*exec.Cmd
	inputs                           map[string]io.WriteCloser
	ports                            map[string]string
}

func (h *haHarness) docker(args ...string) []byte {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "docker", args...).Output()
	if e != nil {
		h.t.Fatal("演练容器操作失败", args[0])
	}
	return out
}
func (h *haHarness) owned(name string) {
	h.t.Helper()
	out := h.docker("inspect", "--format", `{{index .Config.Labels "ex-keygate.ha-run"}}`, name)
	if strings.TrimSpace(string(out)) != h.run {
		h.t.Fatal("拒绝操作不属于本次演练的容器")
	}
}
func (h *haHarness) port(name string) string {
	h.t.Helper()
	raw := h.docker("inspect", "--format", `{{(index (index .NetworkSettings.Ports "8443/tcp") 0).HostPort}}`, name)
	return strings.TrimSpace(string(raw))
}
func (h *haHarness) start(node string, create bool) {
	h.t.Helper()
	name := h.names[node]
	if create {
		cmd := exec.Command("docker", "create", "-i", "--name", name, "--label", "ex-keygate.ha-run="+h.run, "--restart=no", "--network", h.front, "--network-alias", node, "-e", "KEYGATE_HA_WORKER", "-e", "KEYGATE_TEST_DATABASE_URL", "-e", "GOMEMLIMIT=64MiB", "-p", "127.0.0.1::8443", "-v", h.worker+":/worker:ro", "postgres:16-alpine", "/worker", "-test.run=^TestHAHTTPWorker$", "-test.timeout=10m")
		cmd.Env = append(os.Environ(), "KEYGATE_HA_WORKER=1", "KEYGATE_TEST_DATABASE_URL="+os.Getenv("KEYGATE_HA_WORKER_URL"))
		if e := cmd.Run(); e != nil {
			h.t.Fatal("创建认证节点失败")
		}
		h.docker("network", "connect", h.data, name)
	} else {
		h.owned(name)
	}
	cmd := exec.Command("docker", "start", "-ai", name)
	input, e := cmd.StdinPipe()
	if e != nil {
		h.t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		h.t.Fatal(e)
	}
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if e = cmd.Start(); e != nil {
		h.t.Fatal(e)
	}
	spec := h.spec
	spec.Node = node
	if e = json.NewEncoder(input).Encode(spec); e != nil {
		h.t.Fatal("测试根管道失败")
	}
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(out)
		found := false
		var lines []string
		for scan.Scan() {
			lines = append(lines, scan.Text())
			if len(lines) > 12 {
				lines = lines[1:]
			}
			if scan.Text() == "HA_READY" && !found {
				found = true
				ready <- "ready"
			}
		}
		if !found {
			ready <- strings.Join(lines, " | ")
		}
	}()
	select {
	case ok := <-ready:
		if ok != "ready" {
			h.t.Fatal("实际HTTP节点未启动", ok, diagnostic.String())
		}
	case <-time.After(12 * time.Second):
		h.t.Fatal("实际HTTP节点启动超时")
	}
	h.processes[node] = cmd
	h.inputs[node] = input
	h.ports[node] = h.port(name)
}
func (h *haHarness) kill(node string) {
	h.t.Helper()
	name := h.names[node]
	h.owned(name)
	h.docker("kill", name)
	if input := h.inputs[node]; input != nil {
		input.Close()
	}
	if cmd := h.processes[node]; cmd != nil {
		cmd.Wait()
	}
	delete(h.processes, node)
	delete(h.inputs, node)
}
func (h *haHarness) client(port string, keepalive bool) *http.Client {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(h.ca)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"}}, DisableKeepAlives: !keepalive, MaxIdleConns: 32, MaxIdleConnsPerHost: 32, MaxConnsPerHost: 32, ForceAttemptHTTP2: false}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "localhost:8443" {
			return nil, ErrDenied
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", "127.0.0.1:"+port)
	}
	h.t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}
}
func haRequest(environment string, secret []byte) (*http.Request, error) {
	return haRequestVersion(environment, secret, 1)
}
func haRequestVersion(environment string, secret []byte, version uint64) (*http.Request, error) {
	r, e := http.NewRequest("POST", "https://localhost:8443/api/auth/probe", strings.NewReader(`{"probe":true}`))
	if e != nil {
		return nil, e
	}
	requestID, e := controlID()
	if e != nil {
		return nil, e
	}
	now := time.Now().Unix()
	m := httpsign.Message{ClientID: "one", Environment: environment, Audience: "keygate-probe", RequestID: requestID, Version: version, Created: now, Expires: now + 60}
	if _, e = rand.Read(m.Nonce[:]); e != nil {
		return nil, e
	}
	e = httpsign.Sign(r, []byte(`{"probe":true}`), secret, m)
	return r, e
}
func haSend(client *http.Client, r *http.Request) (int, string) {
	response, e := client.Do(r)
	if e != nil {
		return 0, ""
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode, response.Header.Get("X-KeyGate-Test-Node")
}
func haProbe(client *http.Client, environment string, secret []byte) (int, string) {
	r, e := haRequest(environment, secret)
	if e != nil {
		return 0, ""
	}
	return haSend(client, r)
}
func haWait(t *testing.T, limit time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("部署状态收敛超时")
}
func haReady(client *http.Client) int {
	r, _ := http.NewRequest("GET", "https://localhost:8443/health/ready", nil)
	code, _ := haSend(client, r)
	return code
}

type haCapacity struct {
	Concurrency    int            `json:"concurrency"`
	Requests       int            `json:"requests"`
	Accepted       int            `json:"accepted"`
	Errors         map[int]int    `json:"errors"`
	Nodes          map[string]int `json:"nodes"`
	Seconds        float64        `json:"seconds"`
	RPS            float64        `json:"acceptedRPS"`
	P50MS          float64        `json:"p50MS"`
	P95MS          float64        `json:"p95MS"`
	P99MS          float64        `json:"p99MS"`
	ConnectionMode string         `json:"connectionMode"`
}

func haLoad(t *testing.T, client *http.Client, environment string, secret []byte, concurrency, total int) haCapacity {
	t.Helper()
	out := haCapacity{Concurrency: concurrency, Requests: total, Errors: map[int]int{}, Nodes: map[string]int{}, ConnectionMode: "http1.1-tls13-keepalive"}
	var mu sync.Mutex
	latencies := []float64{}
	jobs := make(chan int)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				at := time.Now()
				code, node := haProbe(client, environment, secret)
				elapsed := float64(time.Since(at).Microseconds()) / 1000
				mu.Lock()
				latencies = append(latencies, elapsed)
				if code == 200 {
					out.Accepted++
					out.Nodes[node]++
				} else {
					out.Errors[code]++
				}
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	out.Seconds = time.Since(start).Seconds()
	out.RPS = float64(out.Accepted) / out.Seconds
	sort.Float64s(latencies)
	out.P50MS = latencies[len(latencies)/2]
	out.P95MS = latencies[(len(latencies)-1)*95/100]
	out.P99MS = latencies[(len(latencies)-1)*99/100]
	return out
}

// 实际容器/TLS入口、同步复制与故障编排只在独立脚本授权的专用环境运行，生产认证代码不新增旁路。
func TestHADeployment(t *testing.T) {
	run := os.Getenv("KEYGATE_HA_RUN")
	if run == "" {
		t.Skip("需scripts/test-ha-capacity.py独立环境")
	}
	if !strings.HasPrefix(run, "keygate-ha-") || len(run) != 23 {
		t.Fatal("部署演练标识无效")
	}
	names := map[string]string{}
	if json.Unmarshal([]byte(os.Getenv("KEYGATE_HA_NAMES")), &names) != nil {
		t.Fatal("部署清单无效")
	}
	for _, key := range []string{"primary", "standby", "db-router", "lb", "app-a", "app-b"} {
		if names[key] != run+"-"+key {
			t.Fatal("部署资源不属于本演练")
		}
	}
	h := &haHarness{t: t, names: names, run: run, front: os.Getenv("KEYGATE_HA_FRONT"), data: os.Getenv("KEYGATE_HA_DATA"), worker: os.Getenv("KEYGATE_HA_WORKER"), router: os.Getenv("KEYGATE_HA_ROUTER_CONFIG"), processes: map[string]*exec.Cmd{}, inputs: map[string]io.WriteCloser{}, ports: map[string]string{}}
	if h.front != run+"-front" || h.data != run+"-data" {
		t.Fatal("网络不属于本演练")
	}
	for _, key := range []string{"primary", "standby", "db-router"} {
		h.owned(names[key])
	}
	t.Cleanup(func() {
		for key, cmd := range h.processes {
			h.owned(names[key])
			h.docker("rm", "-f", "-v", names[key])
			h.inputs[key].Close()
			cmd.Wait()
		}
	})
	f := newKeyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := f.f.c.store
	material, e := keycrypto.Generate()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(material)
	root := unique(t)
	originalRoot := f.k.rootID
	if e = source.RegisterRootBudget(ctx, root, 100000, Audit{unique(t), unique(t), "offline-bootstrap", "root_budget_register", root, "success"}); e != nil {
		t.Fatal(e)
	}
	f.k, e = NewDevelopmentKeys(f.f.c, root, material, "login-root")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.k.RegisterRootOffline(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.f.db.Exec(`UPDATE keygate.client_roots SET enabled=false WHERE root_id=$1`, originalRoot); e != nil {
		t.Fatal(e)
	}
	issued := f.issue(t, 1)
	bundle, secret := f.claim(t, issued)
	defer clear(secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write(bundle.PossessionInput)
	if e = f.k.ConfirmPossession(ctx, issued.ID, mac.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	f.operation(t, ActivateKey, 1, "")
	cluster, digest := unique(t), strings.Repeat("d", 64)
	if e = source.ConfigureClusterOffline(ctx, cluster, digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	controller, e := source.AcquireNode(ctx, cluster, digest, "controller", unique(t))
	if e != nil {
		t.Fatal(e)
	}
	leaseCtx, stopController := context.WithCancel(ctx)
	defer stopController()
	go controller.RunNodeLease(leaseCtx)
	f.f.c.store = controller
	serverCert, ca, _, _, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(serverCert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(der)
	cert := []byte{}
	for _, v := range serverCert.Certificate {
		cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v})...)
	}
	h.ca = ca
	h.spec = haSpec{processSpec: processSpec{Cluster: cluster, Config: digest, Environment: f.f.c.environment, Profile: f.f.profile, Root: root, Material: material}, Certificate: cert, PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}
	defer clear(h.spec.PrivateKey)
	h.start("app-a", true)
	h.start("app-b", true)
	cfgDir := t.TempDir()
	os.Chmod(cfgDir, 0755)
	os.WriteFile(filepath.Join(cfgDir, "ca.pem"), ca, 0644)
	cfg := "global\n  maxconn 512\ndefaults\n  mode tcp\n  timeout connect 1s\n  timeout client 6s\n  timeout server 6s\nfrontend authentication\n  bind *:8443\n  default_backend authnodes\nbackend authnodes\n  balance roundrobin\n  option httpchk\n  http-check send meth GET uri /health/ready ver HTTP/1.1 hdr Host localhost:8443\n  http-check expect status 200\n  server a app-a:8443 check check-ssl check-sni localhost verify required ca-file /cfg/ca.pem inter 300ms fall 2 rise 2 on-marked-down shutdown-sessions\n  server b app-b:8443 check check-ssl check-sni localhost verify required ca-file /cfg/ca.pem inter 300ms fall 2 rise 2 on-marked-down shutdown-sessions\n"
	os.WriteFile(filepath.Join(cfgDir, "haproxy.cfg"), []byte(cfg), 0644)
	h.docker("run", "-d", "--name", names["lb"], "--label", "ex-keygate.ha-run="+run, "--restart=no", "--network", h.front, "-p", "127.0.0.1::8443", "-v", cfgDir+":/cfg:ro", "haproxy:3.2-alpine", "haproxy", "-db", "-f", "/cfg/haproxy.cfg")
	lbPort := h.port(names["lb"])
	lb := h.client(lbPort, false)
	a := h.client(h.ports["app-a"], false)
	b := h.client(h.ports["app-b"], false)
	haWait(t, 10*time.Second, func() bool { return haReady(lb) == 200 && haReady(a) == 200 && haReady(b) == 200 })
	nodes := map[string]int{}
	for i := 0; i < 8; i++ {
		code, node := haProbe(lb, f.f.c.environment, secret)
		if code != 200 {
			t.Fatal("负载均衡认证失败", code)
		}
		nodes[node]++
	}
	if len(nodes) != 2 {
		t.Fatal("多节点未同时提供认证", nodes)
	}
	replay, e := haRequest(f.f.c.environment, secret)
	if e != nil {
		t.Fatal(e)
	}
	if code, _ := haSend(a, replay); code != 200 {
		t.Fatal("重放前首次认证失败")
	}
	again := replay.Clone(ctx)
	again.Body, _ = replay.GetBody()
	if code, _ := haSend(b, again); code == 200 {
		t.Fatal("跨节点重放成功")
	}
	measurements := map[string]any{"productionStatus": "NOT_VALIDATED", "tls": "TLS1.3 passthrough with verified CA", "baselineNodes": nodes, "replayRejected": true, "faults": []string{}, "capacity": []haCapacity{}}
	capacity := []haCapacity{}
	for _, load := range []struct{ workers, total int }{{1, 40}, {4, 100}, {8, 160}, {16, 240}} {
		capacity = append(capacity, haLoad(t, h.client(lbPort, true), f.f.c.environment, secret, load.workers, load.total))
	}
	measurements["capacity"] = capacity
	// 只切断A的数据网络，保留TLS入口；B继续服务，超过真实租约后A即使重连也不复活。
	partitionAt := time.Now()
	h.owned(names["app-a"])
	h.docker("network", "disconnect", h.data, names["app-a"])
	haWait(t, 8*time.Second, func() bool { return haReady(a) != 200 })
	haWait(t, 10*time.Second, func() bool {
		code, node := haProbe(lb, f.f.c.environment, secret)
		return code == 200 && node == "app-b"
	})
	for i := 0; i < 8; i++ {
		code, node := haProbe(lb, f.f.c.environment, secret)
		if code != 200 || node != "app-b" {
			t.Fatal("隔离节点仍被路由", code, node)
		}
	}
	if remaining := 17*time.Second - time.Since(partitionAt); remaining > 0 {
		time.Sleep(remaining)
	}
	h.docker("network", "connect", h.data, names["app-a"])
	time.Sleep(time.Second)
	if haReady(a) == 200 {
		t.Fatal("过期节点网络恢复后自动复活")
	}
	if code, _ := haProbe(a, f.f.c.environment, secret); code == 200 {
		t.Fatal("过期旧节点接受认证")
	}
	h.kill("app-a")
	h.start("app-a", false)
	a = h.client(h.ports["app-a"], false)
	haWait(t, 8*time.Second, func() bool { return haReady(a) == 200 })
	var incarnation uint64
	if e = f.f.db.QueryRow(`SELECT incarnation FROM keygate.runtime_nodes WHERE node_id='app-a'`).Scan(&incarnation); e != nil || incarnation < 2 {
		t.Fatal("重启节点未推进实例代次", e)
	}
	measurements["networkPartition"] = map[string]any{"seconds": time.Since(partitionAt).Seconds(), "survivingNode": "app-b", "expiredNodeRejectedAfterReconnect": true, "newIncarnation": incarnation}
	// 同步副本必须包含已确认的撤销；旧主先停止且由Docker状态核实，才允许提升备库。
	standbyDB, e := sql.Open("pgx", os.Getenv("KEYGATE_HA_STANDBY_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer standbyDB.Close()
	incident := unique(t)
	if e = f.f.c.Revoke(ctx, f.f.tokens[0], RevocationInput{IncidentID: incident, ClientID: "one", KeyVersion: 1, Reason: "confirmed_leak"}, unique(t)); e != nil {
		t.Fatal(e)
	}
	var replicated bool
	if e = standbyDB.QueryRow(`SELECT EXISTS(SELECT 1 FROM keygate.revocations WHERE environment=$1 AND incident_id=$2)`, f.f.c.environment, incident).Scan(&replicated); e != nil || !replicated {
		t.Fatal("撤销未同步到副本", e)
	}
	// 撤销保持终态，另签发新版本验证切换后的真实可用性。
	issued2 := f.issue(t, 2)
	bundle2, secret2 := f.claim(t, issued2)
	defer clear(secret2)
	proof := hmac.New(sha256.New, secret2)
	proof.Write(bundle2.PossessionInput)
	if e = f.k.ConfirmPossession(ctx, issued2.ID, proof.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	f.operation(t, ActivateKey, 2, "")
	beforeSwitch, e := haRequestVersion(f.f.c.environment, secret2, 2)
	if e != nil {
		t.Fatal(e)
	}
	replayAt := time.Now()
	if code, _ := haSend(lb, beforeSwitch); code != 200 {
		t.Fatal("切换前新版本不可用", code)
	}
	var synchronized bool
	if e = standbyDB.QueryRow(`SELECT EXISTS(SELECT 1 FROM keygate.key_versions WHERE environment=$1 AND client_id='one' AND version=2 AND state='active')`, f.f.c.environment).Scan(&synchronized); e != nil || !synchronized {
		t.Fatal("新版本未同步", e)
	}
	stopController()
	failoverAt := time.Now()
	h.owned(names["primary"])
	h.docker("stop", "-t", "3", names["primary"])
	stopped := strings.TrimSpace(string(h.docker("inspect", "--format", `{{.State.Running}}`, names["primary"]))) == "false"
	if !stopped {
		t.Fatal("旧主未隔离，禁止提升备库")
	}
	request, e := haRequestVersion(f.f.c.environment, secret2, 2)
	if e != nil {
		t.Fatal(e)
	}
	if code, _ := haSend(lb, request); code == 200 {
		t.Fatal("数据库不可用时仍接受认证")
	}
	h.owned(names["standby"])
	h.docker("exec", "--user", "postgres", names["standby"], "pg_ctl", "promote", "-D", "/var/lib/postgresql/data", "-w", "-t", "10")
	haWait(t, 10*time.Second, func() bool {
		var recovery bool
		job, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		return standbyDB.QueryRowContext(job, `SELECT pg_is_in_recovery()`).Scan(&recovery) == nil && !recovery
	})
	// 新权威库先推进代次，再向应用暴露，旧应用许可必须被拒绝；不允许先接流再补做隔离。
	newAuthority, _ := New(standbyDB)
	fenceCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	e = newAuthority.FenceClusterOffline(fenceCtx, unique(t))
	stop()
	if e != nil {
		t.Fatal("新权威库无法隔离旧许可", e)
	}
	routerConfig, e := os.ReadFile(h.router)
	if e != nil {
		t.Fatal(e)
	}
	routerConfig = []byte(strings.ReplaceAll(string(routerConfig), "primary:5432", "standby:5432"))
	if e = os.WriteFile(h.router, routerConfig, 0644); e != nil {
		t.Fatal(e)
	}
	h.owned(names["db-router"])
	h.docker("restart", "-t", "1", names["db-router"])
	for _, client := range []*http.Client{a, b} {
		haWait(t, 10*time.Second, func() bool {
			request, e := haRequestVersion(f.f.c.environment, secret2, 2)
			if e != nil {
				return false
			}
			response, e := client.Do(request)
			if e != nil {
				return false
			}
			defer response.Body.Close()
			io.Copy(io.Discard, response.Body)
			return response.StatusCode == 503 && response.Header.Get("X-KeyGate-Test-Fenced") == "true"
		})
	}
	h.kill("app-a")
	h.kill("app-b")
	h.start("app-a", false)
	h.start("app-b", false)
	a = h.client(h.ports["app-a"], false)
	b = h.client(h.ports["app-b"], false)
	haWait(t, 10*time.Second, func() bool {
		request, e := haRequestVersion(f.f.c.environment, secret2, 2)
		if e != nil {
			return false
		}
		code, _ := haSend(lb, request)
		return code == 200
	})
	if time.Since(replayAt) >= 55*time.Second {
		t.Fatal("超出签名窗口，无法证明切换后重放拒绝")
	}
	replayed := beforeSwitch.Clone(ctx)
	replayed.Body, _ = beforeSwitch.GetBody()
	if code, _ := haSend(lb, replayed); code != 401 {
		t.Fatal("切换后nonce丢失或拒绝原因异常", code)
	}
	for _, client := range []*http.Client{a, b} {
		if code, _ := haProbe(client, f.f.c.environment, secret); code != 401 {
			t.Fatal("切换后接受旧撤销版本或节点异常", code)
		}
		request, e := haRequestVersion(f.f.c.environment, secret2, 2)
		if e != nil {
			t.Fatal(e)
		}
		if code, _ := haSend(client, request); code != 200 {
			t.Fatal("切换后新版本不能认证", code)
		}
	}
	var generation uint64
	if e = standbyDB.QueryRow(`SELECT generation FROM keygate.runtime_cluster WHERE singleton`).Scan(&generation); e != nil {
		t.Fatal(e)
	}
	measurements["databaseFailover"] = map[string]any{"seconds": time.Since(failoverAt).Seconds(), "oldPrimaryStoppedBeforePromotion": stopped, "replicatedRevocationConfirmedBeforeStop": replicated, "replayRejectedAfterSwitch": true, "oldPermitsRejected": true, "newGeneration": generation, "postFailoverReplication": "single-authority-no-second-standby"}
	capacityPass := true
	for _, v := range capacity {
		if float64(v.Requests-v.Accepted)/float64(v.Requests) > .01 || v.P95MS > 1000 {
			capacityPass = false
		}
	}
	measurements["capacityBudget"] = map[string]any{"maxErrorRate": .01, "maxP95MS": 1000, "pass": capacityPass, "scope": "authentication-executor-with-node-lease-and-synchronous-database", "productionSLA": false}
	statsCtx, statsStop := context.WithTimeout(ctx, 8*time.Second)
	defer statsStop()
	stats := exec.CommandContext(statsCtx, "docker", "stats", "--no-stream", "--format", "{{json .}}", names["app-a"], names["app-b"], names["standby"], names["lb"])
	if raw, e := stats.Output(); e == nil {
		measurements["resourceSampleAfterTest"] = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	output := os.Getenv("KEYGATE_HA_OUTPUT")
	encoded, _ := json.MarshalIndent(measurements, "", "  ")
	if e = os.WriteFile(filepath.Join(output, "measurements.json"), encoded, 0600); e != nil {
		t.Fatal(e)
	}
	if !capacityPass {
		t.Fatal("本机容量样本未达到显式验收预算，详见measurements.json")
	}
	t.Log("实际TLS负载均衡、单节点数据库断网、同步数据库提升、旧主停机隔离、旧许可拒绝和容量样本通过")
}
