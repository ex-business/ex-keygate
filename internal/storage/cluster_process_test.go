package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"ex-keygate/internal/config"
	"ex-keygate/internal/httpsign"
	"ex-keygate/internal/keycrypto"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type processSpec struct {
	Cluster, Config, Node, Environment, Profile, Root string
	Material                                          []byte
}
type processReply struct {
	Failure  string
	Ready    bool
	Accepted bool
}

// 子进程只通过匿名管道接收测试根，禁止写文件、环境变量或命令行；不构成生产根分发机制。
func TestClusterProcessWorker(t *testing.T) {
	if os.Getenv("KEYGATE_CLUSTER_WORKER") != "1" {
		t.Skip("仅由独立进程验收启动")
	}
	in := json.NewDecoder(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	var spec processSpec
	if in.Decode(&spec) != nil {
		t.Fatal("测试输入无效")
	}
	defer clear(spec.Material)
	db, e := sql.Open("pgx", os.Getenv("KEYGATE_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal("测试数据库打开失败")
	}
	defer db.Close()
	s, _ := New(db)
	node, e := s.AcquireNode(context.Background(), spec.Cluster, spec.Config, spec.Node, "process-"+spec.Node+"-"+time.Now().Format("150405.000000000"))
	if e != nil {
		t.Fatal("测试节点登记失败")
	}
	control, e := NewDevelopmentControl(config.Test, spec.Environment, spec.Profile, node)
	if e != nil {
		t.Fatal("测试控制域无效")
	}
	keys, e := NewDevelopmentKeys(control, spec.Root, spec.Material, "login-root")
	clear(spec.Material)
	if e != nil {
		t.Fatal("测试根无效")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.RunNodeLease(ctx)
	if out.Encode(processReply{Ready: true}) != nil {
		t.Fatal("测试输出失败")
	}
	for {
		var raw []byte
		if e = in.Decode(&raw); e == io.EOF {
			return
		} else if e != nil {
			t.Fatal("测试请求无效")
		}
		r, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if e != nil {
			t.Fatal("测试HTTP无效")
		}
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		body, e := io.ReadAll(r.Body)
		r.Body.Close()
		if e != nil {
			t.Fatal("测试正文无效")
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		e = keys.AuthenticateProbe(bounded, r, body, "keygate-probe")
		stop()
		reason := ""
		if e != nil {
			reason = "authentication"
			if _, parseErr := httpsign.Parse(r, body); parseErr != nil {
				reason = "wire"
			}
			if node.CheckReadiness(ctx) != nil {
				reason = "node"
			}
			if keys.CheckHealth(ctx) != nil {
				reason = "root"
			}
		}
		if out.Encode(processReply{Accepted: e == nil, Failure: reason}) != nil {
			t.Fatal("测试输出失败")
		}
	}
}

type processNode struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *json.Decoder
}

func startProcessNode(t *testing.T, spec processSpec) *processNode {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestClusterProcessWorker$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "KEYGATE_CLUSTER_WORKER=1")
	input, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	// 子进程日志不包含密钥；失败信息只保留通用状态，不向输出回显输入管道。
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	p := &processNode{cmd, input, json.NewDecoder(output)}
	t.Cleanup(func() { input.Close(); cmd.Process.Kill(); cmd.Wait() })
	if e = json.NewEncoder(input).Encode(spec); e != nil {
		t.Fatal("测试节点配置发送失败")
	}
	var ready processReply
	if p.output.Decode(&ready) != nil || !ready.Ready {
		t.Fatal("独立测试节点未就绪")
	}
	return p
}
func (p *processNode) authenticate(t *testing.T, request *http.Request) bool {
	t.Helper()
	wire := request.Clone(context.Background())
	// 使用发送端序列化补齐 Content-Length，避免 DumpRequest 将出站结构误当作已解析入站头。
	if request.GetBody == nil {
		t.Fatal("测试请求缺少可重复读取正文")
	}
	body, e := request.GetBody()
	if e != nil {
		t.Fatal(e)
	}
	defer body.Close()
	wire.Body = body
	var buffer bytes.Buffer
	if e = wire.Write(&buffer); e != nil {
		t.Fatal(e)
	}
	raw := buffer.Bytes()
	if e = json.NewEncoder(p.input).Encode(raw); e != nil {
		t.Fatal("测试请求发送失败")
	}
	var reply processReply
	if e = p.output.Decode(&reply); e != nil {
		t.Fatal("测试节点应答失败")
	}
	if !reply.Accepted {
		t.Log("独立节点拒绝阶段", reply.Failure)
	}
	return reply.Accepted
}
func TestClusterSeparateProcessesSurviveNodeFailure(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	material, e := keycrypto.Generate()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(material)
	root := unique(t)
	s := f.f.c.store
	if e = s.RegisterRootBudget(ctx, root, 1000, Audit{unique(t), unique(t), "offline-bootstrap", "root_budget_register", root, "success"}); e != nil {
		t.Fatal(e)
	}
	f.k, e = NewDevelopmentKeys(f.f.c, root, material, "login-root")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.k.RegisterRootOffline(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	issue := f.issue(t, 1)
	bundle, secret := f.claim(t, issue)
	defer clear(secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write(bundle.PossessionInput)
	if e = f.k.ConfirmPossession(ctx, issue.ID, mac.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	f.operation(t, ActivateKey, 1, "")
	cluster, digest := unique(t), strings.Repeat("f", 64)
	if e = s.ConfigureClusterOffline(ctx, cluster, digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, e := s.db.Exec(`DELETE FROM keygate.runtime_nodes; UPDATE keygate.runtime_cluster SET enabled=false,cluster_id='',configuration_hash='',generation=generation+1`)
		if e != nil {
			t.Error(e)
		}
	})
	spec := processSpec{Cluster: cluster, Config: digest, Node: "process-a", Environment: f.f.c.environment, Profile: f.f.profile, Root: root, Material: material}
	a := startProcessNode(t, spec)
	spec.Node = "process-b"
	b := startProcessNode(t, spec)
	body := []byte(`{"probe":true}`)
	request, _ := signedProbe(t, f, secret, body)
	if !a.authenticate(t, request) {
		t.Fatal("节点A认证失败")
	}
	if b.authenticate(t, request) {
		t.Fatal("跨进程重放被接受")
	}
	request, _ = signedProbe(t, f, secret, body)
	if !b.authenticate(t, request) {
		t.Fatal("节点B不能同时提供认证")
	}
	if e = a.cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	request, _ = signedProbe(t, f, secret, body)
	if !b.authenticate(t, request) {
		t.Fatal("节点A退出后B不可用")
	}
	// 实际等待死亡节点租约到期；B独立续约仍提供服务，重启A必须取得更高实例代次。
	time.Sleep(NodeLeaseDuration + time.Second)
	spec.Node = "process-a"
	restarted := startProcessNode(t, spec)
	var incarnation uint64
	if e = s.db.QueryRow(`SELECT incarnation FROM keygate.runtime_nodes WHERE node_id='process-a'`).Scan(&incarnation); e != nil || incarnation != 2 {
		t.Fatal("重启未推进实例代次", e)
	}
	if restarted.authenticate(t, request) {
		t.Fatal("重启节点接受已消费的请求")
	}
	request, _ = signedProbe(t, f, secret, body)
	if !restarted.authenticate(t, request) {
		t.Fatal("重启节点无法继续认证")
	}
	request, _ = signedProbe(t, f, secret, body)
	if !b.authenticate(t, request) {
		t.Fatal("另一节点续约失效")
	}
}
