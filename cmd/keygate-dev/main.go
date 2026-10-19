package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ex-keygate/internal/auditarchive"
	"ex-keygate/internal/config"
	"ex-keygate/internal/devtls"
	"ex-keygate/internal/identity"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/keyservice"
	"ex-keygate/internal/localcert"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/storage"
	"ex-keygate/internal/webauth"
	"ex-keygate/provider"
	"ex-keygate/trustchain"
)

func main() {
	if err := run(); err != nil {
		slog.Error("开发控制台启动或运行失败", "error", err)
		os.Exit(1)
	}
}
func run() error {
	trustDirectory := flag.String("trust-directory", "", "应用根证书及专用状态签名密钥目录，不允许包含根私钥")
	localAccountsFile := flag.String("local-accounts-file", "", "受控本地账号配置，仅含口令摘要（私有文件）")
	tlsDirectory := flag.String("tls-dir", "", "本机固定TLS证书私有目录（cert.pem/key.pem/ca.pem）")
	mfaConfigFile := flag.String("mfa-config-file", "", "受控离线MFA绑定与人员流转配置（私有文件）")
	mfaPluginsFile := flag.String("mfa-plugins-file", "", "MFA邮件/短信/硬件mTLS插件配置（私有文件）")
	resumeEnvironment := flag.String("resume-environment", "", "显式恢复已隔离的开发管理域")
	resumeCheckpoint := flag.String("resume-checkpoint", "", "隔离后最新的独立签名状态校验点")
	resumePublicKey := flag.String("resume-public-key", "", "独立固定的可信校验公钥文件")
	enableFlow := flag.Bool("enable-key-flow", false, "Enable simulated development-only client/key workflow")
	port := flag.Int("port", 18761, "Loopback console TLS port")
	databaseFile := flag.String("database-file", "data/dev-console/database-url", "Private disposable development database URL file")
	ssoFile := flag.String("sso-file", "data/mock-sso/connection.json", "可信 OIDC/SSO 连接配置（默认使用本机模拟配置）")
	ssoSecretFile := flag.String("sso-secret-file", "", "可选 OIDC confidential client 私有密钥文件（0600）")
	output := flag.String("output", "data/dev-console", "Private directory for public console CA and metadata")
	pluginFile := flag.String("plugin-file", "", "受信的私有开发插件连接配置文件")
	flag.Parse()
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	if (cfg.Environment != config.Development && cfg.Environment != config.Test) || cfg.RootMode != config.DevelopmentSoftware {
		return errors.New("development console requires a development/test environment and development_software root mode")
	}
	raw, err := os.ReadFile(*ssoFile)
	if err != nil {
		return errors.New("SSO 连接配置不可用")
	}
	sso, err := identity.ParseConnection(raw)
	if err != nil {
		return errors.New("SSO 连接配置无效")
	}
	// 外部身份平台绝不走模拟账号初始化，防止把测试角色授予真实人员。
	if !sso.DevelopmentOnly && (*enableFlow || *resumeEnvironment != "") {
		return errors.New("外部 SSO 不允许模拟授权初始化或恢复；请使用受控离线授权接入")
	}
	secret := ""
	if *ssoSecretFile != "" {
		value, e := readPrivate(*ssoSecretFile)
		if e != nil {
			return errors.New("SSO 客户端密钥文件不可用")
		}
		secret = strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r")
		clear(value)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	origin := "https://localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if sso.RedirectURI != origin+"/auth/callback" {
		return errors.New("SSO 回调必须精确匹配本机控制台地址")
	}
	// 真实公网 IdP 默认使用系统信任；私有 CA 只加入本连接的专用池，不修改系统证书。
	var roots *x509.CertPool
	if sso.CAFile != "" {
		ca, e := os.ReadFile(sso.CAFile)
		if e != nil {
			return errors.New("SSO CA 文件不可用")
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return errors.New("SSO CA 文件无效")
		}
	}
	if sso.DevelopmentOnly && roots == nil {
		return errors.New("模拟 SSO 必须显式固定测试 CA")
	}
	dsn, err := readPrivate(*databaseFile)
	if err != nil {
		return err
	}
	databaseURL := strings.TrimSpace(string(dsn))
	if !developmentDatabase(databaseURL) {
		clear(dsn)
		return errors.New("database URL must target a loopback keygate_dev database")
	}
	db, err := sql.Open("pgx", databaseURL)
	clear(dsn)
	if err != nil {
		return errors.New("invalid development database configuration")
	}
	defer db.Close()
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(10 * time.Minute)
	startup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = db.PingContext(startup); err != nil {
		return errors.New("development database connection failed")
	}
	// 此命令仅管理专用临时开发数据库；生产迁移不从这里执行。
	if err = storage.Migrate(startup, db); err != nil {
		return errors.New("development schema initialization failed")
	}
	store, _ := storage.New(db)
	key, err := keycrypto.Generate()
	if err != nil {
		return err
	}
	var rootRandom [16]byte
	if _, err = rand.Read(rootRandom[:]); err != nil {
		return err
	}
	rootID := "dev-root-" + hex.EncodeToString(rootRandom[:])
	if err = store.RegisterRootBudget(startup, rootID, 100000, storage.Audit{EventID: rootID, RequestID: "development_bootstrap", ActorID: "development_bootstrap", Action: "root_budget_register", TargetID: rootID, Result: "success"}); err != nil {
		return errors.New("development root budget initialization failed")
	}
	protector, err := keyservice.NewDevelopment(cfg.Environment, rootID, key, store)
	clear(key)
	if err != nil {
		return err
	}
	var mfaPlugins mfa.Plugins
	pluginHash := ""
	if *mfaPluginsFile != "" {
		raw, e := readPrivate(*mfaPluginsFile)
		if e != nil {
			return errors.New("MFA插件配置不可用")
		}
		var closePlugins func()
		mfaPlugins, pluginHash, closePlugins, e = mfa.LoadPlugins(raw)
		if e != nil {
			return errors.New("MFA插件配置无效")
		}
		defer closePlugins()
	}
	identityConfig := sso.IdentityConfig()
	identityConfig.TrustedRoots = roots
	service, err := webauth.New(webauth.Config{Environment: cfg.Environment, MFAPlugins: mfaPlugins, MFAPluginPolicyHash: pluginHash, Identity: identityConfig, TokenAuthMethod: sso.TokenAuthMethod, ClientSecret: secret, AuthorizationEndpoint: sso.AuthorizationEndpoint, TokenEndpoint: sso.TokenEndpoint, CallbackURL: sso.RedirectURI, PolicyVersion: 2}, store, protector)
	if err != nil {
		return errors.New("development login configuration rejected")
	}
	if *resumeEnvironment != "" {
		if !*enableFlow {
			return errors.New("恢复必须显式启用开发流程")
		}
		pub, e := auditarchive.ReadPrivate(*resumePublicKey, 32)
		if e != nil {
			return errors.New("恢复可信公钥不可用")
		}
		raw, e := auditarchive.VerifySignedFile(*resumeCheckpoint, ed25519.PublicKey(pub))
		if e != nil {
			return errors.New("恢复校验点签名无效")
		}
		var expected storage.SafetyCheckpoint
		if json.Unmarshal(raw, &expected) != nil || expected.Environment != *resumeEnvironment {
			return errors.New("恢复域与校验点不符")
		}
		if e = store.VerifySafetyCheckpoint(startup, expected); e != nil {
			return errors.New("恢复状态与外部校验点不一致")
		}
		if e = service.ResumeQuarantinedSimulatedFlow(startup, *resumeEnvironment); e != nil {
			return errors.New("恢复域尚未完成隔离")
		}
	} else if *enableFlow {
		if err = service.EnableSimulatedFlow(startup); err != nil {
			return errors.New("simulated key workflow initialization failed")
		}
	}
	if *enableFlow {
		if e := service.ConfigureDevelopmentPlugins(startup, *pluginFile); e != nil {
			return errors.New("开发插件装配失败")
		}
		defer service.ClosePlugins()
	} else if *pluginFile != "" {
		return errors.New("插件装配必须显式开启开发流程")
	}
	if *mfaConfigFile != "" {
		raw, e := readPrivate(*mfaConfigFile)
		if e != nil {
			return errors.New("MFA离线绑定配置不可用")
		}
		var plan webauth.MFAEnrollmentPlan
		if provider.DecodeStrict(raw, &plan) != nil {
			return errors.New("MFA离线绑定配置无效")
		}
		if e = service.ProvisionNativeMFAOffline(startup, plan); e != nil {
			return errors.New("MFA离线配置失败，未开放HTTP服务")
		}
	}
	if *localAccountsFile != "" {
		raw, e := readPrivate(*localAccountsFile)
		if e != nil {
			return errors.New("本地账号配置不可用")
		}
		var plan webauth.LocalAccountPlan
		if provider.DecodeStrict(raw, &plan) != nil {
			return errors.New("本地账号配置无效")
		}
		if e = service.ProvisionLocalAccountsOffline(startup, plan); e != nil {
			return errors.New("本地账号绑定失败，未开放HTTP服务")
		}
	}

	if *trustDirectory != "" {
		if trustchain.PrivateDirectory(*trustDirectory, false) != nil {
			return errors.New("应用信任链目录必须为私有目录")
		}
		if _, e := os.Lstat(filepath.Join(*trustDirectory, "root.key")); !os.IsNotExist(e) {
			return errors.New("管理服务不得加载包含根私钥的目录")
		}
		root, e := trustchain.ReadCertificate(filepath.Join(*trustDirectory, "root.pem"))
		if e != nil {
			return errors.New("应用根证书不可用")
		}
		status, e := trustchain.ReadCertificate(filepath.Join(*trustDirectory, "status.pem"))
		if e != nil {
			return errors.New("状态签名证书不可用")
		}
		key, e := trustchain.ReadPrivateKey(filepath.Join(*trustDirectory, "status.key"))
		if e != nil {
			return errors.New("状态签名私钥不可用")
		}
		defer clear(key)
		raw, e := trustchain.ReadFile(filepath.Join(*trustDirectory, "runtime.json"), false)
		if e != nil {
			return errors.New("应用环境配置不可用")
		}
		var runtime struct {
			Environment string `json:"environment"`
		}
		if trustchain.DecodeJSON(raw, &runtime) != nil {
			return errors.New("应用环境配置无效")
		}
		if e = service.ConfigureApplicationTrust(startup, runtime.Environment, root, status, key); e != nil {
			return errors.New("应用信任链装配失败")
		}
	}

	var cert tls.Certificate
	var publicCA []byte
	if *tlsDirectory != "" {
		cert, publicCA, err = localcert.Load(*tlsDirectory)
	} else {
		cert, publicCA, err = devtls.Certificate("ExKeyGate Development Console")
	}
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*output, 0700); err != nil {
		return err
	}
	info, err := os.Stat(*output)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("development output directory must be private")
	}
	absolute, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(absolute, "ca.pem"), publicCA, 0600); err != nil {
		return err
	}
	metadata, _ := json.MarshalIndent(map[string]any{"developmentOnly": true, "origin": origin, "loginUrl": origin + "/auth/login", "sessionUrl": origin + "/auth/session", "caFile": filepath.Join(absolute, "ca.pem"), "keyFlowEnabled": *enableFlow, "manageUrl": origin + "/manage"}, "", "  ")
	if err = os.WriteFile(filepath.Join(absolute, "connection.json"), metadata, 0600); err != nil {
		return err
	}
	server := &http.Server{Handler: service.Handler(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	maintenanceDone := make(chan struct{})
	go func() { defer close(maintenanceDone); service.RunLifecycleMaintenance(ctx) }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
	}()
	if *enableFlow {
		slog.Info("开发密钥流程控制台已启动，模拟身份按独立本地授权访问", "origin", origin, "config_file", filepath.Join(absolute, "connection.json"))
	} else {
		slog.Info("开发登录控制台已启动，仅验证身份，不授予管理权限", "origin", origin, "config_file", filepath.Join(absolute, "connection.json"))
	}
	err = server.Serve(tls.NewListener(listener, server.TLSConfig))
	stop()
	<-done
	<-maintenanceDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func readPrivate(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database URL file must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("database URL file unavailable")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database URL file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) == 0 || len(data) > 8192 {
		return nil, errors.New("database URL file size invalid")
	}
	return data, nil
}

func developmentDatabase(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Path != "/keygate_dev" || u.Fragment != "" || u.User == nil {
		return false
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 1 || len(query["sslmode"]) != 1 || query.Get("sslmode") != "disable" {
		return false
	}
	return true
}
