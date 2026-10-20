// Package trustnotify 通过固定HTTPS/mTLS插件传递公开证书到期提醒，插件负责邮件或短信收件人及幂等投递。
package trustnotify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"ex-keygate/internal/storage"
	"ex-keygate/trustchain"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

var ErrPlugin = errors.New("证书提醒插件调用失败")

type Config struct {
	AllowedIPs      []string `json:"allowedIPs"`
	URL             string   `json:"url"`
	CAFile          string   `json:"caFile"`
	CertificateFile string   `json:"certificateFile"`
	KeyFile         string   `json:"keyFile"`
}
type Plugin struct {
	url    string
	client *http.Client
}

func New(c Config) (*Plugin, error) {
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, ErrPlugin
	}
	ca, e := trustchain.ReadFile(c.CAFile, false)
	if e != nil {
		return nil, ErrPlugin
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrPlugin
	}
	certPEM, e := trustchain.ReadFile(c.CertificateFile, false)
	if e != nil {
		return nil, ErrPlugin
	}
	keyPEM, e := trustchain.ReadFile(c.KeyFile, true)
	if e != nil {
		return nil, ErrPlugin
	}
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if e != nil {
		return nil, ErrPlugin
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	number, e := strconv.Atoi(port)
	if e != nil || number < 1 || number > 65535 {
		return nil, ErrPlugin
	}
	if len(c.AllowedIPs) < 1 || len(c.AllowedIPs) > 4 {
		return nil, ErrPlugin
	}
	pins := []netip.Addr{}
	for _, raw := range c.AllowedIPs {
		ip, e := netip.ParseAddr(raw)
		if e != nil || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, ErrPlugin
		}
		pins = append(pins, ip)
	}
	if literal, e := netip.ParseAddr(host); e == nil {
		found := false
		for _, ip := range pins {
			if ip == literal {
				found = true
			}
		}
		if !found {
			return nil, ErrPlugin
		}
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: host}, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	dialer := net.Dialer{Timeout: time.Second}
	// 固定目标IP并保留证书主机名校验，避免代理和DNS重绑定改变管理员批准的插件目的地。
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(host, port) {
			return nil, ErrPlugin
		}
		for _, ip := range pins {
			conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, ErrPlugin
	}

	return &Plugin{url: c.URL, client: &http.Client{Timeout: 10 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrPlugin }}}, nil
}
func (p *Plugin) SendTrustReminder(ctx context.Context, v storage.TrustReminder) error {
	// 尝试次数和内部状态不进入投递正文，同一幂等键重试必须发送完全相同的业务内容。
	payload := struct {
		ID              string    `json:"id"`
		RootFingerprint string    `json:"rootFingerprint"`
		ServiceID       string    `json:"serviceId"`
		Kind            string    `json:"kind"`
		Fingerprint     string    `json:"fingerprint"`
		ExpiresAt       time.Time `json:"expiresAt"`
		Severity        string    `json:"severity"`
	}{v.ID, v.RootFingerprint, v.ServiceID, v.Kind, v.Fingerprint, v.ExpiresAt, v.Severity}
	raw, e := json.Marshal(payload)
	if e != nil {
		return ErrPlugin
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(raw))
	if e != nil {
		return ErrPlugin
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", v.ID)
	response, e := p.client.Do(r)
	if e != nil {
		return ErrPlugin
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	// 只有同步确认接收才标为sent；插件返回202仍按未知结果重试同一幂等键。
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return ErrPlugin
	}
	return nil
}

func (p *Plugin) Close() { p.client.CloseIdleConnections() }
