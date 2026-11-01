// Package node 实现探针 / Agent 与管理中心之间的证书注册、mTLS 连接和自动续期。
package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"safe/internal/pki"
)

// ErrNotEnrolled 表示本机还没有证书，且没有提供 SAFE_ENROLL_TOKEN。
var ErrNotEnrolled = errors.New("node is not enrolled and SAFE_ENROLL_TOKEN is not set")

type Client struct {
	HTTP *http.Client
	ID   string // 证书中的节点 ID，以它为准

	kind   string
	dir    string
	server string
	cert   atomic.Pointer[tls.Certificate]
}

func (c *Client) keyPath() string  { return filepath.Join(c.dir, "node.key") }
func (c *Client) certPath() string { return filepath.Join(c.dir, "node.crt") }
func (c *Client) caPath() string   { return filepath.Join(c.dir, "ca.crt") }

// Connect 加载本机证书；没有证书时用 SAFE_ENROLL_TOKEN 向管理中心注册。
// 证书和私钥保存在 dir 下，私钥只在本机生成、从不上传。
func Connect(ctx context.Context, kind, id, dir, serverURL string) (*Client, error) {
	c := &Client{kind: kind, dir: dir, server: strings.TrimRight(serverURL, "/")}
	if _, err := os.Stat(c.certPath()); errors.Is(err, os.ErrNotExist) {
		token := os.Getenv("SAFE_ENROLL_TOKEN")
		if token == "" {
			return nil, ErrNotEnrolled
		}
		if err := c.enroll(ctx, token, id); err != nil {
			return nil, fmt.Errorf("enroll: %w", err)
		}
	}

	caPEM, err := os.ReadFile(c.caPath())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate in " + c.caPath())
	}
	if err := c.loadCert(); err != nil {
		return nil, err
	}
	leaf := c.cert.Load().Leaf
	c.ID = leaf.Subject.CommonName
	if id != "" && id != c.ID {
		slog.Warn("configured id differs from certificate; using certificate id", "configured", id, "certificate", c.ID)
	}
	c.HTTP = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return c.cert.Load(), nil
			},
		}},
	}
	return c, nil
}

func (c *Client) loadCert() error {
	cert, err := tls.LoadX509KeyPair(c.certPath(), c.keyPath())
	if err != nil {
		return err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return err
		}
	}
	c.cert.Store(&cert)
	return nil
}

type certResponse struct {
	Cert string `json:"cert"`
	CA   string `json:"ca"`
}

func (c *Client) enroll(ctx context.Context, token, id string) error {
	if id == "" {
		return errors.New("node id is required for enrollment")
	}
	_, fingerprint, ok := strings.Cut(token, ".")
	if !ok || len(fingerprint) != 64 {
		return errors.New("malformed enrollment token")
	}

	// 先不校验证书取回 CA，再用令牌里的指纹校验它：防止首次连接被中间人冒充。
	insecure := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}}
	caPEM, err := get(ctx, insecure, c.server+"/api/v1/ca")
	if err != nil {
		return fmt.Errorf("fetch CA: %w", err)
	}
	if got, err := pki.FingerprintPEM(caPEM); err != nil || got != fingerprint {
		return errors.New("server CA fingerprint does not match enrollment token (wrong server or man-in-the-middle)")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	verified := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}

	keyPEM, csrPEM, err := pki.NewKeyAndCSR(id)
	if err != nil {
		return err
	}
	var resp certResponse
	if err := postJSON(ctx, verified, c.server+"/api/v1/enroll",
		map[string]string{"token": token, "kind": c.kind, "id": id, "csr": string(csrPEM)}, &resp); err != nil {
		return err
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	if err := writeFile(c.keyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFile(c.caPath(), caPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(c.certPath(), []byte(resp.Cert), 0o644); err != nil {
		return err
	}
	slog.Info("enrolled with management server", "kind", c.kind, "id", id)
	return nil
}

// RenewLoop 定期检查证书，剩余有效期不足 pki.RenewBefore 时自动续期。
func (c *Client) RenewLoop(ctx context.Context) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		if time.Until(c.cert.Load().Leaf.NotAfter) < pki.RenewBefore {
			if err := c.Renew(ctx); err != nil {
				slog.Error("certificate renewal failed, will retry", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Renew 生成新私钥并换取新证书。服务端换发后旧证书立即失效，因此新文件先写到 .new 再替换。
func (c *Client) Renew(ctx context.Context) error {
	keyPEM, csrPEM, err := pki.NewKeyAndCSR(c.ID)
	if err != nil {
		return err
	}
	if err := writeFile(c.keyPath()+".new", keyPEM, 0o600); err != nil {
		return err
	}
	var resp certResponse
	if err := postJSON(ctx, c.HTTP, c.server+"/api/v1/node/renew", map[string]string{"csr": string(csrPEM)}, &resp); err != nil {
		return err
	}
	if err := writeFile(c.certPath()+".new", []byte(resp.Cert), 0o644); err != nil {
		return err
	}
	if err := os.Rename(c.keyPath()+".new", c.keyPath()); err != nil {
		return err
	}
	if err := os.Rename(c.certPath()+".new", c.certPath()); err != nil {
		return err
	}
	if err := c.loadCert(); err != nil {
		return err
	}
	// 已建立的 keep-alive 连接仍绑定旧证书，必须断开，后续请求才会用新证书重新握手。
	c.HTTP.CloseIdleConnections()
	slog.Info("certificate renewed", "expires", c.cert.Load().Leaf.NotAfter)
	return nil
}

func get(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func postJSON(ctx context.Context, hc *http.Client, url string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("POST %s: %s %s", url, resp.Status, e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
