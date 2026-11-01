// safe-mcp 是 MCP 服务（stdio），让 AI 助手用只读 API 令牌查询管理中心的数据。
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"safe/internal/mcp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-mcp:", err)
		os.Exit(1)
	}
}

// 配置只从环境变量读取：命令行参数中的令牌会出现在进程列表里。
func run() error {
	base, token := strings.TrimRight(os.Getenv("SAFE_URL"), "/"), os.Getenv("SAFE_API_TOKEN")
	if base == "" || token == "" {
		return fmt.Errorf("SAFE_URL and SAFE_API_TOKEN must be set")
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	if file := os.Getenv("SAFE_CA_FILE"); file != "" {
		pem, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates in %s", file)
		}
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	return (&mcp.Server{BaseURL: base, Token: token, HTTP: hc}).Run(context.Background(), os.Stdin, os.Stdout)
}
