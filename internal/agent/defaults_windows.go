//go:build windows

package agent

import (
	"os"
	"path/filepath"
)

func init() {
	root := envOr("SystemRoot", `C:\Windows`)
	programData := envOr("ProgramData", `C:\ProgramData`)
	// hosts 被篡改可劫持域名；所有用户的启动文件夹是常见的持久化位置
	DefaultFIMPaths = []string{
		filepath.Join(root, `System32\drivers\etc\hosts`),
		filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`),
	}
	DefaultWebDirs = []string{envOr("SystemDrive", "C:") + `\inetpub\wwwroot`}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
