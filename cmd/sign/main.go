// safe-sign 生成发布密钥并给 Agent 程序签名。请在离线环境运行，私钥不要放到管理中心、CI 或代码仓库。
//
//	safe-sign keygen <目录>                                      生成 release.key（私钥）和 release.pub（公钥）
//	safe-sign sign -key 私钥 -pub 公钥 -version 版本 [-name 文件名] 程序...   为每个程序写入 <程序>.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"safe/internal/release"
)

func main() {
	var err error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "keygen":
		err = keygen(os.Args[2])
	case len(os.Args) > 2 && os.Args[1] == "sign":
		err = sign(os.Args[2:])
	default:
		err = errors.New("usage: safe-sign keygen <dir> | safe-sign sign -key FILE -pub KEY_OR_FILE -version V [-name NAME] FILE...")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "safe-sign:", err)
		os.Exit(1)
	}
}

func keygen(dir string) error {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// O_EXCL：不覆盖已有私钥，覆盖后已发布的 Agent 将无法再升级
	f, err := os.OpenFile(filepath.Join(dir, "release.key"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.WriteString(f, base64.StdEncoding.EncodeToString(key)+"\n"); err != nil {
		return err
	}
	pubText := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(dir, "release.pub"), []byte(pubText+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Println("public key:", pubText)
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "private key file")
	pubArg := fs.String("pub", "", "expected public key, or a file holding it")
	version := fs.String("version", "", "version these programs report")
	name := fs.String("name", "", "file name on the download server (default: the file's own name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *pubArg == "" || *version == "" || fs.NArg() == 0 {
		return errors.New("-key, -pub, -version and at least one file are required")
	}
	if *name != "" && fs.NArg() != 1 {
		return errors.New("-name works with a single file")
	}
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return errors.New("invalid private key file")
	}
	pub := *pubArg
	if b, err := os.ReadFile(pub); err == nil {
		pub = strings.TrimSpace(string(b))
	}
	for _, path := range fs.Args() {
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		fileName := *name
		if fileName == "" {
			fileName = filepath.Base(path)
		}
		sig := release.Sign(ed25519.PrivateKey(raw), *version, fileName, sum)
		// 用预期的公钥验证一次：私钥和程序内置的公钥不匹配时在这里发现，而不是到所有 Agent 升级失败才发现
		if err := release.Verify(pub, *version, fileName, sum, sig); err != nil {
			return fmt.Errorf("%s: private key does not match public key: %w", path, err)
		}
		if err := os.WriteFile(path+".sig", []byte(sig+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
