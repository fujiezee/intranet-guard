// Package release 对 Agent 发布包做离线签名和验证。私钥不进入管理中心和 CI，
// 所以管理中心被攻破时，攻击者也无法让 Agent 接受自己构造的程序。
package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// message 把版本、文件名和哈希绑定在一起：签名不能用于其他版本或其他平台的程序。
func message(version, file, sha256Hex string) []byte {
	return []byte("intranet-guard-agent-release-v1\n" + version + "\n" + file + "\n" + sha256Hex + "\n")
}

func Sign(key ed25519.PrivateKey, version, file, sha256Hex string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, message(version, file, sha256Hex)))
}

// Verify 用逗号分隔的公钥列表验证签名，任意一个通过即可（更换密钥时新旧公钥并存）。
func Verify(publicKeys, version, file, sha256Hex, signature string) error {
	if strings.TrimSpace(publicKeys) == "" {
		return errors.New("this build has no release public key")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("missing or malformed signature")
	}
	for _, k := range strings.Split(publicKeys, ",") {
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid release public key %q", k)
		}
		if ed25519.Verify(pub, message(version, file, sha256Hex), sig) {
			return nil
		}
	}
	return errors.New("signature does not match")
}
