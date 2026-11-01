package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerify(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	otherPub, otherKey, _ := ed25519.GenerateKey(nil)
	pubs := base64.StdEncoding.EncodeToString(pub)
	other := base64.StdEncoding.EncodeToString(otherPub)
	sum := strings.Repeat("a", 64)
	sig := Sign(key, "1.0.0", "safe-agent-linux-amd64", sum)

	if err := Verify(pubs, "1.0.0", "safe-agent-linux-amd64", sum, sig); err != nil {
		t.Fatal(err)
	}
	if err := Verify(other+","+pubs, "1.0.0", "safe-agent-linux-amd64", sum, sig); err != nil {
		t.Errorf("second key: %v", err)
	}
	for name, err := range map[string]error{
		"other version":  Verify(pubs, "1.0.1", "safe-agent-linux-amd64", sum, sig),
		"other file":     Verify(pubs, "1.0.0", "safe-agent-linux-arm64", sum, sig),
		"other hash":     Verify(pubs, "1.0.0", "safe-agent-linux-amd64", strings.Repeat("b", 64), sig),
		"other key":      Verify(pubs, "1.0.0", "safe-agent-linux-amd64", sum, Sign(otherKey, "1.0.0", "safe-agent-linux-amd64", sum)),
		"no signature":   Verify(pubs, "1.0.0", "safe-agent-linux-amd64", sum, ""),
		"no public key":  Verify("", "1.0.0", "safe-agent-linux-amd64", sum, sig),
		"bad public key": Verify("abc", "1.0.0", "safe-agent-linux-amd64", sum, sig),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
