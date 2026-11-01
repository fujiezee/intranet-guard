package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCALifecycle(t *testing.T) {
	dir := t.TempDir()
	ca, created, err := LoadOrCreateCA(dir)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	again, created, err := LoadOrCreateCA(dir)
	if err != nil || created || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload: created=%v err=%v", created, err)
	}

	keyPEM, csrPEM, err := NewKeyAndCSR("forged-name")
	if err != nil || len(keyPEM) == 0 {
		t.Fatal(err)
	}
	certPEM, cert, err := ca.SignCSR(csrPEM, "agent", "web01")
	if err != nil {
		t.Fatal(err)
	}
	// 主体由 CA 决定，不信任 CSR 里的名字。
	if cert.Subject.CommonName != "web01" || cert.Subject.OrganizationalUnit[0] != "agent" {
		t.Errorf("subject = %v", cert.Subject)
	}
	b, _ := pem.Decode(certPEM)
	parsed, _ := x509.ParseCertificate(b.Bytes)
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client cert does not verify: %v", err)
	}

	srv, err := ca.IssueServerCert([]string{"localhost", "127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(srv.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "127.0.0.1"}); err != nil {
		t.Errorf("server cert does not verify: %v", err)
	}

	if _, _, err := ca.SignCSR([]byte("garbage"), "agent", "x"); err == nil {
		t.Error("garbage CSR accepted")
	}
	if fp, _ := FingerprintPEM(ca.CertPEM); fp != ca.Fingerprint() {
		t.Error("fingerprint mismatch")
	}
}

func TestServerKeyPinStable(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := PublicKeyPin(k1)
	p2, _ := PublicKeyPin(k2)
	if p1 != p2 || len(p1) != len("sha256//")+44 {
		t.Errorf("pin not stable or malformed: %q %q", p1, p2)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "server.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("server.key mode = %v", fi.Mode().Perm())
	}
}
