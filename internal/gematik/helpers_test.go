package gematik

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUUID7(t *testing.T) {
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	id := newUUID7(at)
	ts, ok := uuid7Time(id)
	if !ok || !ts.Equal(at) {
		t.Fatalf("uuid7Time(%s) = %v, %v", id, ts, ok)
	}
	for _, bad := range []string{"", "not-a-uuid", "0190f3a0-0000-4000-8000-000000000000" /* v4 */, "0190f3a0-0000-7000-c000-000000000000" /* variant */} {
		if _, ok := uuid7Time(bad); ok {
			t.Errorf("uuid7Time(%q) accepted", bad)
		}
	}
}

func TestKeyStrength(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if _, ok := keyStrength(&p256.PublicKey); !ok {
		t.Error("P-256 rejected")
	}
	if _, ok := keyStrength(&p224.PublicKey); ok {
		t.Error("P-224 accepted")
	}
}

func TestExactly(t *testing.T) {
	if !exactly([]string{"code"}, "code") || exactly([]string{"code", "token"}, "code") || exactly(nil, "code") {
		t.Fatal("exactly() is wrong")
	}
}

func TestCertHasOID(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	role, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 260})
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3}, Value: append([]byte{0x30, byte(len(role))}, role...)}}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	if !certHasOID(cert, "1.2.276.0.76.4.260") {
		t.Error("role OID inside admission extension not found")
	}
	if certHasOID(cert, "1.2.276.0.76.4.261") {
		t.Error("unrelated OID found")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := selfSigned(key, "fd", nil, nil, false)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("fd.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	write("fd.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
	write("enc.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
	t.Setenv("CTK_PW", "pw")
	write("idp.yaml", []byte(`
idp: {entity_id: https://idp.example.de}
fachdienst:
  client_id: https://fd.example.de
  redirect_uri: https://fd.example.de/cb
  tls_cert: fd.crt
  tls_key: fd.key
  enc_key: enc.key
login: {username: u, password: "${CTK_PW}", steps: [{name: login, form: "form"}]}
`))
	c, err := Load(filepath.Join(dir, "idp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.IDP.EntityStatementURL != "https://idp.example.de/.well-known/openid-federation" || c.Fachdienst.encKey == nil ||
		len(c.Fachdienst.cert.Certificate) == 0 || c.Login.Password != "pw" || c.Login.Method != "form" {
		t.Fatalf("unexpected config: %+v", c)
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKCS8PrivateKey(p384)
	write("enc384.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der384}))
	write("p384.yaml", []byte("idp: {entity_id: https://idp.example.de}\nfachdienst: {client_id: https://fd, redirect_uri: https://fd/cb, tls_cert: fd.crt, tls_key: fd.key, enc_key: enc384.key}\n"))
	if _, err := Load(filepath.Join(dir, "p384.yaml")); err == nil || !strings.Contains(err.Error(), "A_23196") {
		t.Errorf("P-384 enc_key must be rejected per A_23196: %v", err)
	}

	write("bad.yaml", []byte("idp: {entity_id: relative}\nlogin: {method: egk}\nfachdienst: {client_id: x}\n"))
	_, err = Load(filepath.Join(dir, "bad.yaml"))
	for _, want := range []string{"absolute URL", "login.method \"egk\" is not supported", "redirect_uri is required", "tls_cert"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

func TestEveryGematikTestHasExpectation(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range Registry().Tests() {
		if seen[tc.ID] {
			t.Errorf("duplicate ID %s", tc.ID)
		}
		seen[tc.ID] = true
		if len(tc.Expect) < 40 || (tc.Spec != spec && tc.Spec != specFD) || !strings.HasPrefix(tc.Section, "A") {
			t.Errorf("%s: needs Expect text, spec %s and an A_ requirement ID (got %q)", tc.ID, spec, tc.Section)
		}
	}
}
