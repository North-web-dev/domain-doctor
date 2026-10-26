package check

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestEvalExpiryStates(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(na time.Time) *x509.Certificate {
		return &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: na, Subject: pkix.Name{CommonName: "x"}}
	}
	if got := evalExpiry(mk(now.Add(-time.Hour)), now); got.Status != StatusFail {
		t.Errorf("expired cert should FAIL, got %v", got.Status)
	}
	if got := evalExpiry(mk(now.Add(10*24*time.Hour)), now); got.Status != StatusWarn {
		t.Errorf("cert expiring in 10d should WARN, got %v", got.Status)
	}
	if got := evalExpiry(mk(now.Add(90*24*time.Hour)), now); got.Status != StatusPass {
		t.Errorf("cert with 90d left should PASS, got %v", got.Status)
	}
}

func TestEvalSANMatch(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"example.com", "www.example.com"}}
	if got := evalSAN(cert, "example.com"); got.Status != StatusPass {
		t.Errorf("apex+www covered should PASS, got %v (%s)", got.Status, got.Detail)
	}
	certNoWWW := &x509.Certificate{DNSNames: []string{"example.com"}}
	if got := evalSAN(certNoWWW, "example.com"); got.Status != StatusWarn {
		t.Errorf("missing www should WARN, got %v", got.Status)
	}
	certWrong := &x509.Certificate{DNSNames: []string{"other.com"}}
	if got := evalSAN(certWrong, "example.com"); got.Status != StatusFail {
		t.Errorf("uncovered apex should FAIL, got %v", got.Status)
	}
}

// genCert builds a self-signed cert valid for 127.0.0.1 with the given lifetime.
func genCert(t *testing.T, notAfter time.Time) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "domain-doctor-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestRunTLSTrustedServer(t *testing.T) {
	cert, pool := genCert(t, time.Now().Add(90*24*time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	host, port := splitURL(t, srv.URL)
	sec := RunTLS(context.Background(), host, TLSOptions{
		Port: port, Timeout: 3 * time.Second, Roots: pool, SkipHSTS: true,
	})

	byTitle := map[string]Finding{}
	for _, f := range sec.Findings {
		byTitle[f.Title] = f
	}
	if f := byTitle["Certificate expiry"]; f.Status != StatusPass {
		t.Errorf("expiry: got %v (%s)", f.Status, f.Detail)
	}
	if f := byTitle["Certificate chain trust"]; f.Status != StatusPass {
		t.Errorf("trust: got %v (%s)", f.Status, f.Detail)
	}
	if f := byTitle["Protocol versions"]; f.Status != StatusPass {
		t.Errorf("protocols: expected modern-only PASS, got %v (%s)", f.Status, f.Detail)
	}
}

func TestRunTLSUntrustedServer(t *testing.T) {
	cert, _ := genCert(t, time.Now().Add(90*24*time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	host, port := splitURL(t, srv.URL)
	// No Roots → verified against the system store, which does not trust us.
	sec := RunTLS(context.Background(), host, TLSOptions{
		Port: port, Timeout: 3 * time.Second, SkipHSTS: true,
	})
	for _, f := range sec.Findings {
		if f.Title == "Certificate chain trust" {
			if f.Status != StatusFail {
				t.Fatalf("self-signed cert must be reported untrusted, got %v", f.Status)
			}
			return
		}
	}
	t.Fatal("no trust finding produced")
}

func TestRunTLSConnectionRefused(t *testing.T) {
	// Port 1 on localhost is not listening.
	sec := RunTLS(context.Background(), "127.0.0.1", TLSOptions{Port: 1, Timeout: time.Second, SkipHSTS: true})
	if sec.Worst() != StatusFail {
		t.Fatalf("unconnectable host should FAIL, got %v", sec.Worst())
	}
}

func splitURL(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}
