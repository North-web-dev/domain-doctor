package check

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

func dkimTXT(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func TestDKIMParseStrongKey(t *testing.T) {
	k := parseDKIM("default", dkimTXT(t, 2048))
	if k.Revoked {
		t.Fatal("2048-bit key should not be revoked")
	}
	if k.KeyType != "rsa" || k.Bits != 2048 {
		t.Fatalf("expected rsa 2048, got %s %d", k.KeyType, k.Bits)
	}
}

func TestDKIMRevokedKey(t *testing.T) {
	k := parseDKIM("default", "v=DKIM1; k=rsa; p=")
	if !k.Revoked {
		t.Fatal("empty p= must be flagged revoked")
	}
}

func TestDKIMWeakKeyWarns(t *testing.T) {
	zone := resolve.NewFake().Add(
		`default._domainkey.example.com. 300 IN TXT "` + dkimTXT(t, 1024) + `"`,
	)
	f := dkimFinding(context.Background(), zone, "example.com", DefaultDKIMSelectors)
	if f.Status != StatusWarn {
		t.Fatalf("1024-bit key should WARN, got %v (%s)", f.Status, f.Detail)
	}
}

func TestDKIMNoneFoundWarns(t *testing.T) {
	zone := resolve.NewFake()
	f := dkimFinding(context.Background(), zone, "example.com", DefaultDKIMSelectors)
	if f.Status != StatusWarn {
		t.Fatalf("no DKIM found should WARN, got %v", f.Status)
	}
}

func TestDKIMBadBase64(t *testing.T) {
	k := parseDKIM("default", "v=DKIM1; k=rsa; p=@@@notbase64@@@")
	if len(k.Notes) == 0 {
		t.Fatal("invalid base64 should produce a note")
	}
}
