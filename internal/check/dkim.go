package check

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"

	"github.com/miekg/dns"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

// DefaultDKIMSelectors are the common selectors domain-doctor probes. We cannot
// enumerate every selector a sender might use, so the report says which were
// checked.
var DefaultDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2",
}

// DKIMKey is the audited state of one selector.
type DKIMKey struct {
	Selector string
	Found    bool
	Raw      string
	KeyType  string // rsa | ed25519 | ...
	Revoked  bool   // present but p= empty (key revoked)
	Bits     int    // RSA modulus size when derivable, else 0
	Testing  bool   // t=y
	Notes    []string
}

func parseDKIM(selector, raw string) DKIMKey {
	k := DKIMKey{Selector: selector, Found: true, Raw: raw}
	tags := parseDMARCTags(raw) // same k=v;… grammar
	k.KeyType = strings.ToLower(tags["k"])
	if k.KeyType == "" {
		k.KeyType = "rsa" // RFC 6376 default
	}
	for _, f := range strings.Split(strings.ToLower(tags["t"]), ":") {
		if strings.TrimSpace(f) == "y" {
			k.Testing = true
		}
	}
	p, hasP := tags["p"]
	if !hasP || strings.TrimSpace(p) == "" {
		k.Revoked = true
		k.Notes = append(k.Notes, "p= is empty (key revoked)")
		return k
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(p), ""))
	if err != nil {
		k.Notes = append(k.Notes, "public key is not valid base64")
		return k
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		k.Notes = append(k.Notes, "public key is not parseable DER")
		return k
	}
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		k.Bits = pk.N.BitLen()
	case ed25519.PublicKey:
		k.Bits = 256
	case *ecdsa.PublicKey:
		k.Bits = pk.Curve.Params().BitSize
	}
	return k
}

// EvaluateDKIM probes each selector and returns the parsed keys for those found.
func EvaluateDKIM(ctx context.Context, c resolve.Client, domain string, selectors []string) ([]DKIMKey, []string) {
	var found []DKIMKey
	checked := make([]string, 0, len(selectors))
	seen := map[string]bool{}
	for _, sel := range selectors {
		sel = strings.TrimSpace(sel)
		if sel == "" || seen[sel] {
			continue
		}
		seen[sel] = true
		checked = append(checked, sel)
		res, err := c.Query(ctx, sel+"._domainkey."+domain, dns.TypeTXT)
		if err != nil {
			continue
		}
		for _, s := range resolve.TXTStrings(res) {
			low := strings.ToLower(strings.TrimSpace(s))
			if strings.HasPrefix(low, "v=dkim1") || strings.Contains(low, "p=") {
				found = append(found, parseDKIM(sel, s))
				break
			}
		}
	}
	return found, checked
}
