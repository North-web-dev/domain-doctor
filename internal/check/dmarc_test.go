package check

import (
	"context"
	"testing"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

func TestParseDMARCPolicyAndAlignment(t *testing.T) {
	r := parseDMARC("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; rua=mailto:a@x.com,mailto:b@x.com; pct=100")
	if r.Policy != "reject" {
		t.Errorf("policy = %q", r.Policy)
	}
	if r.SubPolicy != "quarantine" {
		t.Errorf("sp = %q", r.SubPolicy)
	}
	if r.ADKIM != "s" || r.ASPF != "r" {
		t.Errorf("alignment adkim=%q aspf=%q", r.ADKIM, r.ASPF)
	}
	if len(r.RUA) != 2 {
		t.Errorf("rua count = %d", len(r.RUA))
	}
}

func TestDMARCNoneIsWarn(t *testing.T) {
	zone := resolve.NewFake().Add(`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=none; rua=mailto:r@example.com"`)
	f := dmarcFinding(context.Background(), zone, "example.com")
	if f.Status != StatusWarn {
		t.Fatalf("p=none should WARN (monitoring only), got %v", f.Status)
	}
}

func TestDMARCRejectIsPass(t *testing.T) {
	zone := resolve.NewFake().Add(`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:r@example.com"`)
	f := dmarcFinding(context.Background(), zone, "example.com")
	if f.Status != StatusPass {
		t.Fatalf("p=reject with rua should PASS, got %v (%s)", f.Status, f.Detail)
	}
}

func TestDMARCMissingIsFail(t *testing.T) {
	zone := resolve.NewFake()
	f := dmarcFinding(context.Background(), zone, "example.com")
	if f.Status != StatusFail || f.Fix == "" {
		t.Fatalf("missing DMARC should FAIL with a fix, got %v", f.Status)
	}
}

func TestDMARCRejectNoRUAWarns(t *testing.T) {
	zone := resolve.NewFake().Add(`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`)
	f := dmarcFinding(context.Background(), zone, "example.com")
	if f.Status != StatusWarn {
		t.Fatalf("reject without rua should WARN, got %v", f.Status)
	}
}
