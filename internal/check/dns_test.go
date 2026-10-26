package check

import (
	"context"
	"testing"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

func findingByTitle(s Section, title string) (Finding, bool) {
	for _, f := range s.Findings {
		if f.Title == title {
			return f, true
		}
	}
	return Finding{}, false
}

func TestDNSCAAMissingWarns(t *testing.T) {
	zone := resolve.NewFake().Add(
		`example.com. 300 IN A 192.0.2.1`,
		`example.com. 300 IN NS ns1.example.com.`,
		`example.com. 300 IN NS ns2.example.com.`,
	)
	sec := RunDNS(context.Background(), zone, "example.com")
	f, _ := findingByTitle(sec, "CAA certificate authority authorization")
	if f.Status != StatusWarn {
		t.Fatalf("missing CAA should WARN, got %v", f.Status)
	}
}

func TestDNSCAAPresentPasses(t *testing.T) {
	zone := resolve.NewFake().Add(
		`example.com. 300 IN A 192.0.2.1`,
		`example.com. 300 IN NS ns1.example.com.`,
		`example.com. 300 IN NS ns2.example.com.`,
		`example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
	)
	sec := RunDNS(context.Background(), zone, "example.com")
	f, _ := findingByTitle(sec, "CAA certificate authority authorization")
	if f.Status != StatusPass {
		t.Fatalf("present CAA should PASS, got %v", f.Status)
	}
}

func TestDNSSingleNameserverWarns(t *testing.T) {
	zone := resolve.NewFake().Add(
		`example.com. 300 IN A 192.0.2.1`,
		`example.com. 300 IN NS ns1.example.com.`,
	)
	sec := RunDNS(context.Background(), zone, "example.com")
	f, _ := findingByTitle(sec, "NS nameservers")
	if f.Status != StatusWarn {
		t.Fatalf("single NS should WARN, got %v", f.Status)
	}
}

func TestDNSMXUnresolvableWarns(t *testing.T) {
	zone := resolve.NewFake().Add(
		`example.com. 300 IN MX 10 mail.example.com.`,
	)
	sec := RunDNS(context.Background(), zone, "example.com")
	f, _ := findingByTitle(sec, "MX mail exchangers")
	if f.Status != StatusWarn {
		t.Fatalf("MX host with no address should WARN, got %v (%s)", f.Status, f.Detail)
	}
}

func TestDNSSECUnsignedWarns(t *testing.T) {
	zone := resolve.NewFake().Add(`example.com. 300 IN A 192.0.2.1`)
	sec := RunDNS(context.Background(), zone, "example.com")
	f, _ := findingByTitle(sec, "DNSSEC")
	if f.Status != StatusWarn {
		t.Fatalf("unsigned zone should WARN, got %v", f.Status)
	}
}

func TestDNSSECSignedPasses(t *testing.T) {
	zone := resolve.NewFake().Add(
		`example.com. 300 IN A 192.0.2.1`,
		`example.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==`,
	).SetAD("example.com")
	sec := RunDNS(context.Background(), zone, "example.com")
	f, _ := findingByTitle(sec, "DNSSEC")
	if f.Status != StatusPass {
		t.Fatalf("signed+validated zone should PASS, got %v (%s)", f.Status, f.Detail)
	}
}
