package check

import (
	"context"
	"strings"
	"testing"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

func TestParseSPFBasic(t *testing.T) {
	p := parseSPF("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all")
	if !p.HasAll || p.AllQual != '-' {
		t.Fatalf("expected -all, got hasAll=%v qual=%q", p.HasAll, p.AllQual)
	}
	var inc int
	for _, tm := range p.Terms {
		if tm.Name == "include" {
			inc++
			if tm.Value != "_spf.google.com" {
				t.Fatalf("include value = %q", tm.Value)
			}
		}
	}
	if inc != 1 {
		t.Fatalf("expected 1 include, got %d", inc)
	}
}

func TestSPFQualifierVariants(t *testing.T) {
	cases := map[string]byte{
		"v=spf1 +all":   '+',
		"v=spf1 ~all":   '~',
		"v=spf1 ?all":   '?',
		"v=spf1 -all":   '-',
		"v=spf1 mx all": '+',
	}
	for raw, want := range cases {
		if got := parseSPF(raw).AllQual; got != want {
			t.Errorf("%q: all qual = %q want %q", raw, got, want)
		}
	}
}

func TestSPFLookupCountSimple(t *testing.T) {
	f := resolve.NewFake().Add(
		`example.com. 300 IN TXT "v=spf1 a mx include:sub.example.com -all"`,
		`sub.example.com. 300 IN TXT "v=spf1 a a mx -all"`,
	)
	rep, err := EvaluateSPF(context.Background(), f, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// example.com: a(1) mx(1) include(1) ; sub: a(1) a(1) mx(1) = 3
	if rep.Lookups != 6 {
		t.Fatalf("expected 6 lookups, got %d", rep.Lookups)
	}
	if rep.Exceeded {
		t.Fatalf("6 lookups should not exceed the limit")
	}
}

func TestSPFLookupCountExceeds(t *testing.T) {
	// Each include costs 1 and resolves to a record with one mx (another 1).
	zone := resolve.NewFake().Add(
		`example.com. 300 IN TXT "v=spf1 include:a.net include:b.net include:c.net include:d.net include:e.net include:f.net -all"`,
	)
	for _, d := range []string{"a.net", "b.net", "c.net", "d.net", "e.net", "f.net"} {
		zone.Add(d + `. 300 IN TXT "v=spf1 mx -all"`)
	}
	rep, err := EvaluateSPF(context.Background(), zone, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// 6 includes + 6 nested mx = 12 > 10
	if rep.Lookups != 12 {
		t.Fatalf("expected 12 lookups, got %d", rep.Lookups)
	}
	if !rep.Exceeded {
		t.Fatalf("12 lookups MUST exceed the 10 limit")
	}
}

func TestSPFIncludeLoopTerminates(t *testing.T) {
	zone := resolve.NewFake().Add(
		`a.com. 300 IN TXT "v=spf1 include:b.com -all"`,
		`b.com. 300 IN TXT "v=spf1 include:a.com -all"`,
	)
	done := make(chan *SPFReport, 1)
	go func() {
		rep, _ := EvaluateSPF(context.Background(), zone, "a.com")
		done <- rep
	}()
	rep := <-done // if the loop guard failed this test would hang and time out
	var looped bool
	for _, n := range rep.Notes {
		if strings.Contains(n, "loop") {
			looped = true
		}
	}
	if !looped {
		t.Fatalf("expected a loop-detection note, got %v", rep.Notes)
	}
}

func TestSPFRedirect(t *testing.T) {
	zone := resolve.NewFake().Add(
		`example.com. 300 IN TXT "v=spf1 redirect=_spf.example.com"`,
		`_spf.example.com. 300 IN TXT "v=spf1 a mx -all"`,
	)
	rep, err := EvaluateSPF(context.Background(), zone, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// redirect(1) + a(1) + mx(1) = 3
	if rep.Lookups != 3 {
		t.Fatalf("expected 3 lookups via redirect, got %d", rep.Lookups)
	}
}

func TestSPFDangerousAllFinding(t *testing.T) {
	zone := resolve.NewFake().Add(`example.com. 300 IN TXT "v=spf1 +all"`)
	f := spfFinding(context.Background(), zone, "example.com")
	if f.Status != StatusFail {
		t.Fatalf("+all must be FAIL, got %v", f.Status)
	}
}

func TestSPFMissingFinding(t *testing.T) {
	zone := resolve.NewFake()
	f := spfFinding(context.Background(), zone, "example.com")
	if f.Status != StatusFail || f.Fix == "" {
		t.Fatalf("missing SPF must FAIL with a fix, got %v fix=%q", f.Status, f.Fix)
	}
}
