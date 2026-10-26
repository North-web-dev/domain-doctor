package check

import (
	"context"
	"strings"

	"github.com/miekg/dns"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

// spfMaxLookups is RFC 7208 §4.6.4's hard limit: the number of DNS-lookup
// mechanisms (include, a, mx, ptr, exists) plus the redirect modifier,
// evaluated recursively, must not exceed 10.
const spfMaxLookups = 10

const (
	spfMaxDepth = 12 // include/redirect recursion guard
	spfCountCap = 60 // stop counting runaway records
)

// spfTerm is one parsed SPF term.
type spfTerm struct {
	Qualifier byte // '+','-','~','?' for mechanisms; 0 for modifiers
	Name      string
	Value     string
	Modifier  bool // name=value form (redirect, exp, ...)
}

// spfParsed is the result of parsing a single record's text (no DNS).
type spfParsed struct {
	Terms       []spfTerm
	AllQual     byte   // qualifier of the trailing all mechanism, 0 if none
	HasAll      bool   // an "all" mechanism is present
	Redirect    string // redirect= target domain, if any
	SyntaxNotes []string
}

// isSPFRecord reports whether a TXT string is an SPF record (RFC 7208 §3.1:
// starts with "v=spf1" followed by a space or end-of-string, case-insensitive).
func isSPFRecord(txt string) bool {
	if len(txt) < 6 {
		return false
	}
	if !strings.EqualFold(txt[:6], "v=spf1") {
		return false
	}
	return len(txt) == 6 || txt[6] == ' '
}

// countsLookup reports whether a mechanism name consumes one of the 10 lookups.
func countsLookup(name string) bool {
	switch name {
	case "include", "a", "mx", "ptr", "exists":
		return true
	}
	return false
}

func parseSPF(raw string) spfParsed {
	var p spfParsed
	fields := strings.Fields(raw)
	for i, f := range fields {
		if i == 0 { // the v=spf1 version token
			continue
		}
		if eq := strings.IndexByte(f, '='); eq > 0 && !isQualifier(f[0]) {
			name := strings.ToLower(f[:eq])
			val := f[eq+1:]
			if name == "redirect" {
				p.Redirect = strings.TrimSuffix(strings.ToLower(val), ".")
			}
			p.Terms = append(p.Terms, spfTerm{Name: name, Value: val, Modifier: true})
			continue
		}
		q := byte('+')
		mech := f
		if isQualifier(f[0]) {
			q = f[0]
			mech = f[1:]
		}
		name := mech
		val := ""
		if idx := strings.IndexAny(mech, ":/"); idx >= 0 {
			name = mech[:idx]
			val = mech[idx+1:]
		}
		name = strings.ToLower(name)
		if name == "all" {
			p.HasAll = true
			p.AllQual = q
		}
		p.Terms = append(p.Terms, spfTerm{Qualifier: q, Name: name, Value: val})
	}
	return p
}

func isQualifier(b byte) bool {
	return b == '+' || b == '-' || b == '~' || b == '?'
}

// SPFReport is the audited SPF state for a domain.
type SPFReport struct {
	Found    bool
	Raw      string
	Multiple bool // more than one v=spf1 record (a permerror condition)
	Parsed   spfParsed
	Lookups  int  // recursive count of lookup-causing terms
	Exceeded bool // Lookups > 10
	Capped   bool // counting hit the safety cap
	AllQual  byte // qualifier of the effective all (0 if none)
	Notes    []string
}

// EvaluateSPF fetches and audits the SPF record for domain.
func EvaluateSPF(ctx context.Context, c resolve.Client, domain string) (*SPFReport, error) {
	res, err := c.Query(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var records []string
	for _, s := range resolve.TXTStrings(res) {
		if isSPFRecord(s) {
			records = append(records, s)
		}
	}
	rep := &SPFReport{}
	if len(records) == 0 {
		return rep, nil
	}
	rep.Found = true
	rep.Raw = records[0]
	rep.Multiple = len(records) > 1
	rep.Parsed = parseSPF(records[0])
	rep.AllQual = rep.Parsed.AllQual

	visited := map[string]bool{strings.ToLower(domain): true}
	n := countLookups(ctx, c, rep.Parsed, 0, visited, &rep.Notes)
	rep.Lookups = n
	rep.Exceeded = n > spfMaxLookups
	if n >= spfCountCap {
		rep.Capped = true
	}
	return rep, nil
}

// countLookups walks the record, following include/redirect targets. It is
// bounded by depth, a visited set (loop termination), and spfCountCap.
func countLookups(ctx context.Context, c resolve.Client, p spfParsed, depth int, visited map[string]bool, notes *[]string) int {
	if depth > spfMaxDepth {
		*notes = append(*notes, "include/redirect nesting too deep; stopped counting")
		return 0
	}
	total := 0
	follow := func(target string) {
		target = strings.TrimSuffix(strings.ToLower(target), ".")
		if target == "" {
			return
		}
		total++ // the lookup for this include/redirect itself
		if total >= spfCountCap {
			return
		}
		if visited[target] {
			*notes = append(*notes, "include loop detected at "+target+" (stopped)")
			return
		}
		visited[target] = true
		res, err := c.Query(ctx, target, dns.TypeTXT)
		if err != nil {
			*notes = append(*notes, "could not resolve include/redirect "+target)
			return
		}
		var sub string
		for _, s := range resolve.TXTStrings(res) {
			if isSPFRecord(s) {
				sub = s
				break
			}
		}
		if sub == "" {
			*notes = append(*notes, "include/redirect "+target+" has no SPF record")
			return
		}
		total += countLookups(ctx, c, parseSPF(sub), depth+1, visited, notes)
	}

	for _, t := range p.Terms {
		if total >= spfCountCap {
			break
		}
		switch {
		case t.Modifier && t.Name == "redirect":
			// redirect only applies when there is no all mechanism.
			if !p.HasAll {
				follow(t.Value)
			}
		case !t.Modifier && t.Name == "include":
			follow(t.Value)
		case !t.Modifier && countsLookup(t.Name):
			total++
		}
	}
	return total
}
