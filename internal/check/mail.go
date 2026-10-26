package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
	"github.com/North-web-dev/domain-doctor/internal/sanitize"
)

// RunMail audits SPF, DKIM and DMARC.
func RunMail(ctx context.Context, c resolve.Client, domain string, dkimSelectors []string) Section {
	s := Section{Name: "Mail authentication"}
	s.Findings = append(s.Findings, spfFinding(ctx, c, domain))
	s.Findings = append(s.Findings, dkimFinding(ctx, c, domain, dkimSelectors))
	s.Findings = append(s.Findings, dmarcFinding(ctx, c, domain))
	return s
}

func spfFinding(ctx context.Context, c resolve.Client, domain string) Finding {
	f := Finding{Title: "SPF (sender policy framework)"}
	rep, err := EvaluateSPF(ctx, c, domain)
	if err != nil {
		f.Status = StatusWarn
		f.Detail = "SPF lookup failed: " + sanitize.Clean(err.Error())
		return f
	}
	if !rep.Found {
		f.Status = StatusFail
		f.Detail = "no SPF record published"
		f.Fix = `publish: ` + domain + ` IN TXT "v=spf1 include:<your-provider> -all"`
		return f
	}

	detail := fmt.Sprintf("%q — %d DNS lookups", sanitize.Clean(rep.Raw), rep.Lookups)
	var fixes []string
	status := StatusPass

	if rep.Multiple {
		status = StatusFail
		detail += "; MULTIPLE SPF records (PermError — receivers reject this)"
		fixes = append(fixes, "merge into a single v=spf1 TXT record")
	}
	if rep.Exceeded {
		status = StatusFail
		detail += fmt.Sprintf("; EXCEEDS the 10-lookup limit (%d) — SPF returns PermError and fails", rep.Lookups)
		fixes = append(fixes, "reduce include/a/mx/ptr/exists terms below 11 (flatten includes or drop unused ones)")
	}
	switch rep.AllQual {
	case '+':
		status = worse(status, StatusFail)
		detail += "; ends in +all (passes ALL senders — effectively no protection)"
		fixes = append(fixes, "change +all to -all (or ~all while testing)")
	case '?':
		status = worse(status, StatusWarn)
		detail += "; ends in ?all (neutral — provides no enforcement)"
		fixes = append(fixes, "move to ~all then -all once confident")
	case '~':
		detail += "; ends in ~all (softfail)"
		if status == StatusPass {
			detail += " — fine, tighten to -all when confident"
		}
	case '-':
		detail += "; ends in -all (hardfail — recommended)"
	case 0:
		status = worse(status, StatusWarn)
		detail += "; no all mechanism (defaults to neutral)"
		fixes = append(fixes, "add a terminating -all or ~all")
	}
	if rep.Capped {
		detail += "; note: lookup counting hit the safety cap"
	}
	for _, n := range rep.Notes {
		detail += "; " + sanitize.Clean(n)
	}
	f.Status = status
	f.Detail = detail
	f.Fix = strings.Join(fixes, "; ")
	return f
}

func dkimFinding(ctx context.Context, c resolve.Client, domain string, selectors []string) Finding {
	f := Finding{Title: "DKIM (domainkeys identified mail)"}
	keys, checked := EvaluateDKIM(ctx, c, domain, selectors)
	checkedNote := fmt.Sprintf(" (checked selectors: %s — cannot enumerate all)", strings.Join(checked, ", "))
	if len(keys) == 0 {
		f.Status = StatusWarn
		f.Detail = "no DKIM key found" + checkedNote
		f.Fix = "if you send mail, publish a DKIM key and pass its selector with --dkim-selector"
		return f
	}
	status := StatusPass
	var parts, fixes []string
	for _, k := range keys {
		switch {
		case k.Revoked:
			status = worse(status, StatusFail)
			parts = append(parts, fmt.Sprintf("%s: REVOKED (empty p=)", k.Selector))
			fixes = append(fixes, "republish a public key for selector "+k.Selector+" or remove it")
		case k.KeyType == "rsa" && k.Bits > 0 && k.Bits < 1024:
			status = worse(status, StatusFail)
			parts = append(parts, fmt.Sprintf("%s: RSA %d-bit (too weak)", k.Selector, k.Bits))
			fixes = append(fixes, "rotate selector "+k.Selector+" to a 2048-bit RSA key")
		case k.KeyType == "rsa" && k.Bits > 0 && k.Bits < 2048:
			status = worse(status, StatusWarn)
			parts = append(parts, fmt.Sprintf("%s: RSA %d-bit", k.Selector, k.Bits))
			fixes = append(fixes, "rotate selector "+k.Selector+" to a 2048-bit RSA key")
		default:
			d := fmt.Sprintf("%s: %s", k.Selector, k.KeyType)
			if k.Bits > 0 {
				d += fmt.Sprintf(" %d-bit", k.Bits)
			}
			if k.Testing {
				d += " (t=y testing)"
			}
			parts = append(parts, d)
		}
	}
	f.Status = status
	f.Detail = strings.Join(parts, "; ") + checkedNote
	f.Fix = strings.Join(fixes, "; ")
	return f
}

func dmarcFinding(ctx context.Context, c resolve.Client, domain string) Finding {
	f := Finding{Title: "DMARC (domain-based message authentication)"}
	rep, err := EvaluateDMARC(ctx, c, domain)
	if err != nil {
		f.Status = StatusWarn
		f.Detail = "DMARC lookup failed: " + sanitize.Clean(err.Error())
		return f
	}
	if !rep.Found {
		f.Status = StatusFail
		f.Detail = "no DMARC record at _dmarc." + domain
		f.Fix = `publish _dmarc.` + domain + ` IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@` + domain + `" then tighten to quarantine/reject`
		return f
	}
	detail := fmt.Sprintf("policy p=%s", rep.Policy)
	if rep.SubPolicy != "" {
		detail += ", sp=" + rep.SubPolicy
	}
	if rep.ADKIM != "" || rep.ASPF != "" {
		detail += fmt.Sprintf(", alignment adkim=%s aspf=%s", orDefault(rep.ADKIM, "r"), orDefault(rep.ASPF, "r"))
	}
	status := StatusPass
	var fixes []string
	if rep.Multiple {
		status = StatusFail
		detail += "; MULTIPLE DMARC records (invalid)"
		fixes = append(fixes, "keep exactly one _dmarc TXT record")
	}
	switch rep.Policy {
	case "reject":
		detail += "; enforcing (reject)"
	case "quarantine":
		detail += "; enforcing (quarantine)"
	case "none":
		status = worse(status, StatusWarn)
		detail += "; monitoring only (p=none does not block spoofing)"
		fixes = append(fixes, "after reviewing rua reports, move p=none → quarantine → reject")
	default:
		status = worse(status, StatusFail)
		detail += "; missing/invalid policy"
		fixes = append(fixes, "set a valid p= (none, quarantine or reject)")
	}
	if len(rep.RUA) == 0 {
		status = worse(status, StatusWarn)
		detail += "; no rua aggregate reporting"
		fixes = append(fixes, "add rua=mailto: to receive aggregate reports")
	} else {
		detail += fmt.Sprintf("; rua→%d dest", len(rep.RUA))
	}
	for _, n := range rep.Notes {
		detail += "; " + sanitize.Clean(n)
	}
	f.Status = status
	f.Detail = detail
	f.Fix = strings.Join(fixes, "; ")
	return f
}

func worse(a, b Status) Status {
	if b > a {
		return b
	}
	return a
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
