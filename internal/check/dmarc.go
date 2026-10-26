package check

import (
	"context"
	"strings"

	"github.com/miekg/dns"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

// DMARCReport is the audited DMARC state for a domain.
type DMARCReport struct {
	Found     bool
	Raw       string
	Multiple  bool
	Policy    string // p=   none|quarantine|reject
	SubPolicy string // sp=
	Pct       string // pct=
	ADKIM     string // r (relaxed) | s (strict)
	ASPF      string
	RUA       []string
	RUF       []string
	Notes     []string
}

func parseDMARCTags(raw string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		tags[key] = strings.TrimSpace(part[eq+1:])
	}
	return tags
}

func parseDMARC(raw string) DMARCReport {
	r := DMARCReport{Raw: raw, Found: true}
	tags := parseDMARCTags(raw)
	r.Policy = strings.ToLower(tags["p"])
	r.SubPolicy = strings.ToLower(tags["sp"])
	r.Pct = tags["pct"]
	r.ADKIM = strings.ToLower(tags["adkim"])
	r.ASPF = strings.ToLower(tags["aspf"])
	if v := tags["rua"]; v != "" {
		r.RUA = splitURIs(v)
	}
	if v := tags["ruf"]; v != "" {
		r.RUF = splitURIs(v)
	}
	switch r.Policy {
	case "none", "quarantine", "reject":
	case "":
		r.Notes = append(r.Notes, "no p= policy tag")
	default:
		r.Notes = append(r.Notes, "unknown policy value p="+r.Policy)
	}
	return r
}

func splitURIs(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// EvaluateDMARC fetches and parses _dmarc.<domain>.
func EvaluateDMARC(ctx context.Context, c resolve.Client, domain string) (*DMARCReport, error) {
	res, err := c.Query(ctx, "_dmarc."+domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var records []string
	for _, s := range resolve.TXTStrings(res) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "v=dmarc1") {
			records = append(records, s)
		}
	}
	if len(records) == 0 {
		return &DMARCReport{}, nil
	}
	rep := parseDMARC(records[0])
	rep.Multiple = len(records) > 1
	return &rep, nil
}
