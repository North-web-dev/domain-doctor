package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
	"github.com/North-web-dev/domain-doctor/internal/sanitize"
)

const maxListed = 8

// RunDNS audits A/AAAA, MX (+host resolution), NS, SOA, TXT, CAA and DNSSEC.
func RunDNS(ctx context.Context, c resolve.Client, domain string) Section {
	s := Section{Name: "DNS"}
	s.Findings = append(s.Findings, checkAddresses(ctx, c, domain))
	s.Findings = append(s.Findings, checkMX(ctx, c, domain))
	s.Findings = append(s.Findings, checkNS(ctx, c, domain))
	s.Findings = append(s.Findings, checkSOA(ctx, c, domain))
	s.Findings = append(s.Findings, checkTXT(ctx, c, domain))
	s.Findings = append(s.Findings, checkCAA(ctx, c, domain))
	s.Findings = append(s.Findings, checkDNSSEC(ctx, c, domain))
	return s
}

func addrStrings(res *resolve.Result) []string {
	var out []string
	if res == nil {
		return out
	}
	for _, rr := range res.Records {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		}
	}
	return out
}

func checkAddresses(ctx context.Context, c resolve.Client, domain string) Finding {
	a, _ := c.Query(ctx, domain, dns.TypeA)
	aaaa, _ := c.Query(ctx, domain, dns.TypeAAAA)
	v4 := addrStrings(a)
	v6 := addrStrings(aaaa)
	f := Finding{Title: "A / AAAA address records"}
	switch {
	case len(v4) == 0 && len(v6) == 0:
		f.Status = StatusWarn
		f.Detail = "no A or AAAA records at the apex"
		f.Fix = "add an A (and ideally AAAA) record if this domain should resolve to a host"
	case len(v6) == 0:
		f.Status = StatusPass
		f.Detail = fmt.Sprintf("A: %s (no AAAA — IPv6 not published)", summ(v4))
	default:
		f.Status = StatusPass
		f.Detail = fmt.Sprintf("A: %s  AAAA: %s", summ(v4), summ(v6))
	}
	return f
}

func checkMX(ctx context.Context, c resolve.Client, domain string) Finding {
	res, err := c.Query(ctx, domain, dns.TypeMX)
	f := Finding{Title: "MX mail exchangers"}
	if err != nil {
		f.Status = StatusWarn
		f.Detail = "MX lookup failed: " + sanitize.Clean(err.Error())
		return f
	}
	var mxs []*dns.MX
	for _, rr := range res.Records {
		if m, ok := rr.(*dns.MX); ok {
			mxs = append(mxs, m)
		}
	}
	if len(mxs) == 0 {
		f.Status = StatusInfo
		f.Detail = "no MX records (this domain does not receive mail)"
		return f
	}
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Preference < mxs[j].Preference })
	if len(mxs) == 1 && strings.TrimSuffix(mxs[0].Mx, ".") == "" {
		f.Status = StatusInfo
		f.Detail = "null MX (RFC 7505: domain explicitly accepts no mail)"
		return f
	}
	var unresolved []string
	var hosts []string
	for _, m := range mxs {
		host := strings.TrimSuffix(m.Mx, ".")
		hosts = append(hosts, fmt.Sprintf("%d %s", m.Preference, sanitize.Clean(host)))
		a, _ := c.Query(ctx, host, dns.TypeA)
		aaaa, _ := c.Query(ctx, host, dns.TypeAAAA)
		if len(addrStrings(a)) == 0 && len(addrStrings(aaaa)) == 0 {
			unresolved = append(unresolved, sanitize.Clean(host))
		}
	}
	f.Detail = strings.Join(hosts, ", ")
	if len(unresolved) > 0 {
		f.Status = StatusWarn
		f.Detail += " — unresolvable: " + strings.Join(unresolved, ", ")
		f.Fix = "every MX host must resolve to an A/AAAA address; fix or remove " + strings.Join(unresolved, ", ")
	} else {
		f.Status = StatusPass
	}
	return f
}

func checkNS(ctx context.Context, c resolve.Client, domain string) Finding {
	res, _ := c.Query(ctx, domain, dns.TypeNS)
	var ns []string
	if res != nil {
		for _, rr := range res.Records {
			if n, ok := rr.(*dns.NS); ok {
				ns = append(ns, sanitize.Clean(strings.TrimSuffix(n.Ns, ".")))
			}
		}
	}
	f := Finding{Title: "NS nameservers"}
	switch {
	case len(ns) == 0:
		f.Status = StatusWarn
		f.Detail = "no NS records returned in the answer section"
		f.Fix = "confirm the zone is delegated with at least two nameservers"
	case len(ns) == 1:
		f.Status = StatusWarn
		f.Detail = "only one nameserver: " + ns[0]
		f.Fix = "publish at least two nameservers (ideally on separate networks) for redundancy"
	default:
		f.Status = StatusPass
		f.Detail = fmt.Sprintf("%d nameservers: %s", len(ns), summ(ns))
	}
	return f
}

func checkSOA(ctx context.Context, c resolve.Client, domain string) Finding {
	res, _ := c.Query(ctx, domain, dns.TypeSOA)
	f := Finding{Title: "SOA start of authority"}
	if res != nil {
		for _, rr := range res.Records {
			if soa, ok := rr.(*dns.SOA); ok {
				f.Status = StatusPass
				f.Detail = fmt.Sprintf("primary %s, serial %d, refresh %ds",
					sanitize.Clean(strings.TrimSuffix(soa.Ns, ".")), soa.Serial, soa.Refresh)
				return f
			}
		}
	}
	f.Status = StatusWarn
	f.Detail = "no SOA record returned"
	f.Fix = "the zone should expose a SOA record; check delegation"
	return f
}

func checkTXT(ctx context.Context, c resolve.Client, domain string) Finding {
	res, _ := c.Query(ctx, domain, dns.TypeTXT)
	txts := resolve.TXTStrings(res)
	f := Finding{Title: "TXT records", Status: StatusInfo}
	if len(txts) == 0 {
		f.Detail = "no TXT records at the apex"
		return f
	}
	shown := make([]string, 0, len(txts))
	for i, t := range txts {
		if i >= maxListed {
			shown = append(shown, fmt.Sprintf("…(+%d more)", len(txts)-maxListed))
			break
		}
		shown = append(shown, "\""+sanitize.Clean(t)+"\"")
	}
	f.Detail = fmt.Sprintf("%d record(s): %s", len(txts), strings.Join(shown, ", "))
	return f
}

func checkCAA(ctx context.Context, c resolve.Client, domain string) Finding {
	res, _ := c.Query(ctx, domain, dns.TypeCAA)
	var caa []string
	if res != nil {
		for _, rr := range res.Records {
			if c, ok := rr.(*dns.CAA); ok {
				caa = append(caa, sanitize.Clean(fmt.Sprintf("%s %s", c.Tag, c.Value)))
			}
		}
	}
	f := Finding{Title: "CAA certificate authority authorization"}
	if len(caa) == 0 {
		f.Status = StatusWarn
		f.Detail = "no CAA record — any certificate authority may issue for this domain"
		f.Fix = `publish a CAA record, e.g. ` + domain + ` IN CAA 0 issue "letsencrypt.org"`
		return f
	}
	f.Status = StatusPass
	f.Detail = strings.Join(caa, ", ")
	return f
}

func checkDNSSEC(ctx context.Context, c resolve.Client, domain string) Finding {
	res, _ := c.Query(ctx, domain, dns.TypeDNSKEY)
	signed := false
	if res != nil {
		for _, rr := range res.Records {
			if _, ok := rr.(*dns.DNSKEY); ok {
				signed = true
				break
			}
		}
	}
	// The AD flag on this answer reflects validation by the upstream resolver.
	ad := res != nil && res.AD
	f := Finding{Title: "DNSSEC"}
	switch {
	case signed && ad:
		f.Status = StatusPass
		f.Detail = "zone is signed and the resolver validated it (AD bit set)"
	case signed:
		f.Status = StatusPass
		f.Detail = "zone publishes DNSKEY records (signed); resolver did not set the AD bit"
	default:
		f.Status = StatusWarn
		f.Detail = "zone is not DNSSEC-signed (no DNSKEY)"
		f.Fix = "enable DNSSEC at your DNS provider and add the DS record at the registrar"
	}
	return f
}

func summ(items []string) string {
	if len(items) <= maxListed {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxListed], ", ") + fmt.Sprintf(" …(+%d)", len(items)-maxListed)
}
