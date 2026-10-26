package resolve

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

// FakeClient is an in-memory Client for tests. It is exported so audit packages
// can be exercised without any network access.
type FakeClient struct {
	// Zones maps a lowercase FQDN (with trailing dot) to its records by qtype.
	Zones map[string]map[uint16]*Result
	// Errs maps a lowercase FQDN to an error to return for any query.
	Errs map[string]error
}

// NewFake returns an empty FakeClient.
func NewFake() *FakeClient {
	return &FakeClient{Zones: map[string]map[uint16]*Result{}, Errs: map[string]error{}}
}

// Add parses one or more zone-file lines and files the resulting records under
// their owner name and type. It panics on a parse error (test-only helper).
func (f *FakeClient) Add(records ...string) *FakeClient {
	for _, line := range records {
		rr, err := dns.NewRR(line)
		if err != nil {
			panic("resolve.FakeClient.Add: " + err.Error())
		}
		name := strings.ToLower(rr.Header().Name)
		qtype := rr.Header().Rrtype
		if f.Zones[name] == nil {
			f.Zones[name] = map[uint16]*Result{}
		}
		if f.Zones[name][qtype] == nil {
			f.Zones[name][qtype] = &Result{Rcode: dns.RcodeSuccess}
		}
		f.Zones[name][qtype].Records = append(f.Zones[name][qtype].Records, rr)
	}
	return f
}

// SetAD marks a name's records (all types) as DNSSEC-authenticated.
func (f *FakeClient) SetAD(name string) *FakeClient {
	n := dns.Fqdn(strings.ToLower(name))
	for _, byType := range f.Zones[n] {
		byType.AD = true
	}
	return f
}

// SetErr makes any query for name return err.
func (f *FakeClient) SetErr(name string, err error) *FakeClient {
	f.Errs[dns.Fqdn(strings.ToLower(name))] = err
	return f
}

func (f *FakeClient) Query(_ context.Context, name string, qtype uint16) (*Result, error) {
	n := dns.Fqdn(strings.ToLower(name))
	if err := f.Errs[n]; err != nil {
		return nil, err
	}
	if byType, ok := f.Zones[n]; ok {
		if res, ok := byType[qtype]; ok {
			return res, nil
		}
	}
	return &Result{Rcode: dns.RcodeSuccess}, nil // NODATA
}
