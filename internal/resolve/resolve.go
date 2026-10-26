// Package resolve wraps DNS queries behind an interface so the audit logic can
// run against a fake resolver in tests and never touches the network there.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Result is the outcome of a single DNS query.
type Result struct {
	Records []dns.RR
	Rcode   int
	// AD is the Authenticated Data bit as reported by the upstream resolver:
	// it means that resolver validated DNSSEC, not that we did.
	AD bool
}

// Client resolves a name/type. Implementations must be safe for concurrent use.
type Client interface {
	Query(ctx context.Context, name string, qtype uint16) (*Result, error)
}

// ErrTimeout is returned when every configured server failed or timed out.
var ErrTimeout = errors.New("dns: all servers failed")

// MiekgClient is the production Client backed by github.com/miekg/dns. It sets
// the DO bit so a validating upstream can return the AD flag.
type MiekgClient struct {
	servers []string
	udp     *dns.Client
	tcp     *dns.Client
}

// NewMiekgClient builds a client. If servers is empty it reads the system
// resolver list, falling back to 1.1.1.1 and 8.8.8.8. Bare IPs gain :53.
func NewMiekgClient(servers []string, timeout time.Duration) *MiekgClient {
	if len(servers) == 0 {
		servers = systemServers()
	}
	norm := make([]string, 0, len(servers))
	for _, s := range servers {
		norm = append(norm, withPort(s))
	}
	return &MiekgClient{
		servers: norm,
		udp:     &dns.Client{Net: "udp", Timeout: timeout, UDPSize: 4096},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}
}

// Servers returns the resolver addresses in use (for honest reporting).
func (c *MiekgClient) Servers() []string { return c.servers }

func (c *MiekgClient) Query(ctx context.Context, name string, qtype uint16) (*Result, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	var lastErr error
	for _, srv := range c.servers {
		r, _, err := c.udp.ExchangeContext(ctx, m, srv)
		if err == nil && r != nil && r.Truncated {
			r, _, err = c.tcp.ExchangeContext(ctx, m, srv)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if r == nil {
			lastErr = fmt.Errorf("dns: nil response from %s", srv)
			continue
		}
		return &Result{Records: r.Answer, Rcode: r.Rcode, AD: r.AuthenticatedData}, nil
	}
	if lastErr == nil {
		lastErr = ErrTimeout
	}
	return nil, lastErr
}

func withPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

func systemServers() []string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		out := make([]string, 0, len(cfg.Servers))
		for _, s := range cfg.Servers {
			out = append(out, s)
		}
		return out
	}
	return []string{"1.1.1.1", "8.8.8.8"}
}

// TXTStrings concatenates the character-strings of each TXT RR in the result
// into one string per record, as a verifier reassembling a split record must.
func TXTStrings(res *Result) []string {
	if res == nil {
		return nil
	}
	var out []string
	for _, rr := range res.Records {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}
