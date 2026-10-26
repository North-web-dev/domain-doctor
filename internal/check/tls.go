package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/North-web-dev/domain-doctor/internal/sanitize"
)

// warnExpiryWindow is how close to expiry a leaf certificate earns a WARN.
const warnExpiryWindow = 21 * 24 * time.Hour

// TLSOptions configures the TLS section. Roots nil means system trust store.
type TLSOptions struct {
	Port     int
	Timeout  time.Duration
	Roots    *x509.CertPool
	SkipHSTS bool // tests set this to avoid an HTTP round-trip
}

// RunTLS connects to host:port and audits the certificate, chain, protocol
// versions, ciphers and HSTS. Protocol and cipher probing is best-effort over
// ordinary handshakes, not a full scanner.
func RunTLS(ctx context.Context, host string, opt TLSOptions) Section {
	s := Section{Name: "TLS"}
	if opt.Port == 0 {
		opt.Port = 443
	}
	if opt.Timeout == 0 {
		opt.Timeout = 5 * time.Second
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", opt.Port))

	state, err := handshake(ctx, addr, host, tls.VersionTLS12, tls.VersionTLS13, opt.Timeout, nil)
	if err != nil {
		s.Findings = append(s.Findings, Finding{
			Status: StatusFail,
			Title:  "TLS connection",
			Detail: "could not establish a TLS session with " + sanitize.Clean(addr) + ": " + sanitize.Clean(err.Error()),
			Fix:    "ensure the host listens on this port and serves a valid certificate",
		})
		return s
	}
	leaf := state.PeerCertificates[0]

	s.Findings = append(s.Findings, evalExpiry(leaf, time.Now()))
	s.Findings = append(s.Findings, evalTrust(state.PeerCertificates, host, opt.Roots))
	s.Findings = append(s.Findings, evalSAN(leaf, host))
	s.Findings = append(s.Findings, evalProtocols(ctx, addr, host, opt.Timeout, state.Version))
	s.Findings = append(s.Findings, evalWeakCiphers(ctx, addr, host, opt.Timeout))
	if !opt.SkipHSTS {
		s.Findings = append(s.Findings, evalHSTS(ctx, host, opt.Port, opt.Timeout))
	}
	return s
}

func handshake(ctx context.Context, addr, serverName string, min, max uint16, timeout time.Duration, ciphers []uint16) (*tls.ConnectionState, error) {
	d := &net.Dialer{Timeout: timeout}
	if dl, ok := ctx.Deadline(); ok {
		d.Deadline = dl
	}
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // we verify the chain ourselves in evalTrust
		MinVersion:         min,
		MaxVersion:         max,
	}
	if ciphers != nil {
		cfg.CipherSuites = ciphers
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server presented no certificate")
	}
	return &st, nil
}

func evalExpiry(leaf *x509.Certificate, now time.Time) Finding {
	f := Finding{Title: "Certificate expiry"}
	cn := sanitize.Clean(leaf.Subject.CommonName)
	switch {
	case now.After(leaf.NotAfter):
		f.Status = StatusFail
		f.Detail = fmt.Sprintf("certificate for %q EXPIRED on %s", cn, leaf.NotAfter.UTC().Format(time.RFC3339))
		f.Fix = "renew/reissue the certificate immediately"
	case now.Before(leaf.NotBefore):
		f.Status = StatusWarn
		f.Detail = fmt.Sprintf("certificate not yet valid (NotBefore %s)", leaf.NotBefore.UTC().Format(time.RFC3339))
		f.Fix = "check the server clock and certificate validity window"
	case leaf.NotAfter.Sub(now) < warnExpiryWindow:
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		f.Status = StatusWarn
		f.Detail = fmt.Sprintf("certificate expires in %d days (%s)", days, leaf.NotAfter.UTC().Format("2006-01-02"))
		f.Fix = "renew now; automate renewal (e.g. certbot/ACME) so it cannot lapse"
	default:
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		f.Status = StatusPass
		f.Detail = fmt.Sprintf("valid for %d more days (expires %s)", days, leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	return f
}

func evalTrust(chain []*x509.Certificate, host string, roots *x509.CertPool) Finding {
	f := Finding{Title: "Certificate chain trust"}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
	})
	if err != nil {
		f.Status = StatusFail
		f.Detail = "chain does not verify against the trust store: " + sanitize.Clean(err.Error())
		f.Fix = "serve the full intermediate chain and use a certificate from a trusted CA"
		return f
	}
	issuer := sanitize.Clean(chain[0].Issuer.CommonName)
	f.Status = StatusPass
	f.Detail = fmt.Sprintf("chain builds and is trusted (issuer %q, %d cert(s) presented)", issuer, len(chain))
	return f
}

func evalSAN(leaf *x509.Certificate, host string) Finding {
	f := Finding{Title: "Subject Alternative Name coverage"}
	names := make([]string, 0, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		names = append(names, sanitize.Clean(n))
	}
	coversApex := leaf.VerifyHostname(host) == nil
	www := "www." + host
	coversWWW := leaf.VerifyHostname(www) == nil
	switch {
	case !coversApex:
		f.Status = StatusFail
		f.Detail = fmt.Sprintf("certificate does not cover %q (SAN: %s)", sanitize.Clean(host), summ(names))
		f.Fix = "reissue the certificate with " + sanitize.Clean(host) + " in the SAN list"
	case !coversWWW:
		f.Status = StatusWarn
		f.Detail = fmt.Sprintf("covers %q but not %q (SAN: %s)", sanitize.Clean(host), sanitize.Clean(www), summ(names))
		f.Fix = "add " + sanitize.Clean(www) + " to the SAN list if you serve the www host"
	default:
		f.Status = StatusPass
		f.Detail = fmt.Sprintf("covers %q and %q (SAN: %s)", sanitize.Clean(host), sanitize.Clean(www), summ(names))
	}
	return f
}

func evalProtocols(ctx context.Context, addr, host string, timeout time.Duration, negotiated uint16) Finding {
	f := Finding{Title: "Protocol versions"}
	var legacy []string
	if _, err := handshake(ctx, addr, host, tls.VersionTLS10, tls.VersionTLS10, timeout, nil); err == nil {
		legacy = append(legacy, "TLS 1.0")
	}
	if _, err := handshake(ctx, addr, host, tls.VersionTLS11, tls.VersionTLS11, timeout, nil); err == nil {
		legacy = append(legacy, "TLS 1.1")
	}
	has13 := false
	if _, err := handshake(ctx, addr, host, tls.VersionTLS13, tls.VersionTLS13, timeout, nil); err == nil {
		has13 = true
	}
	modern := "TLS 1.2"
	if has13 {
		modern = "TLS 1.2, TLS 1.3"
	}
	if len(legacy) > 0 {
		f.Status = StatusFail
		f.Detail = fmt.Sprintf("accepts deprecated %s (also %s)", strings.Join(legacy, " and "), modern)
		f.Fix = "disable TLS 1.0/1.1 at the server; require TLS 1.2 minimum"
		return f
	}
	f.Status = StatusPass
	f.Detail = fmt.Sprintf("TLS 1.0/1.1 refused; offers %s (negotiated %s)", modern, tlsVersionName(negotiated))
	return f
}

func evalWeakCiphers(ctx context.Context, addr, host string, timeout time.Duration) Finding {
	f := Finding{Title: "Weak ciphers (best-effort)"}
	weak := make([]uint16, 0)
	for _, cs := range tls.InsecureCipherSuites() {
		weak = append(weak, cs.ID)
	}
	st, err := handshake(ctx, addr, host, tls.VersionTLS10, tls.VersionTLS12, timeout, weak)
	if err != nil {
		f.Status = StatusPass
		f.Detail = "server refused the legacy cipher suites offered (RC4 / 3DES / CBC-SHA)"
		return f
	}
	f.Status = StatusWarn
	f.Detail = "server accepted a legacy cipher suite when offered: " + sanitize.Clean(tls.CipherSuiteName(st.CipherSuite))
	f.Fix = "disable legacy RC4, 3DES and CBC-SHA cipher suites in the server config"
	return f
}

func evalHSTS(ctx context.Context, host string, port int, timeout time.Duration) Finding {
	f := Finding{Title: "HSTS header"}
	url := fmt.Sprintf("https://%s/", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects (SSRF guard)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		f.Status = StatusInfo
		f.Detail = "could not build HSTS probe request"
		return f
	}
	resp, err := client.Do(req)
	if err != nil {
		f.Status = StatusInfo
		f.Detail = "could not fetch headers for HSTS check: " + sanitize.Clean(err.Error())
		return f
	}
	defer resp.Body.Close()
	if h := resp.Header.Get("Strict-Transport-Security"); h != "" {
		f.Status = StatusPass
		f.Detail = "present: " + sanitize.Clean(h)
		return f
	}
	f.Status = StatusWarn
	f.Detail = "no Strict-Transport-Security response header"
	f.Fix = `send: Strict-Transport-Security: max-age=31536000; includeSubDomains`
	return f
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}
