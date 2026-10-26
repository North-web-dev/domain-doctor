// Command domain-doctor audits a domain's DNS, email authentication and TLS in
// one pass and prints a graded report with a one-line fix for each problem.
//
// It performs read-only network lookups against the named domain and standard
// resolvers only. It never sends mail, never changes DNS, and never follows
// redirects to other hosts.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/North-web-dev/domain-doctor/internal/check"
	"github.com/North-web-dev/domain-doctor/internal/input"
	"github.com/North-web-dev/domain-doctor/internal/report"
	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("domain-doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		jsonOut     = fs.Bool("json", false, "emit machine-readable JSON")
		only        = fs.String("only", "", "restrict to a comma list of sections: dns,mail,tls")
		timeout     = fs.Duration("timeout", 5*time.Second, "per-query / per-connection timeout")
		port        = fs.Int("port", 443, "TLS port to connect to")
		resolver    = fs.String("resolver", "", "comma list of DNS servers (default: system, then 1.1.1.1/8.8.8.8)")
		dkimSel     = fs.String("dkim-selector", "", "extra DKIM selectors to probe (comma-separated)")
		noColor     = fs.Bool("no-color", false, "disable ANSI colour")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "domain-doctor %s — audit a domain's DNS, email auth and TLS.\n\n", version)
		fmt.Fprintf(stderr, "Usage:\n  domain-doctor [flags] <domain>\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 no failures, 1 at least one FAIL, 2 usage/resolve error.\n")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "domain-doctor "+version)
		return 0
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	domain, err := input.ParseDomain(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid domain: %v\n", err)
		return 2
	}

	opt := check.Options{DNS: true, Mail: true, TLS: true}
	if *only != "" {
		opt.DNS, opt.Mail, opt.TLS = false, false, false
		for _, s := range strings.Split(*only, ",") {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "dns":
				opt.DNS = true
			case "mail":
				opt.Mail = true
			case "tls":
				opt.TLS = true
			case "":
			default:
				fmt.Fprintf(stderr, "error: unknown --only section %q (valid: dns,mail,tls)\n", s)
				return 2
			}
		}
	}
	if *dkimSel != "" {
		opt.DKIMSelectors = splitComma(*dkimSel)
	}
	opt.TLS_ = check.TLSOptions{Port: *port, Timeout: *timeout}

	var servers []string
	if *resolver != "" {
		servers = splitComma(*resolver)
	}
	client := resolve.NewMiekgClient(servers, *timeout)

	ctx, cancel := context.WithTimeout(context.Background(), globalDeadline(*timeout))
	defer cancel()

	if opt.DNS || opt.Mail {
		if err := preflight(ctx, client, domain); err != nil {
			fmt.Fprintf(stderr, "error: cannot resolve %q: %v\n", domain, err)
			return 2
		}
	}

	rep := check.Run(ctx, client, domain, opt)

	if *jsonOut {
		if err := report.JSON(stdout, rep); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	} else {
		report.Text(stdout, rep, !*noColor && isTerminal(stdout))
	}
	return rep.ExitCode()
}

// preflight confirms the domain exists in DNS at all, so a typo returns a clean
// exit code 2 rather than a wall of failures.
func preflight(ctx context.Context, c resolve.Client, domain string) error {
	res, err := c.Query(ctx, domain, dns.TypeNS)
	if err != nil {
		return err
	}
	if res.Rcode == dns.RcodeNameError {
		return fmt.Errorf("NXDOMAIN (domain does not exist)")
	}
	return nil
}

func globalDeadline(per time.Duration) time.Duration {
	d := per * 20
	if d < 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
