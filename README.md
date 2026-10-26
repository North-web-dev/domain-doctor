# domain-doctor

[![Release](https://img.shields.io/github/v/release/North-web-dev/domain-doctor?sort=semver)](https://github.com/North-web-dev/domain-doctor/releases) [![Go Reference](https://pkg.go.dev/badge/github.com/North-web-dev/domain-doctor.svg)](https://pkg.go.dev/github.com/North-web-dev/domain-doctor) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Go](https://img.shields.io/github/go-mod/go-version/North-web-dev/domain-doctor)

[![ci](https://github.com/North-web-dev/domain-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/North-web-dev/domain-doctor/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/North-web-dev/domain-doctor.svg)](https://pkg.go.dev/github.com/North-web-dev/domain-doctor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Audit a domain's **DNS**, **email authentication** (SPF / DKIM / DMARC) and **TLS**
in one command. domain-doctor prints a graded report — `PASS` / `WARN` / `FAIL`
per check — with the exact one-line fix for every problem it finds. Zero config,
single static binary, read-only.

```
domain-doctor example.com
```

## The problem

Every time you ship a domain you tend to botch the same handful of things, and
none of them throw an error until a customer complains:

- Mail silently lands in spam because SPF, DKIM or DMARC is broken — most often
  because the **SPF record quietly blew past the 10-DNS-lookup limit** and now
  returns PermError.
- The TLS certificate expires over a weekend because nobody was watching the
  clock.
- `DNSSEC` and `CAA` were never turned on.
- Legacy `TLS 1.0 / 1.1` is still accepted.

The usual way to check these is a dozen manual `dig` and `openssl s_client`
invocations, or pasting your domain into a paid web tool. domain-doctor does the
whole sweep locally in one command and tells you what to change.

## Install

With Go 1.25 or newer:

```
go install github.com/North-web-dev/domain-doctor/cmd/domain-doctor@latest
```

Or grab a prebuilt binary (linux / macOS / windows, amd64 + arm64) from the
[releases page](https://github.com/North-web-dev/domain-doctor/releases). Each
release ships a `checksums.txt`:

```
tar -xzf domain-doctor_v0.1.0_linux_amd64.tar.gz
./domain-doctor example.com
```

Docker (distroless, static, non-root):

```
docker build -t domain-doctor .
docker run --rm domain-doctor example.com
```

## Usage

```
domain-doctor [flags] <domain>

  --json                   emit machine-readable JSON
  --only dns,mail,tls      restrict to a comma list of sections
  --timeout 5s             per-query / per-connection timeout
  --port 443               TLS port to connect to
  --resolver 1.1.1.1,8.8.8.8   DNS servers (default: system, then 1.1.1.1/8.8.8.8)
  --dkim-selector s1,s2    extra DKIM selectors to probe
  --no-color               disable ANSI colour
  --version
```

The domain argument is forgiving — `https://example.com/path`, `example.com:443`
and `user@example.com` all normalise to `example.com`.

## Example report

Run against a domain that does not publish SPF or DMARC:

```
$ domain-doctor neverssl.com

domain-doctor report for neverssl.com
────────────────────────────────────────────────────────────

DNS  [WARN]
  PASS  A / AAAA address records
        A: 34.223.124.45  AAAA: 2600:1f13:37c:1400:ba21:7165:5fc7:736e
  INFO  MX mail exchangers
        no MX records (this domain does not receive mail)
  PASS  NS nameservers
        4 nameservers: ns-1716.awsdns-22.co.uk, ns-320.awsdns-40.com, ...
  PASS  SOA start of authority
        primary ns-1716.awsdns-22.co.uk, serial 1, refresh 7200s
  INFO  TXT records
        no TXT records at the apex
  WARN  CAA certificate authority authorization
        no CAA record — any certificate authority may issue for this domain
        ↳ fix: publish a CAA record, e.g. neverssl.com IN CAA 0 issue "letsencrypt.org"
  WARN  DNSSEC
        zone is not DNSSEC-signed (no DNSKEY)
        ↳ fix: enable DNSSEC at your DNS provider and add the DS record at the registrar

Mail authentication  [FAIL]
  FAIL  SPF (sender policy framework)
        no SPF record published
        ↳ fix: publish: neverssl.com IN TXT "v=spf1 include:<your-provider> -all"
  WARN  DKIM (domainkeys identified mail)
        no DKIM key found (checked selectors: default, google, selector1, selector2,
        k1, mail, dkim, s1, s2 — cannot enumerate all)
        ↳ fix: if you send mail, publish a DKIM key and pass its selector with --dkim-selector
  FAIL  DMARC (domain-based message authentication)
        no DMARC record at _dmarc.neverssl.com
        ↳ fix: publish _dmarc.neverssl.com IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@neverssl.com"
              then tighten to quarantine/reject

TLS  [WARN]
  PASS  Certificate expiry
        valid for 58 more days (expires 2026-12-23)
  PASS  Certificate chain trust
        chain builds and is trusted (issuer "Amazon RSA 2048 M04", 3 cert(s) presented)
  PASS  Subject Alternative Name coverage
        covers "neverssl.com" and "www.neverssl.com" (SAN: neverssl.com, *.neverssl.com)
  PASS  Protocol versions
        TLS 1.0/1.1 refused; offers TLS 1.2, TLS 1.3 (negotiated TLS 1.3)
  WARN  Weak ciphers (best-effort)
        server accepted a legacy cipher suite when offered: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        ↳ fix: disable legacy RC4, 3DES and CBC-SHA cipher suites in the server config

────────────────────────────────────────────────────────────
Overall: FAIL   grade F   (7 pass, 4 warn, 2 fail)
```

A well-configured domain with a certificate expiring soon or 1024-bit DKIM keys
produces `WARN` lines with the same `↳ fix:` hint; a certificate that has
actually expired, or a server that still answers TLS 1.0, produces `FAIL`.

## What each section checks

### DNS

| Check | Grades |
|---|---|
| `A` / `AAAA` | address records resolve; notes if IPv6 is absent |
| `MX` | mail exchangers present, sorted by preference, and **each MX host itself resolves** to an address; understands RFC 7505 null MX |
| `NS` | at least two nameservers (one is a `WARN` — no redundancy) |
| `SOA` | start-of-authority present, with primary + serial |
| `TXT` | apex TXT records listed (sanitized) |
| `CAA` | present? **missing is a `WARN`** — without it, any CA may issue for your domain |
| `DNSSEC` | zone is signed (publishes `DNSKEY`) and the resolver set the `AD` bit |

### Mail authentication

- **SPF** — fetches the TXT record, parses every mechanism, and **counts the
  DNS-lookup-causing terms** (see below). Flags `+all` / `?all` as dangerous,
  notes `~all` vs `-all`, detects multiple SPF records, and follows `include:`
  and `redirect=` recursively to count nested lookups (bounded, loop-safe).
- **DKIM** — probes the common selectors (`default`, `google`, `selector1`,
  `selector2`, `k1`, `mail`, `dkim`, `s1`, `s2`) plus any you pass with
  `--dkim-selector`. Reports which exist, parses the public key, flags a revoked
  key (`p=` empty) and derivable weak RSA sizes (`<1024` FAIL, `<2048` WARN).
- **DMARC** — reads `_dmarc.<domain>`: policy (`p=none` is a `WARN`, "monitoring
  only"), `rua`/`ruf` reporting addresses, `adkim`/`aspf` alignment and `sp=`.
  The fix line walks you through the safe `none → quarantine → reject` rollout.

### TLS

Connects to `:443` (or `--port`) and audits:

- **Leaf expiry** — `WARN` within 21 days, `FAIL` if expired.
- **Chain trust** — the chain builds and verifies against the system trust store.
- **SAN coverage** — the certificate actually covers the domain *and* `www.`.
- **Protocol versions** — `FAIL` if TLS 1.0 or 1.1 is accepted; notes 1.2 / 1.3.
- **Weak ciphers** — a best-effort probe that offers only known-legacy suites.
- **HSTS** — whether a `Strict-Transport-Security` header is returned.

## The SPF 10-lookup gotcha

This is the single most common real-world mail breakage, and it is invisible
until you hit it. [RFC 7208 §4.6.4](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4)
says an SPF evaluation **must not require more than 10 DNS lookups**. Each of
these mechanisms costs one lookup — `include`, `a`, `mx`, `ptr`, `exists` — as
does the `redirect` modifier. `ip4`, `ip6` and `all` cost nothing. Crucially,
**the count is recursive**: every `include:` pulls in another record whose own
lookups add to the *same* budget of 10.

So a record that looks fine —

```
v=spf1 include:_spf.google.com include:servers.mcsv.net include:sendgrid.net
       include:spf.protection.outlook.com include:_spf.salesforce.com -all
```

— can quietly exceed 10 once you expand what those providers include. When it
does, conforming receivers return `PermError` and your SPF **fails entirely**,
so legitimate mail starts getting marked as spam. domain-doctor flattens the
include tree (bounded depth, with loop detection), prints the real total, and
`FAIL`s when it is over 10:

```
SPF … — 12 DNS lookups; EXCEEDS the 10-lookup limit (12) — SPF returns PermError and fails
  ↳ fix: reduce include/a/mx/ptr/exists terms below 11 (flatten includes or drop unused ones)
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no `FAIL` findings (warnings do not fail the run, so it is CI-friendly) |
| `1` | at least one `FAIL` |
| `2` | usage error, invalid domain, or the domain could not be resolved at all |

`--json` emits the full report plus `overall`, `grade`, counts and `exit_code`
for scripting.

## Honest limits

domain-doctor reports only what it actually resolved or measured — it never
fabricates a DNS answer or a verdict. Where a check cannot be exhaustive, it
says so rather than implying certainty:

- **DKIM selectors cannot be enumerated.** DNS does not let you list the
  selectors under `_domainkey`; a sender can use any name. domain-doctor probes
  a fixed common set (plus whatever you pass) and the report states exactly which
  selectors it checked. "No DKIM found" means "not found at these selectors",
  not "no DKIM exists".
- **Cipher and protocol probing is best-effort**, done over ordinary Go
  handshakes — not a full scanner like testssl.sh. The protocol check reports
  which versions a handshake *actually* succeeded with; if the Go runtime
  declines to offer a legacy version the result errs toward "not offered". The
  weak-cipher check only offers the suites Go still implements as insecure.
- **DNSSEC validation depth.** domain-doctor reports whether the zone publishes
  `DNSKEY` records and whether the *upstream resolver* set the `AD`
  (Authenticated Data) bit. It does not itself walk and cryptographically
  validate the chain of trust from the root — use a dedicated validator for that.
- It audits the apex domain you name. It does not crawl subdomains.

## Security notes

- **Read-only.** domain-doctor only performs DNS queries and TLS connections. It
  never sends mail, never writes DNS, and makes no state-changing request.
- **Single target.** It connects only to the domain you name and to standard DNS
  resolvers. The HSTS probe uses `HEAD` with redirect-following disabled, so a
  server cannot bounce the tool to an internal host (no SSRF beyond the named
  target).
- **Input is validated.** The domain is parsed into a bare hostname before any
  query; control characters, whitespace and malformed labels are rejected.
- **Output is terminal-safe.** TXT records and certificate CN/SAN fields are
  attacker-influenced, so every such string is stripped of control characters
  and ANSI escape sequences, and length-capped, before it is printed. A hostile
  record cannot rewrite your terminal.
- The TLS section intentionally completes the handshake with verification
  disabled *in order to inspect the presented certificate even when it is
  untrusted*, then verifies the chain itself and reports the result. This is the
  only way to tell you *why* a chain is untrusted; it never trusts a bad chain.

## Development

```
go build ./...
go vet ./...
gofmt -l .
go test ./... -race
```

Tests use fixtures, an in-memory fake resolver and an in-process TLS server —
they make no live network calls. The one runtime dependency is
[`github.com/miekg/dns`](https://github.com/miekg/dns) for proper DNS
(`CAA`, `DNSKEY`, raw `TXT`, explicit resolver); everything else is the Go
standard library.

## Support

If domain-doctor saved you a debugging session, a ⭐ on the repo is appreciated —
and tips are welcome:

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## License

[MIT](LICENSE)
