// Package input validates and normalises the user-supplied domain so the rest
// of the tool only ever handles a clean hostname (no scheme, port, path, or
// control characters) — the sole target we will resolve or connect to.
package input

import (
	"errors"
	"strings"
)

// ParseDomain normalises raw into a bare lowercase hostname. It accepts input
// with a scheme, a trailing path, a port or a trailing dot and strips them. It
// rejects anything that is not a plausible DNS hostname.
func ParseDomain(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty domain")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimPrefix(s, "*.") // a wildcard cert name → its base
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 { // user@host
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 { // host:port
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)

	if s == "" {
		return "", errors.New("no hostname found in input")
	}
	if len(s) > 253 {
		return "", errors.New("domain exceeds 253 characters")
	}
	if !strings.Contains(s, ".") {
		return "", errors.New("not a fully-qualified domain (needs at least one dot)")
	}
	for _, label := range strings.Split(s, ".") {
		if err := validLabel(label); err != nil {
			return "", err
		}
	}
	return s, nil
}

func validLabel(label string) error {
	if label == "" {
		return errors.New("empty label (consecutive dots)")
	}
	if len(label) > 63 {
		return errors.New("label exceeds 63 characters")
	}
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return errors.New("label may not start or end with a hyphen: " + label)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		case r == '_': // permitted in DNS labels for records like _dmarc
		default:
			return errors.New("invalid character in domain label")
		}
	}
	return nil
}
