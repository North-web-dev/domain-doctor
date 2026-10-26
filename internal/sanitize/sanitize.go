// Package sanitize makes attacker-influenced strings (TXT records, cert
// CN/SAN) safe to print to a terminal.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

const maxStringLen = 4096

// Clean strips control characters (including ANSI escape sequences, NUL, and
// other C0/C1 bytes) from s, replacing each with a visible placeholder, and
// caps the length. Tabs and ordinary spaces are preserved; all other
// non-printing runes become "." so a hostile record cannot rewrite the
// terminal.
func Clean(s string) string {
	if len(s) > maxStringLen {
		s = s[:maxStringLen] + "…(truncated)"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteByte('.')
		case r == '\t':
			b.WriteByte(' ')
		case r == 0x7f: // DEL
			b.WriteByte('.')
		case r < 0x20: // C0 controls incl. ESC, CR, LF, NUL
			b.WriteByte('.')
		case r >= 0x80 && r <= 0x9f: // C1 controls
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
