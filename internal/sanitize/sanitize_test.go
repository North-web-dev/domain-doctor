package sanitize

import (
	"strings"
	"testing"
)

func TestCleanStripsControlAndEscape(t *testing.T) {
	// A TXT record carrying an ANSI clear-screen + colour escape and a NUL.
	in := "v=spf1 \x1b[2J\x1b[31mINJECT\x1b[0m include:evil\x00.com ~all\r\n"
	got := Clean(in)
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("ESC survived sanitization: %q", got)
	}
	if strings.ContainsRune(got, 0x00) {
		t.Fatalf("NUL survived sanitization: %q", got)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("CR/LF survived sanitization: %q", got)
	}
	if !strings.Contains(got, "v=spf1") || !strings.Contains(got, "INJECT") {
		t.Fatalf("printable content lost: %q", got)
	}
}

func TestCleanKeepsPrintableAndUnicode(t *testing.T) {
	in := "normal text — ключ 日本語"
	if got := Clean(in); got != in {
		t.Fatalf("printable unicode altered: %q != %q", got, in)
	}
}

func TestCleanCapsLength(t *testing.T) {
	in := strings.Repeat("a", maxStringLen+500)
	got := Clean(in)
	if !strings.Contains(got, "truncated") {
		t.Fatalf("overlong string not truncated")
	}
}

func TestCleanTabBecomesSpace(t *testing.T) {
	if got := Clean("a\tb"); got != "a b" {
		t.Fatalf("tab not normalised: %q", got)
	}
}
