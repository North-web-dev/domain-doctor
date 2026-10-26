package input

import "testing"

func TestParseDomainNormalises(t *testing.T) {
	cases := map[string]string{
		"example.com":                    "example.com",
		"EXAMPLE.COM":                    "example.com",
		"https://example.com/path?q=1":   "example.com",
		"http://user@example.com:8443/x": "example.com",
		"example.com.":                   "example.com",
		"*.example.com":                  "example.com",
		"sub.example.co.uk":              "sub.example.co.uk",
		"  spaced.example.com  ":         "spaced.example.com",
		"_dmarc.example.com":             "_dmarc.example.com",
	}
	for in, want := range cases {
		got, err := ParseDomain(in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestParseDomainRejects(t *testing.T) {
	bad := []string{
		"",
		"nodot",
		"has space.com",
		"bad_char!.com",
		"-leadinghyphen.com",
		"trailinghyphen-.com",
		"double..dot.com",
		"ctrl\x00.com",
		"line\nfeed.com",
	}
	for _, in := range bad {
		if got, err := ParseDomain(in); err == nil {
			t.Errorf("%q: expected error, got %q", in, got)
		}
	}
}
