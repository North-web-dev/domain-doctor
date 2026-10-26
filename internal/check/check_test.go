package check

import "testing"

func report(findings ...Finding) Report {
	return Report{Domain: "x", Sections: []Section{{Name: "s", Findings: findings}}}
}

func TestExitCodeAndGrade(t *testing.T) {
	cases := []struct {
		name      string
		r         Report
		wantExit  int
		wantGrade string
	}{
		{"all pass", report(Finding{Status: StatusPass}, Finding{Status: StatusPass}), 0, "A"},
		{"one warn", report(Finding{Status: StatusPass}, Finding{Status: StatusWarn}), 0, "B"},
		{"many warn", report(Finding{Status: StatusWarn}, Finding{Status: StatusWarn}, Finding{Status: StatusWarn}, Finding{Status: StatusWarn}), 0, "D"},
		{"any fail", report(Finding{Status: StatusPass}, Finding{Status: StatusFail}), 1, "F"},
	}
	for _, c := range cases {
		if got := c.r.ExitCode(); got != c.wantExit {
			t.Errorf("%s: exit = %d want %d", c.name, got, c.wantExit)
		}
		if got := c.r.Grade(); got != c.wantGrade {
			t.Errorf("%s: grade = %q want %q", c.name, got, c.wantGrade)
		}
	}
}

func TestSkippedSectionsIgnored(t *testing.T) {
	r := Report{Sections: []Section{
		{Name: "a", Findings: []Finding{{Status: StatusPass}}},
		{Name: "b", Skipped: true, Findings: []Finding{{Status: StatusFail}}},
	}}
	if r.ExitCode() != 0 {
		t.Fatal("skipped section's FAIL must not affect the exit code")
	}
}

func TestWorstStatus(t *testing.T) {
	s := Section{Findings: []Finding{{Status: StatusPass}, {Status: StatusWarn}, {Status: StatusInfo}}}
	if s.Worst() != StatusWarn {
		t.Fatalf("worst = %v want WARN", s.Worst())
	}
}
