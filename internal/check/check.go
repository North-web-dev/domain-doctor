// Package check runs the domain audit and produces a graded report.
package check

import "strconv"

// Status is the grade of a single finding or section.
type Status int

const (
	StatusInfo Status = iota
	StatusPass
	StatusWarn
	StatusFail
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	default:
		return "INFO"
	}
}

// MarshalJSON renders the status as its name.
func (s Status) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}

// Finding is one audited item.
type Finding struct {
	Status Status `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Section groups findings (DNS, Mail, TLS).
type Section struct {
	Name     string    `json:"name"`
	Findings []Finding `json:"findings"`
	// Skipped is set when --only excluded this section.
	Skipped bool `json:"skipped,omitempty"`
}

// Status of a section is the worst status among its findings.
func (s Section) Worst() Status {
	w := StatusInfo
	for _, f := range s.Findings {
		if f.Status > w {
			w = f.Status
		}
	}
	return w
}

// Report is the full audit result.
type Report struct {
	Domain   string    `json:"domain"`
	Target   string    `json:"target,omitempty"`
	Sections []Section `json:"sections"`
}

// Overall returns the worst status across all run sections.
func (r Report) Overall() Status {
	w := StatusInfo
	for _, s := range r.Sections {
		if s.Skipped {
			continue
		}
		if sw := s.Worst(); sw > w {
			w = sw
		}
	}
	return w
}

// Counts tallies findings by status across run sections.
func (r Report) Counts() (pass, warn, fail int) {
	for _, s := range r.Sections {
		if s.Skipped {
			continue
		}
		for _, f := range s.Findings {
			switch f.Status {
			case StatusPass:
				pass++
			case StatusWarn:
				warn++
			case StatusFail:
				fail++
			}
		}
	}
	return
}

// Grade maps the findings to a letter grade. Any FAIL caps the grade at F;
// otherwise warnings lower an A toward C.
func (r Report) Grade() string {
	pass, warn, fail := r.Counts()
	if fail > 0 {
		return "F"
	}
	if warn == 0 {
		if pass == 0 {
			return "—"
		}
		return "A"
	}
	switch {
	case warn <= 1:
		return "B"
	case warn <= 3:
		return "C"
	default:
		return "D"
	}
}

// ExitCode is 1 when any section FAILs, else 0. Usage/resolve errors are
// handled by the caller as exit code 2.
func (r Report) ExitCode() int {
	if r.Overall() == StatusFail {
		return 1
	}
	return 0
}
