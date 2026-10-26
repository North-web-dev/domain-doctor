// Package report renders a check.Report as human text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/North-web-dev/domain-doctor/internal/check"
)

type palette struct{ reset, pass, warn, fail, info, bold, dim string }

func colors(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{
		reset: "\033[0m", pass: "\033[32m", warn: "\033[33m",
		fail: "\033[31m", info: "\033[36m", bold: "\033[1m", dim: "\033[2m",
	}
}

func (p palette) tag(s check.Status) string {
	switch s {
	case check.StatusPass:
		return p.pass + "PASS" + p.reset
	case check.StatusWarn:
		return p.warn + "WARN" + p.reset
	case check.StatusFail:
		return p.fail + "FAIL" + p.reset
	default:
		return p.info + "INFO" + p.reset
	}
}

// Text writes a graded, human-readable report.
func Text(w io.Writer, r check.Report, color bool) {
	p := colors(color)
	fmt.Fprintf(w, "\n%sdomain-doctor%s report for %s%s%s\n", p.bold, p.reset, p.bold, r.Domain, p.reset)
	fmt.Fprintf(w, "%s%s%s\n", p.dim, strings.Repeat("─", 60), p.reset)

	for _, sec := range r.Sections {
		if sec.Skipped {
			continue
		}
		fmt.Fprintf(w, "\n%s%s%s  [%s]\n", p.bold, sec.Name, p.reset, p.tag(sec.Worst()))
		for _, f := range sec.Findings {
			fmt.Fprintf(w, "  %s  %s\n", p.tag(f.Status), f.Title)
			if f.Detail != "" {
				fmt.Fprintf(w, "        %s%s%s\n", p.dim, f.Detail, p.reset)
			}
			if f.Fix != "" {
				fmt.Fprintf(w, "        %s↳ fix:%s %s\n", p.bold, p.reset, f.Fix)
			}
		}
	}

	pass, warn, fail := r.Counts()
	fmt.Fprintf(w, "\n%s%s%s\n", p.dim, strings.Repeat("─", 60), p.reset)
	fmt.Fprintf(w, "%sOverall: %s%s   grade %s%s%s   (%d pass, %d warn, %d fail)\n",
		p.bold, p.tag(r.Overall()), p.reset, p.bold, r.Grade(), p.reset, pass, warn, fail)
	fmt.Fprintln(w)
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, r check.Report) error {
	pass, warn, fail := r.Counts()
	out := struct {
		check.Report
		Overall string `json:"overall"`
		Grade   string `json:"grade"`
		Pass    int    `json:"pass"`
		Warn    int    `json:"warn"`
		Fail    int    `json:"fail"`
		Exit    int    `json:"exit_code"`
	}{
		Report:  r,
		Overall: r.Overall().String(),
		Grade:   r.Grade(),
		Pass:    pass, Warn: warn, Fail: fail,
		Exit: r.ExitCode(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
