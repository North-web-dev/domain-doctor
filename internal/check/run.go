package check

import (
	"context"
	"sync"

	"github.com/North-web-dev/domain-doctor/internal/resolve"
)

// Options controls which sections run and how.
type Options struct {
	DNS           bool
	Mail          bool
	TLS           bool
	DKIMSelectors []string
	TLS_          TLSOptions
}

// Run executes the enabled sections concurrently and returns an ordered report.
func Run(ctx context.Context, c resolve.Client, domain string, opt Options) Report {
	type slot struct {
		idx int
		sec Section
	}
	var tasks []func() slot
	order := 0

	add := func(name string, enabled bool, fn func() Section) {
		idx := order
		order++
		if !enabled {
			tasks = append(tasks, func() slot { return slot{idx, Section{Name: name, Skipped: true}} })
			return
		}
		tasks = append(tasks, func() slot { return slot{idx, fn()} })
	}

	add("DNS", opt.DNS, func() Section { return RunDNS(ctx, c, domain) })
	add("Mail authentication", opt.Mail, func() Section {
		return RunMail(ctx, c, domain, selectorsOrDefault(opt.DKIMSelectors))
	})
	add("TLS", opt.TLS, func() Section { return RunTLS(ctx, domain, opt.TLS_) })

	results := make([]Section, len(tasks))
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(fn func() slot) {
			defer wg.Done()
			s := fn()
			results[s.idx] = s.sec
		}(t)
	}
	wg.Wait()

	return Report{Domain: domain, Target: domain, Sections: results}
}

func selectorsOrDefault(sel []string) []string {
	out := append([]string{}, DefaultDKIMSelectors...)
	out = append(out, sel...)
	return out
}
