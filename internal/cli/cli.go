// Package cli wires probes, output formatters, and cobra commands into
// the mailsec-probe binary.
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/shigeya/mailsec-probe/internal/classifier"
	"github.com/shigeya/mailsec-probe/internal/output"
	"github.com/shigeya/mailsec-probe/internal/probe/bimi"
	"github.com/shigeya/mailsec-probe/internal/probe/dkim"
	"github.com/shigeya/mailsec-probe/internal/probe/dmarc"
	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/dnssec"
	"github.com/shigeya/mailsec-probe/internal/probe/mtasts"
	"github.com/shigeya/mailsec-probe/internal/probe/mx"
	"github.com/shigeya/mailsec-probe/internal/probe/spf"
	"github.com/shigeya/mailsec-probe/internal/probe/tlsrpt"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

// Version is overwritten at build time via -ldflags.
var Version = "0.1.0-dev"

// Exit codes:
//
//	0 — every domain was observed (regardless of feature presence)
//	1 — at least one domain failed observation outright
//	2 — invalid flags or arguments
const (
	// exitOK = 0 is implicit (no os.Exit call).
	exitObservationErr = 1
	exitUsageErr       = 2
)

// Execute runs the root command and exits with the appropriate code.
func Execute() {
	root := newRoot()
	err := root.Execute()
	if err != nil {
		if ec, ok := err.(*exitCodeErr); ok {
			os.Exit(ec.code)
		}
		fmt.Fprintf(os.Stderr, "mailsec-probe: %v\n", err)
		os.Exit(exitUsageErr)
	}
}

// exitCodeErr is returned by RunE to request a specific non-zero exit
// without printing an error message (the formatted report was already
// written to stdout).
type exitCodeErr struct{ code int }

func (e *exitCodeErr) Error() string { return fmt.Sprintf("exit %d", e.code) }

type rootOpts struct {
	outputFmt       string
	dnsServer       string
	dkimSelectors   []string
	dkimSelFile     string
	timeout         time.Duration
	concurrency     int
	includeRaw      bool
	verbose         int
}

func newRoot() *cobra.Command {
	opts := &rootOpts{
		outputFmt:   "human",
		timeout:     10 * time.Second,
		concurrency: 8,
	}

	cmd := &cobra.Command{
		Use:           "mailsec-probe <domain> [domain...]",
		Short:         "Observe mail-security DNS records (SPF/DMARC/DKIM/MX/MTA-STS/TLS-RPT/BIMI/DNSSEC)",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogger(opts.verbose)
			return run(cmd.Context(), opts, args)
		},
	}

	pf := cmd.PersistentFlags()
	pf.StringVarP(&opts.outputFmt, "output", "o", opts.outputFmt, "output format: human|json")
	pf.StringVar(&opts.dnsServer, "dns-server", "", "DNS server to query (host or host:port). Default: system resolver")
	pf.StringSliceVar(&opts.dkimSelectors, "dkim-selector", nil, "additional DKIM selector to probe (repeatable)")
	pf.StringVar(&opts.dkimSelFile, "dkim-selectors-file", "", "override the embedded DKIM selector list with this YAML file")
	pf.DurationVar(&opts.timeout, "timeout", opts.timeout, "per-domain observation timeout")
	pf.IntVar(&opts.concurrency, "concurrency", opts.concurrency, "max parallel domains")
	pf.BoolVar(&opts.includeRaw, "include-raw", false, "include raw TXT/HTTPS bodies in the output")
	pf.CountVarP(&opts.verbose, "verbose", "v", "increase verbosity (-v info, -vv debug)")

	return cmd
}

func setupLogger(v int) {
	level := slog.LevelWarn
	switch {
	case v >= 2:
		level = slog.LevelDebug
	case v == 1:
		level = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}

func run(ctx context.Context, opts *rootOpts, domains []string) error {
	dnsCli, err := dnsclient.New(dnsclient.Config{
		Server:  opts.dnsServer,
		Timeout: opts.timeout,
	})
	if err != nil {
		return fmt.Errorf("init DNS client: %w", err)
	}

	probes, err := buildProbes(dnsCli, opts)
	if err != nil {
		return err
	}
	runner := classifier.New(probes...)

	reports := make([]signals.Report, len(domains))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(opts.concurrency)
	for i, d := range domains {
		d := strings.TrimSpace(strings.ToLower(d))
		g.Go(func() error {
			rctx, cancel := context.WithTimeout(gctx, opts.timeout*2)
			defer cancel()
			reports[i] = runner.Run(rctx, d)
			return nil
		})
	}
	_ = g.Wait()

	switch opts.outputFmt {
	case "json":
		if err := output.WriteJSON(os.Stdout, reports); err != nil {
			return err
		}
	case "human", "":
		if err := output.WriteHuman(os.Stdout, reports); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown output format %q (want human|json)", opts.outputFmt)
	}

	if anyDomainFailed(reports) {
		return &exitCodeErr{code: exitObservationErr}
	}
	return nil
}

// anyDomainFailed reports whether any report represents a complete
// observation failure (every feature unknown, or a top-level error).
func anyDomainFailed(reports []signals.Report) bool {
	for _, r := range reports {
		if len(r.Errors) > 0 || len(r.Features) == 0 {
			return true
		}
		allUnknown := true
		for _, f := range r.Features {
			if f.Status != signals.StatusUnknown {
				allUnknown = false
				break
			}
		}
		if allUnknown {
			return true
		}
	}
	return false
}

func buildProbes(dnsCli dnsclient.Client, opts *rootOpts) ([]classifier.Probe, error) {
	var dkimSelectorsYAML []byte
	if opts.dkimSelFile != "" {
		b, err := os.ReadFile(opts.dkimSelFile)
		if err != nil {
			return nil, fmt.Errorf("read DKIM selectors file: %w", err)
		}
		dkimSelectorsYAML = b
	}

	var dkimProbe *dkim.Probe
	{
		// Load (possibly overridden) base selectors, then append --dkim-selector.
		baseSel, err := dkim.LoadSelectors(dkimSelectorsYAML)
		if err != nil {
			return nil, err
		}
		merged := append(append([]string{}, baseSel...), opts.dkimSelectors...)
		dkimProbe, err = dkim.New(dnsCli, mergedAsExtras(merged), opts.includeRaw)
		if err != nil {
			return nil, err
		}
		// dkim.New re-loaded the embedded set; rewrite Selectors with the
		// user-controlled merged list so --dkim-selectors-file actually wins.
		dkimProbe.Selectors = dedupe(merged)
	}

	return []classifier.Probe{
		spf.New(dnsCli, opts.includeRaw),
		dmarc.New(dnsCli, opts.includeRaw),
		dkimProbe,
		mx.New(dnsCli),
		mtasts.New(dnsCli, opts.includeRaw),
		tlsrpt.New(dnsCli, opts.includeRaw),
		bimi.New(dnsCli, opts.includeRaw),
		dnssec.New(dnsCli),
	}, nil
}

// mergedAsExtras is a tiny adapter: dkim.New treats its second arg as
// "extras to append on top of the embedded base". When the caller has
// already merged a custom base, we pass that as extras and overwrite
// Selectors after construction.
func mergedAsExtras(s []string) []string { return s }

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
