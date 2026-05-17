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
	"github.com/shigeya/mailsec-probe/internal/probe/mtatls"
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
	outputFmt      string
	color          string
	dnsServer      string
	dkimSelectors  []string
	dkimSelFile    string
	noSPFInference bool
	noRUACheck     bool
	active         bool
	smtpPort       int
	smtpTimeout    time.Duration
	ehloName       string
	inputFile      string
	stats          bool
	timeout        time.Duration
	concurrency    int
	includeRaw     bool
	verbose        int
}

func newRoot() *cobra.Command {
	opts := &rootOpts{
		outputFmt:   "human",
		color:       "auto",
		timeout:     10 * time.Second,
		concurrency: 8,
		smtpPort:    25,
		smtpTimeout: 10 * time.Second,
		ehloName:    "mailsec-probe.local",
	}

	cmd := &cobra.Command{
		Use:           "mailsec-probe <domain> [domain...]",
		Short:         "Observe mail-security DNS records (SPF/DMARC/DKIM/MX/MTA-STS/TLS-RPT/BIMI/DNSSEC)",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs, // accept zero args when --input is given
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogger(opts.verbose)
			return run(cmd.Context(), opts, args)
		},
	}

	pf := cmd.PersistentFlags()
	pf.StringVarP(&opts.outputFmt, "output", "o", opts.outputFmt, "output format: human|json|tsv")
	pf.StringVar(&opts.color, "color", opts.color, "colour mode for human output: auto|always|never")
	pf.StringVar(&opts.dnsServer, "dns-server", "", "DNS server to query (host or host:port). Default: system resolver")
	pf.StringSliceVar(&opts.dkimSelectors, "dkim-selector", nil, "additional DKIM selector to probe (repeatable)")
	pf.StringVar(&opts.dkimSelFile, "dkim-selectors-file", "", "override the embedded DKIM selector list with this YAML file")
	pf.BoolVar(&opts.noSPFInference, "no-spf-inference", false, "disable SPF-driven DKIM selector inference")
	pf.BoolVar(&opts.noRUACheck, "no-rua-check", false, "disable DMARC rua= HTTPS reachability HEAD checks")
	pf.BoolVar(&opts.active, "active", false, "enable active SMTP probes (STARTTLS + DANE). Connects to each MX on TCP 25")
	pf.IntVar(&opts.smtpPort, "smtp-port", opts.smtpPort, "SMTP port for --active probes")
	pf.DurationVar(&opts.smtpTimeout, "smtp-timeout", opts.smtpTimeout, "per-MX SMTP probe timeout")
	pf.StringVar(&opts.ehloName, "ehlo-name", opts.ehloName, "name used in our EHLO greeting during --active probes")
	pf.StringVar(&opts.inputFile, "input", "", "read additional domains from this file (one per line, # comments). Use \"-\" for stdin")
	pf.BoolVar(&opts.stats, "stats", false, "append a cross-domain statistics block to the output")
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

func run(ctx context.Context, opts *rootOpts, args []string) error {
	fileDomains, err := readDomainsFile(opts.inputFile)
	if err != nil {
		return err
	}
	domains := mergeDomains(args, fileDomains)
	if len(domains) == 0 {
		return fmt.Errorf("no domains supplied (pass as args or via --input)")
	}

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
		if err := output.WriteJSON(os.Stdout, reports, opts.stats); err != nil {
			return err
		}
	case "tsv":
		if err := output.WriteTSV(os.Stdout, reports); err != nil {
			return err
		}
		if opts.stats {
			if err := output.WriteStatsTSV(os.Stdout, reports); err != nil {
				return err
			}
		}
	case "human", "":
		colorizer := output.NewColorizer(output.ColorMode(opts.color), os.Stdout)
		if err := output.WriteHumanColored(os.Stdout, reports, colorizer); err != nil {
			return err
		}
		if opts.stats {
			if err := output.WriteStatsHumanColored(os.Stdout, reports, colorizer); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown output format %q (want human|json|tsv)", opts.outputFmt)
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
		if opts.noSPFInference {
			dkimProbe.EnableInference = false
		}
	}

	dmarcProbe := dmarc.New(dnsCli, opts.includeRaw)
	if opts.noRUACheck {
		dmarcProbe.EnableRUACheck = false
	}

	probes := []classifier.Probe{
		spf.New(dnsCli, opts.includeRaw),
		dmarcProbe,
		dkimProbe,
		mx.New(dnsCli),
		mtasts.New(dnsCli, opts.includeRaw),
		tlsrpt.New(dnsCli, opts.includeRaw),
		bimi.New(dnsCli, opts.includeRaw),
		dnssec.New(dnsCli),
	}

	if opts.active {
		mtatlsProbe := mtatls.New(dnsCli)
		mtatlsProbe.Port = opts.smtpPort
		mtatlsProbe.OurName = opts.ehloName
		mtatlsProbe.Dialer = mtatls.NewDialer(opts.smtpTimeout)
		probes = append(probes, mtatlsProbe)
	}

	return probes, nil
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
