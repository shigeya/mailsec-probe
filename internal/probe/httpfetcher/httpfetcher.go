// Package httpfetcher provides a tiny HTTPS surface shared by probes
// that need to talk to web endpoints (currently mtasts and dmarc).
//
// Keeping the surface small (Get / Head) lets tests substitute a
// deterministic stub without depending on net/http.
package httpfetcher

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

// DefaultUserAgent is the User-Agent header sent on every request when
// the caller did not override it.
const DefaultUserAgent = "mailsec-probe/0.1 (+https://github.com/shigeya/mailsec-probe)"

// Fetcher is the minimal HTTPS surface.
type Fetcher interface {
	Get(ctx context.Context, url string) (status int, body string, err error)
	Head(ctx context.Context, url string) (status int, err error)
}

// New returns a Fetcher backed by net/http with TLS 1.2+ enforced.
func New(timeout time.Duration, userAgent string) Fetcher {
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	return &fetcher{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
		ua: userAgent,
	}
}

type fetcher struct {
	client *http.Client
	ua     string
}

func (f *fetcher) Get(ctx context.Context, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

func (f *fetcher) Head(ctx context.Context, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
