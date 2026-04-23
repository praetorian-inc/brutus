// pkg/enum/httpclient.go
package enum

import (
	"io"
	"net/http"
	"time"
)

// defaultUserAgent is a common browser UA to avoid fingerprinting.
const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// maxResponseBody is the default body read limit (1 MB).
const maxResponseBody int64 = 1 << 20

// uaTransport wraps an http.RoundTripper to inject a default User-Agent.
type uaTransport struct {
	base http.RoundTripper
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		r2 := req.Clone(req.Context())
		r2.Header.Set("User-Agent", defaultUserAgent)
		return t.base.RoundTrip(r2)
	}
	return t.base.RoundTrip(req)
}

// NewEnumHTTPClient returns an HTTP client with safe defaults for enum plugins:
//   - No redirect following (returns last response)
//   - Default User-Agent header
//   - Specified timeout
func NewEnumHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &uaTransport{base: http.DefaultTransport},
	}
}

// ReadResponseBody reads a response body with a size limit to prevent OOM from hostile endpoints.
// If limit is 0, maxResponseBody (1 MB) is used.
func ReadResponseBody(resp *http.Response, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = maxResponseBody
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
