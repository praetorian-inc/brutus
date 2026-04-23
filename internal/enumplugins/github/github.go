// Package github provides enumeration via the GitHub users API.
package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://api.github.com"

func init() {
	enum.Register("github", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks GitHub account existence via the users API.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "github" }

// Check tests if a GitHub account exists for the local part of the email.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (200)
//   - Exists=false, Error=nil: Account does not exist (404)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	username := extractUsername(email)
	if username == "" {
		result.Error = fmt.Errorf("invalid email: cannot extract username")
		result.Duration = time.Since(start)
		return result
	}

	apiURL := p.baseURL + "/users/" + url.PathEscape(username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := enum.NewEnumHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		result.Exists = true
		result.Confidence = enum.ConfidenceMedium
	case http.StatusNotFound:
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	default:
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	result.Duration = time.Since(start)
	return result
}

// extractUsername returns the local part of an email address (before @).
func extractUsername(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) < 2 || parts[0] == "" {
		return ""
	}
	return parts[0]
}
