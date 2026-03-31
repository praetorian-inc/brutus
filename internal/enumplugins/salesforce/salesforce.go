// Package salesforce provides enumeration via the Salesforce login response.
package salesforce

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://login.salesforce.com"

func init() {
	enum.Register("salesforce", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Salesforce account existence via login response differences.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "salesforce" }

// Check tests if an email account exists on Salesforce.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (login page shows password prompt)
//   - Exists=false, Error=nil: Account does not exist (login page shows user not found)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	form := url.Values{}
	form.Set("un", email)
	form.Set("pw", "InvalidPassword123!")

	apiURL := p.baseURL + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	bodyStr := string(body)

	// Salesforce returns different error messages for valid vs invalid users.
	// "Please check your username and password" = valid user, wrong password
	// "no account" or specific not-found indicators = user doesn't exist
	switch {
	case strings.Contains(bodyStr, "Please check your username and password"):
		result.Exists = true
		result.Confidence = enum.ConfidenceMedium
	case strings.Contains(bodyStr, "Username not found"),
		strings.Contains(bodyStr, "no account"):
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		result.Exists = false
		result.Confidence = enum.ConfidenceLow
	case resp.StatusCode >= 500:
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
	default:
		result.Confidence = enum.ConfidenceLow
	}

	result.Duration = time.Since(start)
	return result
}
