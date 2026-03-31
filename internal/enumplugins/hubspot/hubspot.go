// Package hubspot provides enumeration via the HubSpot login response.
package hubspot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://app.hubspot.com"

func init() {
	enum.Register("hubspot", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks HubSpot account existence via login response differences.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "hubspot" }

type loginResponse struct {
	Status     string `json:"status"`
	LoginValid bool   `json:"loginValid"`
}

// Check tests if an email account exists on HubSpot.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (loginValid=true)
//   - Exists=false, Error=nil: Account does not exist (loginValid=false)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	form := url.Values{}
	form.Set("email", email)

	apiURL := p.baseURL + "/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		result.Duration = time.Since(start)
		return result
	}

	var loginResp loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	if loginResp.LoginValid {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
	} else {
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	}

	result.Duration = time.Since(start)
	return result
}
