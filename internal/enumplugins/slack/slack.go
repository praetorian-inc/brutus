// Package slack provides enumeration via the Slack auth.findUser API.
package slack

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

const defaultBaseURL = "https://slack.com"

func init() {
	enum.Register("slack", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Slack account existence via auth.findUser API.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "slack" }

type findUserResponse struct {
	OK    bool `json:"ok"`
	Found bool `json:"found"`
}

// Check tests if an email account exists on Slack.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (found=true)
//   - Exists=false, Error=nil: Account does not exist (found=false)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	apiURL := p.baseURL + "/api/auth.findUser"
	form := url.Values{}
	form.Set("email", email)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

	var findResp findUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&findResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	if findResp.Found {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
	} else {
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	}

	result.Duration = time.Since(start)
	return result
}
