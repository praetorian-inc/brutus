// Package atlassian provides enumeration via the Atlassian check-username API.
package atlassian

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://id.atlassian.com"

func init() {
	enum.Register("atlassian", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Atlassian account existence via check-username API.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "atlassian" }

type checkRequest struct {
	Username string `json:"username"`
}

type checkResponse struct {
	Action string `json:"action"` // "login" = exists, "signup" = not exists
}

// Check tests if an email account exists on Atlassian.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (action="login")
//   - Exists=false, Error=nil: Account does not exist (action="signup")
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	body, err := json.Marshal(checkRequest{Username: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	url := p.baseURL + "/rest/check-username"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Content-Type", "application/json")

	client := enum.NewEnumHTTPClient(timeout)
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

	var checkResp checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	switch checkResp.Action {
	case "login":
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
	case "signup":
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	default:
		result.Confidence = enum.ConfidenceLow
	}

	result.Duration = time.Since(start)
	return result
}
