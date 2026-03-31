// Package microsoft365 provides enumeration via the GetCredentialType API.
package microsoft365

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://login.microsoftonline.com"

func init() {
	enum.Register("microsoft365", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Microsoft 365 account existence via GetCredentialType API.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "microsoft365" }

type credTypeRequest struct {
	Username string `json:"Username"`
}

type credTypeResponse struct {
	IfExistsResult int `json:"IfExistsResult"`
	ThrottleStatus int `json:"ThrottleStatus"`
}

// Check tests if an email account exists on Microsoft 365.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (IfExistsResult 0, 5, or 6)
//   - Exists=false, Error=nil: Account does not exist (IfExistsResult 1)
//   - Exists=false, Error!=nil: Service/connection error or throttled
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	body, err := json.Marshal(credTypeRequest{Username: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	url := p.baseURL + "/common/GetCredentialType"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Content-Type", "application/json")

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

	var credResp credTypeResponse
	if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	if credResp.ThrottleStatus != 0 {
		result.Error = fmt.Errorf("throttled by Microsoft 365")
		result.Duration = time.Since(start)
		return result
	}

	// IfExistsResult: 0 = exists, 1 = not exists, 5 = exists (different tenant), 6 = exists (domain hint)
	switch credResp.IfExistsResult {
	case 0, 5, 6:
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
	case 1:
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	default:
		result.Confidence = enum.ConfidenceLow
	}

	result.Duration = time.Since(start)
	return result
}
