// Package adobe provides enumeration via the Adobe auth services API.
package adobe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://auth.services.adobe.com"

func init() {
	enum.Register("adobe", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Adobe account existence via auth services API.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "adobe" }

type accountsRequest struct {
	Username string `json:"username"`
}

type accountsResponse struct {
	// Non-empty Type means the account exists (e.g., "type1", "type2e", "type3")
	Type string `json:"type"`
}

// Check tests if an email account exists on Adobe.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (200 with account type)
//   - Exists=false, Error=nil: Account does not exist (404)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	body, err := json.Marshal(accountsRequest{Username: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	apiURL := p.baseURL + "/signin/v2/users/accounts"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

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
		var acctResp accountsResponse
		if err := json.NewDecoder(resp.Body).Decode(&acctResp); err != nil {
			result.Error = fmt.Errorf("decoding response: %w", err)
			result.Duration = time.Since(start)
			return result
		}
		if acctResp.Type != "" {
			result.Exists = true
			result.Confidence = enum.ConfidenceHigh
		} else {
			result.Exists = false
			result.Confidence = enum.ConfidenceLow
		}
	case http.StatusNotFound:
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	default:
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	result.Duration = time.Since(start)
	return result
}
