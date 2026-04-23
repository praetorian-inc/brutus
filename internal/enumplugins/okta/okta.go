// Package okta provides enumeration via the Okta authn API.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://login.okta.com"

func init() {
	enum.Register("okta", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Okta account existence via authn API.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "okta" }

type authnRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authnErrorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorSummary string `json:"errorSummary"`
}

// Check tests if an email account exists on Okta.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (401 with E0000004)
//   - Exists=false, Error=nil: Account does not exist (404)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	body, err := json.Marshal(authnRequest{
		Username: email,
		Password: "InvalidPassword123!",
	})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	url := p.resolveURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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

	// 401 with auth failure error = account exists (wrong password rejected)
	if resp.StatusCode == http.StatusUnauthorized {
		raw, readErr := enum.ReadResponseBody(resp, 0)
		if readErr == nil {
			var errResp authnErrorResponse
			if err := json.Unmarshal(raw, &errResp); err == nil {
				if errResp.ErrorCode == "E0000004" {
					result.Exists = true
					result.Confidence = enum.ConfidenceMedium
					result.Duration = time.Since(start)
					return result
				}
			}
		}
	}

	// 200 = account exists (successful auth unlikely but possible)
	if resp.StatusCode == http.StatusOK {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
		result.Duration = time.Since(start)
		return result
	}

	// 404 = not found
	if resp.StatusCode == http.StatusNotFound {
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
		result.Duration = time.Since(start)
		return result
	}

	// Other status codes = error
	result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
	result.Duration = time.Since(start)
	return result
}

func (p *Plugin) resolveURL() string {
	if p.baseURL != "" {
		return p.baseURL + "/api/v1/authn"
	}
	return defaultBaseURL + "/api/v1/authn"
}
