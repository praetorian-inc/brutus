// Package dropbox provides enumeration via the Dropbox login response.
package dropbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://www.dropbox.com"

func init() {
	enum.Register("dropbox", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Dropbox account existence via login endpoint.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "dropbox" }

type loginRequest struct {
	Email string `json:"email"`
}

type loginResponse struct {
	HasAccount bool   `json:"has_account"`
	Status     string `json:"status"`
}

// Check tests if an email account is registered on Dropbox.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (has_account=true)
//   - Exists=false, Error=nil: Account does not exist (has_account=false)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	body, err := json.Marshal(loginRequest{Email: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	apiURL := p.baseURL + "/login"
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

	if loginResp.HasAccount {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
	} else {
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	}

	result.Duration = time.Since(start)
	return result
}
