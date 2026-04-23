// Package linkedin provides enumeration via the LinkedIn login check.
package linkedin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://www.linkedin.com"

func init() {
	enum.Register("linkedin", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks LinkedIn account existence via login/signup check.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "linkedin" }

type checkRequest struct {
	Email string `json:"email"`
}

type checkResponse struct {
	Exists bool `json:"exists"`
}

// Check tests if an email account is registered on LinkedIn.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (exists=true)
//   - Exists=false, Error=nil: Account does not exist (exists=false)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	body, err := json.Marshal(checkRequest{Email: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	apiURL := p.baseURL + "/uas/login-submit"
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

	raw, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	var checkResp checkResponse
	if err := json.Unmarshal(raw, &checkResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	if checkResp.Exists {
		result.Exists = true
		result.Confidence = enum.ConfidenceMedium
	} else {
		result.Exists = false
		result.Confidence = enum.ConfidenceMedium
	}

	result.Duration = time.Since(start)
	return result
}
