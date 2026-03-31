// Package zoom provides enumeration via the Zoom signup check API.
package zoom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultBaseURL = "https://zoom.us"

func init() {
	enum.Register("zoom", func() enum.Plugin {
		return &Plugin{baseURL: defaultBaseURL}
	})
}

// Plugin checks Zoom account existence via the signup check endpoint.
type Plugin struct {
	baseURL string
}

func (p *Plugin) Name() string { return "zoom" }

type checkResponse struct {
	Registered bool `json:"registered"`
}

// Check tests if an email account is registered on Zoom.
//
// Returns Result with:
//   - Exists=true, Error=nil: Account exists (registered=true)
//   - Exists=false, Error=nil: Account does not exist (registered=false)
//   - Exists=false, Error!=nil: Service/connection error
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	apiURL := p.baseURL + "/user/email"
	params := url.Values{}
	params.Set("email", email)
	fullURL := apiURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
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

	var checkResp checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	if checkResp.Registered {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
	} else {
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	}

	result.Duration = time.Since(start)
	return result
}
