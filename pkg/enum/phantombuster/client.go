// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package phantombuster provides a client for the PhantomBuster agent
// execution API. It handles launching pre-configured agents, polling for
// async completion, and fetching results from S3. The client is generic —
// scraper-specific parsing (e.g. LinkedIn Sales Navigator) lives in
// separate files.
package phantombuster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

var (
	ErrUnauthorized = errors.New("invalid or missing PhantomBuster API key")
	ErrNotFound     = errors.New("agent not found")
	ErrRateLimited  = errors.New("rate limit exceeded")
	ErrAgentFailed  = errors.New("agent run failed")
)

const (
	defaultBaseURL   = "https://api.phantombuster.com"
	headerAPIKey     = "X-Phantombuster-Key-1"
	launchPath       = "/api/v2/agents/launch"
	outputPath       = "/api/v1/agent/%s/output.json"
	fetchPath        = "/api/v2/agents/fetch"
	s3BaseURL        = "https://phantombuster.s3.amazonaws.com"
	defaultPollInit  = 5 * time.Second
	defaultPollMax   = 30 * time.Second
	defaultPollMult  = 1.5
	maxResponseBytes = 10 << 20 // 10 MB for S3 result files
)

// ContainerStatus values returned by the output endpoint.
const (
	StatusRunning    = "running"
	StatusNotRunning = "not running"
)

// Client holds state for interacting with the PhantomBuster API.
type Client struct {
	apiKey     string // X-Phantombuster-Key-1 — NEVER logged (P0-1)
	httpClient *http.Client
	baseURL    string

	pollInit time.Duration
	pollMax  time.Duration
	pollMult float64
}

// NewClient builds a PhantomBuster client. timeout is the per-request HTTP budget.
func NewClient(apiKey string, timeout time.Duration) *Client {
	return &Client{
		apiKey:     apiKey,
		httpClient: enum.NewEnumHTTPClient(timeout),
		baseURL:    defaultBaseURL,
		pollInit:   defaultPollInit,
		pollMax:    defaultPollMax,
		pollMult:   defaultPollMult,
	}
}

// LaunchResult is returned by Launch.
type LaunchResult struct {
	ContainerID string `json:"containerId"`
}

// Launch starts a pre-configured agent. The agent must already exist in the
// PhantomBuster UI with its script, inputs, and LinkedIn session cookie
// configured. Returns the container ID for polling.
func (c *Client) Launch(ctx context.Context, agentID string) (*LaunchResult, error) {
	body := map[string]string{"id": agentID}
	respBody, err := c.doJSON(ctx, http.MethodPost, launchPath, body)
	if err != nil {
		return nil, err
	}

	var result LaunchResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decoding launch response: %w", err)
	}
	if result.ContainerID == "" {
		return nil, fmt.Errorf("launch returned empty containerId")
	}
	return &result, nil
}

// outputV1Response wraps the v1 output endpoint's envelope format:
// {"status":"success","data":{...actual fields...}}
type outputV1Response struct {
	Status string       `json:"status"`
	Data   OutputStatus `json:"data"`
}

// OutputStatus is the parsed polling response from the output endpoint.
type OutputStatus struct {
	ContainerStatus string `json:"containerStatus"`
	ExitCode        int    `json:"exitCode"`
	ExitMessage     string `json:"exitMessage"`
	Progress        *struct {
		Value json.Number `json:"value"`
		Label string      `json:"label"`
	} `json:"progress"`
	ResultObject json.RawMessage `json:"resultObject"`
}

// PollUntilDone polls the agent output endpoint until the container finishes
// or the context is cancelled. It uses exponential backoff between polls.
// onProgress is called (if non-nil) on each poll with the current status,
// allowing the caller to log progress updates.
func (c *Client) PollUntilDone(ctx context.Context, agentID, containerID string, onProgress func(OutputStatus)) (*OutputStatus, error) {
	path := fmt.Sprintf(outputPath, agentID)
	if containerID != "" {
		path += "?mode=track&containerId=" + containerID
	}

	delay := c.pollInit
	for {
		respBody, err := c.doJSON(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, fmt.Errorf("polling agent status: %w", err)
		}

		var status OutputStatus
		var envelope outputV1Response
		if err := json.Unmarshal(respBody, &envelope); err != nil {
			return nil, fmt.Errorf("decoding output response: %w", err)
		}
		if envelope.Data.ContainerStatus != "" {
			status = envelope.Data
		} else if err := json.Unmarshal(respBody, &status); err != nil {
			return nil, fmt.Errorf("decoding output response: %w", err)
		}

		if onProgress != nil {
			onProgress(status)
		}

		if status.ContainerStatus != StatusRunning {
			if status.ExitCode != 0 {
				return &status, fmt.Errorf("%w: %s (exit code %d)", ErrAgentFailed, status.ExitMessage, status.ExitCode)
			}
			return &status, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = time.Duration(float64(delay) * c.pollMult)
		if delay > c.pollMax {
			delay = c.pollMax
		}
	}
}

// AgentInfo is the parsed response from the fetch endpoint, containing
// S3 paths needed to download results.
type AgentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	S3Folder    string `json:"s3Folder"`
	OrgS3Folder string `json:"orgS3Folder"`
}

// FetchAgentInfo retrieves the agent's metadata including S3 folder paths.
func (c *Client) FetchAgentInfo(ctx context.Context, agentID string) (*AgentInfo, error) {
	path := fetchPath + "?id=" + agentID
	respBody, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var info AgentInfo
	if err := json.Unmarshal(respBody, &info); err != nil {
		return nil, fmt.Errorf("decoding agent info: %w", err)
	}
	return &info, nil
}

// DownloadResult fetches the result file (CSV or JSON) from the agent's
// S3 bucket. The filename is typically "result.csv" for Sales Nav scrapers.
func (c *Client) DownloadResult(ctx context.Context, info *AgentInfo, filename string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s/%s/%s", s3BaseURL, info.OrgS3Folder, info.S3Folder, filename)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building S3 download request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading result from S3: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("S3 download failed (HTTP %d)", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading S3 result: %w", err)
	}
	return data, nil
}

// RunAndFetch is a convenience that launches, polls, and fetches the result
// file in one call. It is the primary entry point for CLI usage.
func (c *Client) RunAndFetch(ctx context.Context, agentID, resultFile string, onProgress func(OutputStatus)) ([]byte, error) {
	launch, err := c.Launch(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("launching agent: %w", err)
	}

	_, err = c.PollUntilDone(ctx, agentID, launch.ContainerID, onProgress)
	if err != nil {
		return nil, err
	}

	info, err := c.FetchAgentInfo(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("fetching agent info: %w", err)
	}

	return c.DownloadResult(ctx, info, resultFile)
}

// doJSON is the single choke point for authenticated API requests. It
// JSON-encodes the body (if non-nil), sets the API key header, issues the
// request, reads the response via a bounded reader, and maps non-2xx to
// typed errors. The key is NEVER logged (P0-1).
func (c *Client) doJSON(ctx context.Context, method, path string, body any) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding request: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set(headerAPIKey, c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.classifyHTTPError(resp.StatusCode)
	}

	return respBody, nil
}

func (c *Client) classifyHTTPError(code int) error {
	switch code {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return fmt.Errorf("phantombuster API error (HTTP %d)", code)
	}
}
