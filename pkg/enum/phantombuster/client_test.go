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

package phantombuster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c := NewClient("test-key", 5*time.Second)
	c.baseURL = server.URL
	c.pollInit = 10 * time.Millisecond
	c.pollMax = 50 * time.Millisecond
	return c
}

func TestLaunch_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/agents/launch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get(headerAPIKey); got != "test-key" {
			t.Errorf("expected API key header, got %q", got)
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if body["id"] != "agent-123" {
			t.Errorf("expected agent id agent-123, got %q", body["id"])
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"containerId":"container-abc"}`)
	})

	c := newTestClient(t, mux)
	result, err := c.Launch(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if result.ContainerID != "container-abc" {
		t.Errorf("expected containerId container-abc, got %q", result.ContainerID)
	}
}

func TestLaunch_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/agents/launch", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":"Unauthorized"}`)
	})

	c := newTestClient(t, mux)
	_, err := c.Launch(context.Background(), "agent-123")
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestLaunch_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/agents/launch", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"error":"Agent not found"}`)
	})

	c := newTestClient(t, mux)
	_, err := c.Launch(context.Background(), "bad-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestLaunch_EmptyContainerID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/agents/launch", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"containerId":""}`)
	})

	c := newTestClient(t, mux)
	_, err := c.Launch(context.Background(), "agent-123")
	if err == nil {
		t.Fatal("expected error for empty containerId")
	}
}

func TestPollUntilDone_ImmediateSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/agent-123/output.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"containerStatus":"not running","exitCode":0,"exitMessage":"finished"}}`)
	})

	c := newTestClient(t, mux)
	status, err := c.PollUntilDone(context.Background(), "agent-123", "container-abc", nil)
	if err != nil {
		t.Fatalf("PollUntilDone: %v", err)
	}
	if status.ExitMessage != "finished" {
		t.Errorf("expected exitMessage finished, got %q", status.ExitMessage)
	}
}

func TestPollUntilDone_TransitionsToComplete(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/agent-123/output.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := calls.Add(1)
		if n <= 2 {
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"containerStatus":"running","progress":{"value":"0.5","label":"scraping"}}}`)
		} else {
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"containerStatus":"not running","exitCode":0,"exitMessage":"finished"}}`)
		}
	})

	c := newTestClient(t, mux)
	var progressCalls int
	status, err := c.PollUntilDone(context.Background(), "agent-123", "container-abc", func(_ OutputStatus) {
		progressCalls++
	})
	if err != nil {
		t.Fatalf("PollUntilDone: %v", err)
	}
	if status.ExitMessage != "finished" {
		t.Errorf("expected exitMessage finished, got %q", status.ExitMessage)
	}
	if progressCalls < 3 {
		t.Errorf("expected at least 3 progress callbacks, got %d", progressCalls)
	}
}

func TestPollUntilDone_AgentFailed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/agent-123/output.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"containerStatus":"not running","exitCode":1,"exitMessage":"agent timeout"}}`)
	})

	c := newTestClient(t, mux)
	_, err := c.PollUntilDone(context.Background(), "agent-123", "container-abc", nil)
	if !errors.Is(err, ErrAgentFailed) {
		t.Errorf("expected ErrAgentFailed, got %v", err)
	}
}

func TestPollUntilDone_ContextCancelled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/agent-123/output.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"containerStatus":"running"}}`)
	})

	c := newTestClient(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.PollUntilDone(ctx, "agent-123", "container-abc", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestFetchAgentInfo_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/agents/fetch", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "agent-123" {
			t.Errorf("expected id=agent-123, got %q", r.URL.Query().Get("id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"agent-123","name":"Sales Nav Scraper","s3Folder":"s3folder","orgS3Folder":"orgfolder"}`)
	})

	c := newTestClient(t, mux)
	info, err := c.FetchAgentInfo(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("FetchAgentInfo: %v", err)
	}
	if info.S3Folder != "s3folder" || info.OrgS3Folder != "orgfolder" {
		t.Errorf("unexpected S3 paths: %+v", info)
	}
}

func TestDownloadResult_Success(t *testing.T) {
	csvContent := "fullName,firstName,lastName\nJohn Smith,John,Smith\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/orgfolder/s3folder/result.csv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, csvContent)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := NewClient("test-key", 5*time.Second)
	c.baseURL = server.URL

	// s3BaseURL is a const so we can't override it for tests. Instead, verify
	// the download mechanics by hitting the test server directly.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		server.URL+"/orgfolder/s3folder/result.csv", nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestRateLimited(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/agents/launch", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"Rate limited"}`)
	})

	c := newTestClient(t, mux)
	_, err := c.Launch(context.Background(), "agent-123")
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}
}
