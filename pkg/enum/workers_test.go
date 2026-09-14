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

package enum

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingPlugin struct {
	name  string
	calls atomic.Int32
}

func (p *countingPlugin) Name() string { return p.name }

func (p *countingPlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	p.calls.Add(1)
	return &Result{
		Service:    p.name,
		Email:      email,
		Exists:     true,
		Confidence: ConfidenceHigh,
	}
}

func TestRunTasks_CanceledContextRecordsEveryTask(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &countingPlugin{name: "cancel-oracle"}
	results, err := EnumerateWithPlugin(ctx, &Config{
		Targets: []Target{
			{Email: "one@example.com", First: "Ada", Last: "Lovelace"},
			{Email: "two@example.com", First: "Alan", Last: "Turing"},
			{Email: "three@example.com"},
		},
		Threads: 4,
		Timeout: time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 3, "every task must produce a result even when ctx is already canceled")
	assert.Equal(t, int32(0), p.calls.Load(), "Check must not run on an already-canceled context")

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	one := byEmail["one@example.com"]
	require.Error(t, one.Error)
	assert.True(t, errors.Is(one.Error, context.Canceled))
	assert.Equal(t, "Ada", one.First)
	assert.Equal(t, "Lovelace", one.Last)
	assert.Equal(t, "cancel-oracle", one.Service)

	two := byEmail["two@example.com"]
	require.Error(t, two.Error)
	assert.True(t, errors.Is(two.Error, context.Canceled))
	assert.Equal(t, "Alan", two.First)
	assert.Equal(t, "Turing", two.Last)

	three := byEmail["three@example.com"]
	require.Error(t, three.Error)
	assert.True(t, errors.Is(three.Error, context.Canceled))
	assert.Empty(t, three.First)
	assert.Empty(t, three.Last)
}

func TestRunTasks_RateLimiterErrorRecordsResult(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	p := &countingPlugin{name: "rate-oracle"}
	targets := []Target{
		{Email: "one@example.com", First: "Gwen", Last: "Alpha"},
		{Email: "two@example.com", First: "Hank", Last: "Beta"},
	}
	results, err := EnumerateWithPlugin(ctx, &Config{
		Targets:   targets,
		Threads:   2,
		Timeout:   time.Second,
		RateLimit: 0.001,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, len(targets), "limiter.Wait error must still record a result")

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		require.NotEmpty(t, r.Email, "no result may be a dropped zero value")
		byEmail[r.Email] = r
	}

	var limited *Result
	for i := range results {
		if results[i].Error != nil {
			rc := results[i]
			limited = &rc
			break
		}
	}
	require.NotNil(t, limited, "at least one task must be rejected by the rate limiter within the short deadline")

	for _, tgt := range targets {
		r := byEmail[tgt.Email]
		assert.Equal(t, tgt.First, r.First)
		assert.Equal(t, tgt.Last, r.Last)
		assert.Equal(t, "rate-oracle", r.Service)
	}
}

func TestRunTasks_JitterCancelRecordsResult(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)

	p := &countingPlugin{name: "jitter-oracle"}
	results, err := EnumerateWithPlugin(ctx, &Config{
		Targets:   []Target{{Email: "jit@example.com", First: "Iris", Last: "Gamma"}},
		Threads:   1,
		Timeout:   time.Second,
		RateLimit: 1000,
		Jitter:    2 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, int32(0), p.calls.Load(), "Check must not run when ctx is canceled during jitter")
	require.Error(t, results[0].Error)
	assert.True(t, errors.Is(results[0].Error, context.Canceled))
	assert.Equal(t, "jit@example.com", results[0].Email)
	assert.Equal(t, "Iris", results[0].First)
	assert.Equal(t, "Gamma", results[0].Last)
	assert.Equal(t, "jitter-oracle", results[0].Service)
}
