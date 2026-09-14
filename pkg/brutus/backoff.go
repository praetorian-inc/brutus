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

package brutus

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"sync/atomic"
	"time"
)

// backoffController manages per-credential retry backoff and adaptive pacing.
// It tracks consecutive connection errors across all workers. When errors exceed
// a threshold, it signals all workers to add delays before their next attempt,
// effectively reducing throughput without changing thread count.
type backoffController struct {
	consecutiveErrors atomic.Int64
	baseDelay         time.Duration
	maxDelay          time.Duration
	threshold         int64 // consecutive errors before adaptive pacing kicks in
	verbose           bool
}

func newBackoffController(base, maxDelay time.Duration, verbose bool) *backoffController {
	return &backoffController{
		baseDelay: base,
		maxDelay:  maxDelay,
		threshold: 3,
		verbose:   verbose,
	}
}

// recordError increments the consecutive error counter.
func (b *backoffController) recordError() {
	count := b.consecutiveErrors.Add(1)
	if count == b.threshold && b.verbose {
		fmt.Fprintf(os.Stderr, "[adaptive] Connection errors detected, enabling backoff\n")
	}
}

// recordSuccess resets the consecutive error counter.
func (b *backoffController) recordSuccess() {
	prev := b.consecutiveErrors.Swap(0)
	if prev >= b.threshold && b.verbose {
		fmt.Fprintf(os.Stderr, "[adaptive] Connection recovered, disabling backoff\n")
	}
}

// adaptiveDelay returns a delay for adaptive pacing based on consecutive error count.
// Returns 0 if below threshold.
func (b *backoffController) adaptiveDelay() time.Duration {
	errors := b.consecutiveErrors.Load()
	if errors < b.threshold {
		return 0
	}
	return b.jitteredDelay(int(errors - b.threshold))
}

// retryDelay returns a delay for per-credential retry based on attempt number.
func (b *backoffController) retryDelay(attempt int) time.Duration {
	return b.jitteredDelay(attempt)
}

// jitteredDelay computes exponential backoff with full jitter.
// Formula: random(0, min(maxDelay, baseDelay * 2^level))
func (b *backoffController) jitteredDelay(level int) time.Duration {
	expDelay := float64(b.baseDelay) * math.Pow(2, float64(level))
	capped := math.Min(expDelay, float64(b.maxDelay))
	if capped <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(capped)))
}
