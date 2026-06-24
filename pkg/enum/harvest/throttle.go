// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// pkg/enum/harvest/throttle.go
package harvest

import (
	"context"
	"math/rand"
	"time"

	"golang.org/x/time/rate"
)

// Throttle paces outbound source requests. A single Throttle is shared across
// all sources so the global --rate-limit bounds total req/s across the run,
// mirroring the limiter+jitter semantics of pkg/enum/workers.go.
type Throttle struct {
	Limiter *rate.Limiter // nil = unlimited
	Jitter  time.Duration // 0 = none
}

// Wait blocks until the limiter admits one request (plus optional jitter),
// or returns ctx.Err() if the context is cancelled first. A zero-value
// Throttle (nil limiter) is a no-op.
func (t Throttle) Wait(ctx context.Context) error {
	if t.Limiter == nil {
		return nil
	}
	if err := t.Limiter.Wait(ctx); err != nil {
		return err
	}
	if t.Jitter > 0 {
		select {
		case <-time.After(time.Duration(rand.Int63n(int64(t.Jitter)))):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
