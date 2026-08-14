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

// pkg/enum/targetworker.go
package enum

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// TargetWorker is the one bounded worker pool shared by the account-existence
// enumerators in pkg/enum/*. It runs exactly one probe per Target with bounded
// concurrency, optional rate limiting and optional jitter, and returns one
// result per input Target in input order.
//
// It exists because google, microsoft365, github, gravatar and teams each grew
// their own copy of the same ~90-line pool. The copies drifted: three recorded a
// result on context cancellation and two silently dropped it, two guarded a nil
// probe result and three did not, and one of the five carried an extra field on
// its failure results that a naive shared implementation would have erased.
// Consolidating the pool here removes the drift surface; the four hook fields
// below are precisely the parts that legitimately differ per package, and
// nothing else is configurable.
//
// # Contract
//
// Run fills results[i] for EVERY i in 0..len(targets)-1 and invokes onResult
// exactly once per target — on a completed probe, on an already-canceled
// context, on a rate-limiter error, on cancellation during jitter, and on panic
// recovery. There is no path on which a slot is left as a dropped zero value.
// The returned slice is in input order; completion order is not, so callers
// (and tests) must correlate a streamed result with its input by email, never
// by arrival position.
//
// onResult is invoked while holding the same mutex that guards the results
// slice, so callbacks never interleave with each other and never race the
// slice. A callback must therefore be cheap and self-contained: it may write to
// an io.Writer or bump a counter, but it must NOT call back into the enumerator
// that owns this worker (that risks deadlock and defeats the serialization
// guarantee).
//
// # Concurrency and pacing
//
// threads <= 0 is clamped to 1. This clamp is load-bearing: errgroup.SetLimit(0)
// permits zero concurrent goroutines, so no worker could ever run and Run would
// hang forever, while a negative limit means unbounded — neither is what a
// caller passing 0 wants.
//
// rateLimit <= 0 disables the limiter. jitter is applied ONLY when a limiter is
// active; jitter with rateLimit == 0 is silently ignored. That is inherited
// behavior from all five original pools and is preserved deliberately rather
// than "fixed", because changing it would alter the pacing of every existing
// caller. See TestRun_JitterIgnoredWithoutRateLimit.
//
// # Panics
//
// A panic inside Check is recovered per goroutine. The worker writes a
// diagnostic to os.Stderr and records NewError(email, <formatted panic>) for
// that target, so one bad probe cannot take down a run. A panic raised inside
// the caller's onResult is also caught by the same recover and will produce a
// second record for that index — a pre-existing hazard in all five original
// pools, preserved here unchanged.
type TargetWorker[R any] struct {
	// Label prefixes the two panic diagnostics this worker emits:
	//
	//	os.Stderr: "<Label>: panic checking <email>: <value>\n<stack>\n"
	//	result:    "<Label>: panicked: <value>"
	//
	// It must be the package's existing diagnostic prefix with NO trailing
	// colon — "google enum", "microsoft365 enum", "github enum",
	// "gravatar enum", "teams enum" — so that the emitted text stays
	// byte-identical to what each package produced before consolidation.
	// External tooling greps these lines; changing a Label is a log-format
	// change, not a cosmetic one.
	Label string

	// Check performs exactly one probe and returns its outcome. Required.
	//
	// It must encode every failure in R's own error field and must never return
	// an error out of band. It must not populate the name fields — Run stamps
	// those via StampName, at the single point every outcome funnels through, so
	// that failure results carry a name too.
	//
	// A package whose underlying probe returns a POINTER (microsoft365's and
	// gravatar's CheckAccount) adapts it here and substitutes NewError for a nil
	// return. The nil guard lives in the package rather than in this worker
	// because its message is package-specific text ("<pkg> enum: nil result for
	// <email>") and because keeping Check value-returning avoids a pointer/value
	// duality in the generic signature.
	Check func(ctx context.Context, email string) R

	// NewError builds the result for every failure the WORKER detects rather
	// than the probe: an already-canceled context, a rate-limiter error,
	// cancellation during jitter, and panic recovery. Required.
	//
	// It is a per-package hook, not a generic zero-value construction, because
	// "zero value plus an error" is not a valid result everywhere. gravatar's
	// failure results must carry Hash: HashEmail(email) — a generic construction
	// would silently drop the hash. teams' must carry Exists: ExistenceUnknown —
	// a generic construction would leave the tri-state empty, an invalid value
	// that DerivePosture reads. Those are load-bearing, not decorative.
	//
	// A package should route its own nil-result substitute through this same
	// function (inside Check) so that every failure result the package can
	// produce has exactly one shape.
	NewError func(email string, err error) R

	// StampName copies the originating Target's name onto a result. Required.
	// Implementations are one line: func(r *R, t Target) { r.First, r.Last = t.First, t.Last }
	//
	// This is a callback rather than an interface method because Go generics
	// cannot read or write a type parameter's struct fields. An interface would
	// require a second type parameter constrained on the pointer type
	// ("[R any, P interface{ *R; NameSetter }]"), which propagates into every
	// call site's instantiation, plus a new exported mutator method on all five
	// result types — a wider public API and a mutator on a value type that
	// invites misuse — all to replace five one-line closures. The closures win
	// on both line count and blast radius.
	StampName func(res *R, t Target)
}

// Run executes one Check per target using a bounded worker pool.
//
// See the TargetWorker doc comment for the full contract: every slot is filled,
// onResult fires exactly once per target under the results mutex, the returned
// slice is in input order, threads <= 0 clamps to 1, and jitter applies only
// when rateLimit > 0.
func (w TargetWorker[R]) Run(ctx context.Context, targets []Target, threads int, rateLimit float64, jitter time.Duration, onResult func(R)) []R {
	// Fail fast and loudly on a misconfigured worker. Without this, a nil hook
	// nil-panics inside a worker goroutine, gets swallowed by the per-goroutine
	// recover, and surfaces as one confusing "panicked" result per email instead
	// of one obvious programmer error.
	if w.Check == nil || w.NewError == nil || w.StampName == nil {
		panic("enum: TargetWorker requires Check, NewError and StampName")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	// Normalize thread count: 0 would deadlock errgroup.SetLimit (no goroutine
	// can ever run) and a negative value means unbounded. Clamp to a safe
	// positive default of 1 (serial execution).
	if threads <= 0 {
		threads = 1
	}
	g.SetLimit(threads)

	var limiter *rate.Limiter
	if rateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(rateLimit), 1)
	}

	results := make([]R, len(targets))
	var mu sync.Mutex

	// record stamps the originating target's name onto the result, stores it and,
	// under the same lock, invokes the caller's callback so streamed output is
	// serialized and slice-safe.
	//
	// The stamp lives here, at the single point every outcome funnels through, so
	// that error and panic-recovery results carry their name too. Stamping at the
	// individual call sites instead is how names end up on successes but not
	// failures. targets is read-only, so the copy needs no lock.
	record := func(i int, res R) {
		w.StampName(&res, targets[i])

		mu.Lock()
		defer mu.Unlock()
		results[i] = res
		if onResult != nil {
			onResult(res)
		}
	}

	for i, t := range targets {
		email := t.Email
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "%s: panic checking %s: %v\n%s\n", w.Label, email, r, debug.Stack())
					record(i, w.NewError(email, fmt.Errorf("%s: panicked: %v", w.Label, r)))
				}
			}()

			select {
			case <-ctx.Done():
				// Record before returning so every index is filled and the callback fires exactly once per email.
				record(i, w.NewError(email, ctx.Err()))
				return nil
			default:
			}

			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					// Record before returning so every index is filled and the callback fires exactly once per email.
					record(i, w.NewError(email, err))
					return nil
				}
				if jitter > 0 {
					delay := time.Duration(rand.Int63n(int64(jitter)))
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						// Record before returning so every index is filled and the callback fires exactly once per email.
						record(i, w.NewError(email, ctx.Err()))
						return nil
					}
				}
			}

			record(i, w.Check(ctx, email))
			return nil
		})
	}

	// Discarding g.Wait()'s error is deliberate: worker goroutines never return
	// a non-nil error (per-email failures are encoded in each result), so the
	// returned error is always nil.
	_ = g.Wait()
	return results
}
