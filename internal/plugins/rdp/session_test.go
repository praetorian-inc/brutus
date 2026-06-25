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

package rdp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestCarefulBudgetMatchesLegacy locks CarefulBudget to the exact pre-budget
// hardcoded settle consts. If any field drifts, careful-mode behavior changed.
// This is the characterization test from Task 1 of the fast-mode plan.
//
// RED until the developer adds the SettleBudget struct + CarefulBudget preset
// to session.go, replacing the const block at lines 84-101.
func TestCarefulBudgetMatchesLegacy(t *testing.T) {
	assert.Equal(t, 1500*time.Millisecond, CarefulBudget.quietWindow)
	assert.Equal(t, 2*time.Second, CarefulBudget.minPump)
	assert.Equal(t, 2000, CarefulBudget.noisePixels)
	assert.Equal(t, 500*time.Millisecond, CarefulBudget.readDeadline)
	assert.Equal(t, 1500*time.Millisecond, CarefulBudget.postKeystrokeWait)
}

// TestFastBudgetValues locks FastBudget to the exact values specified in the
// design decisions (D4) of the fast-mode plan.
//
// RED until the developer adds the FastBudget preset to session.go.
func TestFastBudgetValues(t *testing.T) {
	assert.Equal(t, 400*time.Millisecond, FastBudget.quietWindow)
	assert.Equal(t, 600*time.Millisecond, FastBudget.minPump)
	assert.Equal(t, 3000, FastBudget.noisePixels)
	assert.Equal(t, 250*time.Millisecond, FastBudget.readDeadline)
	assert.Equal(t, 700*time.Millisecond, FastBudget.postKeystrokeWait)
}

// TestSettledFastBudget verifies the fast profile settles earlier than careful.
// At the fast floor (minPump+quietWindow = 1000ms), careful (floor = 3500ms)
// must still not be settled.
//
// RED until the developer adds SettleBudget + updates settled() to accept a
// budget parameter.
func TestSettledFastBudget(t *testing.T) {
	start := time.Time{}
	// Quiet since start; now just past FastBudget's floor (minPump+quietWindow=1000ms)
	now := start.Add(FastBudget.minPump + FastBudget.quietWindow + 10*time.Millisecond)
	assert.True(t, settled(start, start, now, FastBudget), "fast budget settles at its own floor")
	assert.False(t, settled(start, start, now, CarefulBudget), "careful budget not yet settled at the fast floor")
}

// TestFramesQuietFastBudget verifies the higher fast noise tolerance (3000 px)
// vs careful (2000 px). A frame with 2500 changed pixels should count as quiet
// under FastBudget but not under CarefulBudget.
//
// RED until the developer updates framesQuiet() to accept a budget parameter.
func TestFramesQuietFastBudget(t *testing.T) {
	const w, h = uint32(200), uint32(200)
	prev := makeFrame(w, h, 100)
	cur := makeFrame(w, h, 100)
	flipPixels(cur, 2500, changeThreshold+20) // 2500 px changed: between careful(2000) and fast(3000)
	assert.False(t, framesQuiet(prev, cur, w, h, CarefulBudget), "2500 changed px exceeds careful 2000 budget")
	assert.True(t, framesQuiet(prev, cur, w, h, FastBudget), "2500 changed px is within fast 3000 budget")
}
