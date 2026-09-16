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

package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOraclePacing(t *testing.T) {
	origRate := flagRateLimit
	origJitter := flagJitter
	t.Cleanup(func() {
		flagRateLimit = origRate
		flagJitter = origJitter
	})

	t.Run("zero flags get conservative defaults", func(t *testing.T) {
		flagRateLimit = 0
		flagJitter = 0

		rateLimit, jitter := oraclePacing()

		assert.Equal(t, defaultOracleRateLimit, rateLimit)
		assert.Equal(t, defaultOracleJitter, jitter)
		assert.Greater(t, rateLimit, 0.0)
		assert.Greater(t, jitter, time.Duration(0))
	})

	t.Run("explicit values are preserved", func(t *testing.T) {
		flagRateLimit = 5.5
		flagJitter = 250 * time.Millisecond

		rateLimit, jitter := oraclePacing()

		assert.Equal(t, 5.5, rateLimit)
		assert.Equal(t, 250*time.Millisecond, jitter)
	})

	t.Run("zero jitter is filled when rate limit is set", func(t *testing.T) {
		flagRateLimit = 3
		flagJitter = 0

		rateLimit, jitter := oraclePacing()

		assert.Equal(t, 3.0, rateLimit)
		assert.Equal(t, defaultOracleJitter, jitter)
	})
}
