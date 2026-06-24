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

package harvest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestThrottleNilIsNoop(t *testing.T) {
	t.Parallel()
	var th Throttle // zero value: nil limiter
	require.NoError(t, th.Wait(context.Background()))
}

func TestThrottleRespectsCancel(t *testing.T) {
	t.Parallel()
	th := Throttle{Limiter: rate.NewLimiter(rate.Limit(0.001), 1)}
	// Consume the single available token so the next Wait must block.
	_ = th.Wait(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, th.Wait(ctx))
}
