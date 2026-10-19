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

package winrm

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/masterzen/winrm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyAccessError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want AccessKind
	}{
		{name: "nil", err: nil, want: AccessAllowed},
		{name: "401", err: errors.New("http error 401: Unauthorized"), want: AccessBadCredentials},
		{name: "401 alt", err: errors.New("http response error: 401"), want: AccessBadCredentials},
		{
			name: "SOAP AccessDenied",
			err:  &winrm.ExecuteCommandError{Inner: errors.New("received error response"), Body: "<Fault>AccessDenied</Fault>"},
			want: AccessDenied,
		},
		{name: "refused", err: errors.New("dial tcp: connection refused"), want: AccessUnreachable},
		{name: "timeout", err: context.DeadlineExceeded, want: AccessUnreachable},
		{name: "canceled", err: context.Canceled, want: AccessUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := classifyAccessError(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAbortsSpray(t *testing.T) {
	assert.True(t, AccessBadCredentials.AbortsSpray())
	assert.False(t, AccessAllowed.AbortsSpray())
	assert.False(t, AccessDenied.AbortsSpray())
	assert.False(t, AccessUnreachable.AbortsSpray())
}

func TestSprayNoHosts(t *testing.T) {
	_, err := Spray(context.Background(), SprayConfig{Username: "bob"})
	require.Error(t, err)
}

func TestSprayUnreachableDoesNotAbort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	reports, err := Spray(ctx, SprayConfig{
		Hosts:    []string{"127.0.0.1:1", "127.0.0.1:2"},
		Username: "bob",
		Password: "x",
		Timeout:  400 * time.Millisecond,
		Workers:  2,
	})
	require.NoError(t, err, "unreachable hosts must not abort")
	require.Len(t, reports, 2)
	for _, r := range reports {
		assert.Equal(t, AccessUnreachable, r.Kind, fmt.Sprintf("%s: %s", r.Host, r.Detail))
	}
}
