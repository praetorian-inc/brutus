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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckUnauthAccess_UnknownProtocol(t *testing.T) {
	t.Parallel()
	r := CheckUnauthAccess(context.Background(), "127.0.0.1:1", "no-such-protocol", time.Second, PluginConfig{})
	assert.Nil(t, r, "unknown protocol must not invent an unauth finding")
}

func TestCheckUnauthAccess_PluginWithoutUnauthChecker(t *testing.T) {
	t.Parallel()
	name := "cred-only-" + t.Name()
	Register(name, func() Plugin { return &fakeCredentialPlugin{} })

	r := CheckUnauthAccess(context.Background(), "127.0.0.1:1", name, time.Second, PluginConfig{})
	assert.Nil(t, r, "a credential-only plugin must not be probed for unauth access")
}

func TestCheckUnauthAccess_SuccessStampsKind(t *testing.T) {
	t.Parallel()
	name := "unauth-ok-" + t.Name()
	Register(name, func() Plugin { return &fakeUnauthPlugin{unauthSuccess: true} })

	r := CheckUnauthAccess(context.Background(), "test:9", name, time.Second, PluginConfig{})
	require.NotNil(t, r)
	assert.True(t, r.Success)
	assert.Equal(t, KindUnauthenticated, r.Kind)
	assert.NotEqual(t, KindCredential, r.Kind)
}

func TestCheckUnauthAccess_FailureDoesNotStampKind(t *testing.T) {
	t.Parallel()
	name := "unauth-fail-" + t.Name()
	Register(name, func() Plugin { return &fakeUnauthPlugin{unauthSuccess: false} })

	r := CheckUnauthAccess(context.Background(), "test:9", name, time.Second, PluginConfig{})
	require.NotNil(t, r)
	assert.False(t, r.Success)
	assert.Equal(t, KindUnspecified, r.Kind, "a failed unauth probe must not be labeled unauthenticated access")
}

func TestCheckUnauthAccess_UnauthOnlyRegistry(t *testing.T) {
	t.Parallel()
	name := "unauth-only-" + t.Name()
	RegisterUnauthChecker(name, func() UnauthOnlyChecker {
		return &fakeUnauthOnly{success: true}
	})

	r := CheckUnauthAccess(context.Background(), "test:9", name, time.Second, PluginConfig{})
	require.NotNil(t, r)
	assert.True(t, r.Success)
	assert.Equal(t, KindUnauthenticated, r.Kind)
}

type fakeUnauthOnly struct {
	success bool
}

func (f *fakeUnauthOnly) Name() string { return "fake-unauth-only" }

func (f *fakeUnauthOnly) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	return &Result{
		Protocol: "fake-unauth-only",
		Target:   target,
		Success:  f.success,
		Banner:   "fake unauth-only probe",
	}
}
