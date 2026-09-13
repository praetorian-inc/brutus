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

// TestClassifyCredentialResult pins the precedence rules for deriving a
// ResultKind from a Result produced by a credential attempt (Plugin.Test /
// TestKey): Indeterminate always wins over Success, regardless of Success's
// value, and only then does Success decide credential vs failed.
func TestClassifyCredentialResult(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   ResultKind
	}{
		{
			name:   "indeterminate with success true still yields inconclusive",
			result: Result{Indeterminate: true, Success: true},
			want:   KindInconclusive,
		},
		{
			name:   "indeterminate with success false yields inconclusive",
			result: Result{Indeterminate: true, Success: false},
			want:   KindInconclusive,
		},
		{
			name:   "success alone yields credential",
			result: Result{Indeterminate: false, Success: true},
			want:   KindCredential,
		},
		{
			name:   "neither success nor indeterminate yields failed",
			result: Result{Indeterminate: false, Success: false},
			want:   KindFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyCredentialResult(tt.result))
		})
	}
}

// TestBrute_UnauthCheckSuccess_StampsKindUnauthenticated is the regression pin
// for the live defect described in ENG-6689: workers.go returned the
// CheckUnauth result with Success=true and no way to distinguish it from a
// credential win, so Guard's adapter reported "no authentication at all" as
// weak credentials. This test drives the real Brute() entry point with a
// fake plugin whose CheckUnauth reports unauthenticated access, and asserts
// the single returned Result is stamped KindUnauthenticated and is NOT
// KindCredential. If the markUnauthenticated stamp in runWorkers is removed,
// this test must fail.
func TestBrute_UnauthCheckSuccess_StampsKindUnauthenticated(t *testing.T) {
	plug := &fakeUnauthPlugin{unauthSuccess: true}

	cfg := &Config{
		Target:    "test:9999",
		Protocol:  "fake-unauth",
		Usernames: []string{"user"},
		Passwords: []string{"pass"},
		Timeout:   1 * time.Second,
		Threads:   1,
		Plugin:    plug,
	}

	results, err := Brute(cfg)
	require.NoError(t, err)
	require.Len(t, results, 1, "an unauthenticated finding must short-circuit credential testing")

	assert.Equal(t, KindUnauthenticated, results[0].Kind)
	assert.NotEqual(t, KindCredential, results[0].Kind,
		"an unauthenticated-access finding must never be reported as a credential authentication")
}

// TestBrute_UnauthCheckFailure_ProceedsToCredentialTesting is the counterpart
// to the regression pin above: when CheckUnauth reports the service DOES
// enforce authentication (Success=false), credential testing must proceed
// normally and every resulting Result must carry a credential-path kind,
// never KindUnauthenticated.
func TestBrute_UnauthCheckFailure_ProceedsToCredentialTesting(t *testing.T) {
	plug := &fakeUnauthPlugin{unauthSuccess: false}

	// Two distinct usernames, one per password, so the worker pool's
	// existing per-user early-stop (a cracked user skips its remaining
	// passwords) cannot collapse this into a single result.
	cfg := &Config{
		Target: "test:9999",
		Credentials: []Credential{
			{Username: "userA", Password: "correct"},
			{Username: "userB", Password: "wrong"},
		},
		Protocol: "fake-unauth",
		Timeout:  1 * time.Second,
		Threads:  1,
		Plugin:   plug,
	}

	results, err := Brute(cfg)
	require.NoError(t, err)
	require.Len(t, results, 2, "credential testing must run every password when the unauth probe fails")

	for _, r := range results {
		assert.NotEqual(t, KindUnauthenticated, r.Kind,
			"a credential-path result must never be stamped KindUnauthenticated")
		if r.Password == "correct" {
			assert.Equal(t, KindCredential, r.Kind)
		} else {
			assert.Equal(t, KindFailed, r.Kind)
		}
	}
}

// TestBrute_CredentialSuccess_KindCredential pins that a credential success
// flowing through the worker pool (executeWorkerPool -> runWorkersDefault ->
// Brute) is classified KindCredential.
func TestBrute_CredentialSuccess_KindCredential(t *testing.T) {
	plug := &fakeCredentialPlugin{}

	cfg := &Config{
		Target:    "test:9999",
		Protocol:  "fake-credential",
		Usernames: []string{"user"},
		Passwords: []string{"success"},
		Timeout:   1 * time.Second,
		Threads:   1,
		Plugin:    plug,
	}

	results, err := Brute(cfg)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, KindCredential, results[0].Kind)
}

// TestBrute_CredentialFailureAndIndeterminate_Kinds pins that a credential
// failure flowing through the worker pool is classified KindFailed, and an
// indeterminate result is classified KindInconclusive.
func TestBrute_CredentialFailureAndIndeterminate_Kinds(t *testing.T) {
	plug := &fakeCredentialPlugin{}

	cfg := &Config{
		Target:    "test:9999",
		Protocol:  "fake-credential",
		Usernames: []string{"user"},
		Passwords: []string{"fail", "indeterminate"},
		Timeout:   1 * time.Second,
		Threads:   1,
		Plugin:    plug,
	}

	results, err := Brute(cfg)
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, r := range results {
		switch r.Password {
		case "fail":
			assert.Equal(t, KindFailed, r.Kind)
		case "indeterminate":
			assert.Equal(t, KindInconclusive, r.Kind)
		default:
			t.Fatalf("unexpected password in result: %q", r.Password)
		}
	}
}

// TestMarkUnauthenticated_AdditiveOnly pins that markUnauthenticated only
// ever adds the Kind stamp: Success, Banner, Username and Password must be
// byte-identical before and after the call. This is what proves the change
// cannot alter behavior for any existing consumer of this package (Guard's
// compute build imports pkg/brutus).
func TestMarkUnauthenticated_AdditiveOnly(t *testing.T) {
	r := Result{
		Protocol: "postgresql",
		Target:   "10.0.0.5:5432",
		Success:  true,
		Banner:   "unauthenticated access confirmed",
		Username: "someuser",
		Password: "somepass",
	}
	before := r

	markUnauthenticated(&r)

	assert.Equal(t, KindUnauthenticated, r.Kind)
	assert.Equal(t, before.Success, r.Success, "markUnauthenticated must not touch Success")
	assert.Equal(t, before.Banner, r.Banner, "markUnauthenticated must not touch Banner")
	assert.Equal(t, before.Username, r.Username, "markUnauthenticated must not touch Username")
	assert.Equal(t, before.Password, r.Password, "markUnauthenticated must not touch Password")
}

// TestResultKind_ZeroValueIsUnspecified pins that a Result built by a plain
// struct literal with no Kind is KindUnspecified, never KindCredential, so an
// un-migrated producer is not silently reported as a credential
// authentication.
func TestResultKind_ZeroValueIsUnspecified(t *testing.T) {
	r := Result{
		Protocol: "ssh",
		Target:   "test:22",
		Username: "root",
		Password: "password",
		Success:  true,
	}

	assert.Equal(t, KindUnspecified, r.Kind)
	assert.NotEqual(t, KindCredential, r.Kind)
}

// fakeUnauthPlugin is a test double implementing both Plugin and
// UnauthChecker, so the worker pool's `plug.(UnauthChecker)` type assertion
// in runWorkers succeeds. unauthSuccess controls what CheckUnauth reports;
// Test() reports a credential success only for the password "correct" so
// tests can distinguish credential-path outcomes by Password.
type fakeUnauthPlugin struct {
	unauthSuccess bool
}

func (p *fakeUnauthPlugin) Name() string { return "fake-unauth" }

func (p *fakeUnauthPlugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	return &Result{
		Protocol: "fake-unauth",
		Target:   target,
		Success:  p.unauthSuccess,
		Banner:   "fake unauth probe",
	}
}

func (p *fakeUnauthPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	return &Result{
		Protocol: "fake-unauth",
		Target:   target,
		Username: username,
		Password: password,
		Success:  password == "correct",
	}
}

// fakeCredentialPlugin is a test double implementing only Plugin (no
// UnauthChecker), so runWorkers's unauth pre-check is skipped entirely and
// every attempt flows through credential testing. Test() reports success,
// indeterminate, or failure based on the password value.
type fakeCredentialPlugin struct{}

func (p *fakeCredentialPlugin) Name() string { return "fake-credential" }

func (p *fakeCredentialPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	switch password {
	case "success":
		return &Result{
			Protocol: "fake-credential",
			Target:   target,
			Username: username,
			Password: password,
			Success:  true,
		}
	case "indeterminate":
		return &Result{
			Protocol:      "fake-credential",
			Target:        target,
			Username:      username,
			Password:      password,
			Indeterminate: true,
		}
	default:
		return &Result{
			Protocol: "fake-credential",
			Target:   target,
			Username: username,
			Password: password,
			Success:  false,
		}
	}
}
