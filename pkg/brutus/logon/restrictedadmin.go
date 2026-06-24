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

package logon

import (
	"context"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// RestrictedAdminResult re-exports the RDP Restricted Admin probe result so CLI
// consumers need not import the internal RDP plugin directly.
type RestrictedAdminResult = rdp.RestrictedAdminResult

// AuthCredentials re-exports RDP authenticated-session credentials.
type AuthCredentials = rdp.AuthCredentials

// Restricted Admin scan verdicts.
const (
	VerdictSupported    = rdp.VerdictSupported
	VerdictNotSupported = rdp.VerdictNotSupported
	VerdictUnknown      = rdp.VerdictUnknown
)

// ScanRestrictedAdmin probes a single target for Restricted Admin Mode support.
// The result is always non-nil; on a connection error it carries Reachable=false
// and a descriptive Detail.
func ScanRestrictedAdmin(ctx context.Context, target string, timeout time.Duration, proxyURL string) *RestrictedAdminResult {
	res, _ := rdp.ProbeRestrictedAdmin(ctx, target, timeout, proxyURL)
	return res
}

// ProtocolName renders a selected RDP security protocol for display.
func ProtocolName(proto uint32) string { return rdp.ProtocolName(proto) }

// NormalizeNTHash validates and normalizes an NT hash for pass-the-hash.
func NormalizeNTHash(raw string) (string, error) { return rdp.NormalizeNTHash(raw) }

// RestrictedAdminWebConfig configures an authenticated Restricted Admin web session.
type RestrictedAdminWebConfig struct {
	Target      string
	Timeout     time.Duration
	OpenBrowser bool
	Creds       AuthCredentials
}

// RunRestrictedAdminWeb opens an authenticated (password or pass-the-hash)
// Restricted Admin session in the built-in browser terminal. It blocks until the
// terminal server stops (Ctrl+C / context cancellation).
func RunRestrictedAdminWeb(ctx context.Context, cfg RestrictedAdminWebConfig) (brutus.Result, bool) {
	result := brutus.Result{
		Protocol: "rdp",
		Target:   cfg.Target,
		Username: cfg.Creds.Username,
	}

	err := rdp.RunWebTerminalAuthenticated(ctx, cfg.Target, cfg.Timeout, cfg.OpenBrowser, cfg.Creds)
	if err != nil && err != http.ErrServerClosed {
		result.Error = err
		return result, false
	}

	result.Success = true
	return result, true
}
