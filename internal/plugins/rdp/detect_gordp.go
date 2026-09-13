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
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// Detection runs at the desktop size the analysis heuristics were tuned
// against. Asking for a different size would move every region boundary the
// vision checks reason about.
const (
	detectWidth  = 1024
	detectHeight = 768
)

// runStickyKeysCheckGordp performs sticky keys detection through the native
// library.
//
// Everything after the frames are captured — the image analysis, the region
// classification, the verdict and its conservative downgrades — is the same code
// the WASM path uses. Only the transport differs, which is the point: a
// difference in verdict between the two backends is a transport bug, and there
// is nowhere else for it to hide.
func (p *Plugin) runStickyKeysCheckGordp(ctx context.Context, target, proxyURL string,
	connectTimeout, timeout time.Duration, noVision bool, budget SettleBudget, fast bool) *StickyKeysResult {

	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	sess, err := dialDetectionSession(ctx, addr, proxyURL, connectTimeout)
	if err != nil {
		return &StickyKeysResult{
			Performed:   false,
			Unreachable: isUnreachable(err),
			SkipReason:  fmt.Sprintf("connection failed: %v", err),
		}
	}
	defer func() { _ = sess.Close(ctx) }()

	result := &StickyKeysResult{Performed: true}
	var diag sessionDiag

	baseline, response, width, height, stabilized, err := p.runBackendSession(
		ctx, sess, triggerStickyKeys, timeout, budget, &diag)
	if err != nil {
		result.Performed = false
		result.SessionTerminated = diag.terminated
		result.TerminationReason = diag.reason
		result.SkipReason = fmt.Sprintf("session failed: %v", err)
		return result
	}

	if dir := os.Getenv("BRUTUS_DEBUG_SCREENSHOT_DIR"); dir != "" {
		dumpFrame(dir, addr, "sticky_keys", "baseline", baseline, width, height)
		dumpFrame(dir, addr, "sticky_keys", "response", response, width, height)
	}

	analysis := runStickyKeysAnalysis(ctx, baseline, response, width, height, visionKey(noVision))
	finalizeStickyKeysResult(result, &analysis, diag, stabilized, fast)
	return result
}

// runUtilmanCheckGordp performs utilman detection through the native library.
func (p *Plugin) runUtilmanCheckGordp(ctx context.Context, target, proxyURL string,
	connectTimeout, timeout time.Duration, noVision bool, budget SettleBudget, fast bool) *UtilmanResult {

	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	sess, err := dialDetectionSession(ctx, addr, proxyURL, connectTimeout)
	if err != nil {
		return &UtilmanResult{
			Performed:   false,
			Unreachable: isUnreachable(err),
			SkipReason:  fmt.Sprintf("connection failed: %v", err),
		}
	}
	defer func() { _ = sess.Close(ctx) }()

	result := &UtilmanResult{Performed: true}
	var diag sessionDiag

	baseline, response, width, height, stabilized, err := p.runBackendSession(
		ctx, sess, triggerUtilman, timeout, budget, &diag)
	if err != nil {
		result.Performed = false
		result.SessionTerminated = diag.terminated
		result.TerminationReason = diag.reason
		result.SkipReason = fmt.Sprintf("session failed: %v", err)
		return result
	}

	if dir := os.Getenv("BRUTUS_DEBUG_SCREENSHOT_DIR"); dir != "" {
		dumpFrame(dir, addr, "utilman", "baseline", baseline, width, height)
		dumpFrame(dir, addr, "utilman", "response", response, width, height)
	}

	analysis := runUtilmanAnalysis(ctx, baseline, response, width, height, visionKey(noVision))
	finalizeUtilmanResult(result, &analysis, diag, stabilized, fast)
	return result
}

// dialDetectionSession opens the credential-less connection both checks work
// from.
//
// These are pre-authentication checks: they reach the logon screen without a
// password, so CredSSP is skipped. A host that requires NLA cannot be checked at
// all, which ProbeNLA classifies before it gets this far.
func dialDetectionSession(ctx context.Context, addr, proxyURL string,
	connectTimeout time.Duration) (rdpSession, error) {

	dial, err := dialGordp(ctx, addr, proxyURL, rdpConfig{
		Server:   addr,
		SkipAuth: true,
	}, detectWidth, detectHeight, connectTimeout)
	if err != nil {
		return nil, err
	}
	return dial.session, nil
}

// isUnreachable reports whether the failure was the TCP connection itself, as
// opposed to anything that happened after it was established.
//
// The distinction is load-bearing: an unreachable host is a terminal state that
// is never retried, while a post-connection failure is indeterminate and should
// be rerun.
func isUnreachable(err error) bool {
	var netErr net.Error
	if errorsAs(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	return errorsAs(err, &opErr)
}

// visionKey returns the API key for optional vision confirmation, or empty when
// vision is not enabled.
func visionKey(noVision bool) string {
	if noVision {
		return ""
	}
	return os.Getenv("ANTHROPIC_API_KEY")
}
