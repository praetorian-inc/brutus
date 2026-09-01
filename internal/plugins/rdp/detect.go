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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// unreachableScanBanner is the terminal verdict prefix for a host whose TCP dial
// failed in the WASM scan path. It carries the literal token "unreachable" so
// JSONL/grep and human output surface it, with a leading [INFO] tag. Shared by
// both mappers to avoid drift between the two identical dial-failure sites.
const unreachableScanBanner = "[INFO] unreachable (no RDP/TCP connection to host — not scannable): "

// ---------------------------------------------------------------------------
// CLI-level detection wrappers (format results as brutus.Result)
// ---------------------------------------------------------------------------

// DetectStickyKeys performs sticky keys backdoor detection and returns a brutus.Result
// with the verdict formatted as a banner string.
//
// This function wraps RunStickyKeysCheck and interprets the StickyKeysResult into
// a standardized Result format suitable for CLI output. fast selects the short
// FastBudget settle profile and enforces the never-clean invariant.
func DetectStickyKeys(ctx context.Context, target string, connectTimeout, timeout time.Duration, username string, noVision, fast bool) *brutus.Result {
	plugin := &Plugin{}
	budget := CarefulBudget
	if fast {
		budget = FastBudget
	}
	stickyResult := plugin.RunStickyKeysCheck(ctx, target, "", connectTimeout, timeout, noVision, budget, fast)
	// Some hosts drop the pre-auth logon session a few seconds in -- sooner than the
	// careful profile's ~5s settle needs, so the post-trigger screen is never
	// observed. The short profile completes inside that window, so retry once there
	// rather than returning a scan that saw no render. Only from the careful budget:
	// a --fast scan has no shorter profile to fall back to.
	stickyResult = retryStickyKeysOnTermination(fast, stickyResult, func() *StickyKeysResult {
		return plugin.RunStickyKeysCheck(ctx, target, "", connectTimeout, timeout, noVision, FastBudget, true)
	})
	result := mapStickyResult(stickyResult, username)
	result.Target = target
	return result
}

// mapStickyResult interprets a StickyKeysResult into a standardized brutus.Result
// suitable for CLI output. It is the single source of verdict→banner mapping,
// reused by both the per-check entry point and the shared-connection path.
func mapStickyResult(stickyResult *StickyKeysResult, username string) *brutus.Result {
	result := brutus.NewResult("rdp", "", username, "")
	result.ScanType = "sticky_keys"

	if stickyResult == nil {
		result.Error = fmt.Errorf("sticky keys check returned nil")
		return result
	}

	if stickyResult.Unreachable {
		// TCP dial failed: terminal-unreachable, NOT indeterminate. Success and
		// Indeterminate stay at their zero values (false/false) so the retry loop
		// never fires (cardinal rule: unreachable != clean, unreachable != rerun).
		result.Banner = unreachableScanBanner + stickyResult.SkipReason
		return result
	}

	if !stickyResult.Performed {
		// A failed connect/instance is NOT a benign skip — it produced no
		// verdict, so surface it loudly as indeterminate (rerun), not clean. A server
		// that ended the session mid-scan gets the termination banner instead:
		// "could not connect" misdirects an operator whose connect worked fine.
		if stickyResult.SessionTerminated {
			result.Banner = indeterminateBanner("Sticky keys", true, stickyResult.TerminationReason)
		} else {
			result.Banner = fmt.Sprintf("[WARN] Sticky keys check INDETERMINATE (could not connect — rerun): %s", stickyResult.SkipReason)
		}
		result.Indeterminate = true
		return result
	}

	result.Success = false // Default to false (fail-closed)
	switch stickyResult.OverallVerdict {
	case "backdoor_confirmed":
		result.Banner = fmt.Sprintf("[CRITICAL] Sticky keys backdoor CONFIRMED (confidence: %.0f%%)", stickyResult.Confidence*100)
		result.Success = true
	case "backdoor_likely":
		result.Banner = fmt.Sprintf("[HIGH] Sticky keys backdoor likely (confidence: %.0f%%)", stickyResult.Confidence*100)
		result.Success = true
	case "vulnerable":
		result.Banner = "[INFO] Non-NLA target, sticky keys triggers normally (no backdoor)"
		result.Success = true
	case verdictIndeterminate:
		result.Banner = indeterminateBanner("Sticky keys", stickyResult.SessionTerminated, stickyResult.TerminationReason)
		result.Indeterminate = true
		// Success stays false
	case "clean":
		result.Banner = "[INFO] Sticky keys check: clean (no response to 5x Shift)"
		// Success stays false
	default:
		result.Banner = fmt.Sprintf("[INFO] Sticky keys check returned unknown verdict: %q", stickyResult.OverallVerdict)
		// Success stays false (fail-closed)
	}

	// Geometry diagnostic (never affects the verdict — confidence/banner only).
	if stickyResult.RegionNote != "" {
		result.Banner += fmt.Sprintf(" (%s)", stickyResult.RegionNote)
	}

	return result
}

// DetectUtilman performs utilman backdoor detection and returns a brutus.Result
// with the verdict formatted as a banner string.
//
// This function wraps RunUtilmanCheck and interprets the UtilmanResult into
// a standardized Result format suitable for CLI output. fast selects the short
// FastBudget settle profile and enforces the never-clean invariant.
func DetectUtilman(ctx context.Context, target string, connectTimeout, timeout time.Duration, username string, noVision, fast bool) *brutus.Result {
	plugin := &Plugin{}
	budget := CarefulBudget
	if fast {
		budget = FastBudget
	}
	utilmanResult := plugin.RunUtilmanCheck(ctx, target, "", connectTimeout, timeout, noVision, budget, fast)
	// See DetectStickyKeys: a host that drops the pre-auth session before the careful
	// settle completes is still observable on the short profile.
	utilmanResult = retryUtilmanOnTermination(fast, utilmanResult, func() *UtilmanResult {
		return plugin.RunUtilmanCheck(ctx, target, "", connectTimeout, timeout, noVision, FastBudget, true)
	})
	result := mapUtilmanResult(utilmanResult, username)
	result.Target = target
	return result
}

// mapUtilmanResult interprets a UtilmanResult into a standardized brutus.Result
// suitable for CLI output. It is the single source of verdict→banner mapping,
// reused by both the per-check entry point and the shared-connection path.
func mapUtilmanResult(utilmanResult *UtilmanResult, username string) *brutus.Result {
	result := brutus.NewResult("rdp", "", username, "")
	result.ScanType = "utilman"

	if utilmanResult == nil {
		result.Error = fmt.Errorf("utilman check returned nil")
		return result
	}

	if utilmanResult.Unreachable {
		// TCP dial failed: terminal-unreachable, NOT indeterminate. Success and
		// Indeterminate stay at their zero values (false/false) so the retry loop
		// never fires (cardinal rule: unreachable != clean, unreachable != rerun).
		result.Banner = unreachableScanBanner + utilmanResult.SkipReason
		return result
	}

	if !utilmanResult.Performed {
		// A failed connect/instance is NOT a benign skip — it produced no
		// verdict, so surface it loudly as indeterminate (rerun), not clean. A server
		// that ended the session mid-scan gets the termination banner instead:
		// "could not connect" misdirects an operator whose connect worked fine.
		if utilmanResult.SessionTerminated {
			result.Banner = indeterminateBanner("Utilman", true, utilmanResult.TerminationReason)
		} else {
			result.Banner = fmt.Sprintf("[WARN] Utilman check INDETERMINATE (could not connect — rerun): %s", utilmanResult.SkipReason)
		}
		result.Indeterminate = true
		return result
	}

	result.Success = false // Default to false (fail-closed)
	switch utilmanResult.OverallVerdict {
	case "backdoor_confirmed":
		result.Banner = fmt.Sprintf("[CRITICAL] Utilman backdoor CONFIRMED (confidence: %.0f%%)", utilmanResult.Confidence*100)
		result.Success = true
	case "backdoor_likely":
		result.Banner = fmt.Sprintf("[HIGH] Utilman backdoor likely (confidence: %.0f%%)", utilmanResult.Confidence*100)
		result.Success = true
	case "vulnerable":
		result.Banner = "[INFO] Non-NLA target, utilman triggers normally (no backdoor)"
		result.Success = true
	case verdictIndeterminate:
		result.Banner = indeterminateBanner("Utilman", utilmanResult.SessionTerminated, utilmanResult.TerminationReason)
		result.Indeterminate = true
		// Success stays false
	case "clean":
		result.Banner = "[INFO] Utilman check: clean (no response to Win+U)"
		// Success stays false
	default:
		result.Banner = fmt.Sprintf("[INFO] Utilman check returned unknown verdict: %q", utilmanResult.OverallVerdict)
		// Success stays false (fail-closed)
	}

	// Geometry diagnostic (never affects the verdict — confidence/banner only).
	if utilmanResult.RegionNote != "" {
		result.Banner += fmt.Sprintf(" (%s)", utilmanResult.RegionNote)
	}

	return result
}

// ---------------------------------------------------------------------------
// Detection entry points (connection setup + detection sequence)
// ---------------------------------------------------------------------------

// RunStickyKeysCheck performs sticky keys detection on a separate connection.
// The noVision flag disables Vision API confirmation. budget selects the settle
// profile; fast enforces the never-clean invariant.
func (p *Plugin) RunStickyKeysCheck(ctx context.Context, target, proxyURL string, connectTimeout, timeout time.Duration, noVision bool, budget SettleBudget, fast bool) *StickyKeysResult {
	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	eng, err := initEngine()
	if err != nil {
		return &StickyKeysResult{Performed: false, SkipReason: fmt.Sprintf("wasm init: %v", err)}
	}

	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, connectTimeout, proxyURL)
	if err != nil {
		return &StickyKeysResult{Performed: false, Unreachable: true, SkipReason: fmt.Sprintf("connection failed: %v", err)}
	}
	defer func() { _ = conn.Close() }()

	inst, err := newInstance(ctx, eng, conn)
	if err != nil {
		return &StickyKeysResult{Performed: false, SkipReason: fmt.Sprintf("wasm instance: %v", err)}
	}
	defer func() { _ = inst.close(ctx) }()

	stickyResult, err := p.runStickyKeysDetection(ctx, inst, addr, noVision, timeout, budget, fast)
	if err != nil {
		return &StickyKeysResult{Performed: false, SkipReason: fmt.Sprintf("detection failed: %v", err)}
	}

	return stickyResult
}

// RunUtilmanCheck performs utilman backdoor detection on a separate connection.
// budget selects the settle profile; fast enforces the never-clean invariant.
func (p *Plugin) RunUtilmanCheck(ctx context.Context, target, proxyURL string, connectTimeout, timeout time.Duration, noVision bool, budget SettleBudget, fast bool) *UtilmanResult {
	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	eng, err := initEngine()
	if err != nil {
		return &UtilmanResult{Performed: false, SkipReason: fmt.Sprintf("wasm init: %v", err)}
	}

	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, connectTimeout, proxyURL)
	if err != nil {
		return &UtilmanResult{Performed: false, Unreachable: true, SkipReason: fmt.Sprintf("connection failed: %v", err)}
	}
	defer func() { _ = conn.Close() }()

	inst, err := newInstance(ctx, eng, conn)
	if err != nil {
		return &UtilmanResult{Performed: false, SkipReason: fmt.Sprintf("wasm instance: %v", err)}
	}
	defer func() { _ = inst.close(ctx) }()

	utilmanResult, err := p.runUtilmanDetection(ctx, inst, addr, noVision, timeout, budget, fast)
	if err != nil {
		return &UtilmanResult{Performed: false, SkipReason: fmt.Sprintf("detection failed: %v", err)}
	}

	return utilmanResult
}

// ---------------------------------------------------------------------------
// Detection sequences (non-NLA connection → trigger → analyze)
// ---------------------------------------------------------------------------

// runStickyKeysDetection performs the full detection sequence on a non-NLA connection.
// timeout is the per-host budget passed to each session pump phase. budget selects
// the settle profile; fast enforces the never-clean invariant in stabilizedVerdict.
func (p *Plugin) runStickyKeysDetection(ctx context.Context, inst *wasmInstance, addr string, noVision bool, timeout time.Duration, budget SettleBudget, fast bool) (*StickyKeysResult, error) {
	result := &StickyKeysResult{Performed: true}

	cfg := rdpConfig{
		Server:   addr,
		Username: "",
		Password: "",
		Domain:   "",
		SkipAuth: true,
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	connHandle, _, err := p.runConnectorForSession(ctx, inst, configBytes)
	if err != nil {
		result.Performed = false
		result.SkipReason = fmt.Sprintf("connection failed: %v", err)
		return result, nil
	}
	// Ensure connector handle is freed after session use
	callCtx := inst.callCtx(ctx)
	defer func() {
		if freeFn := inst.mod.ExportedFunction("connector_free"); freeFn != nil {
			_, _ = freeFn.Call(callCtx, uint64(connHandle))
		}
	}()

	var diag sessionDiag
	baseline, response, width, height, stabilized, err := p.runSession(ctx, inst, connHandle, 1024, 768, timeout, budget, &diag)
	if err != nil {
		result.Performed = false
		result.SessionTerminated = diag.terminated
		result.TerminationReason = diag.reason
		result.SkipReason = fmt.Sprintf("session failed: %v", err)
		return result, nil
	}

	// DEBUG: dump captured frames to PNG when BRUTUS_DEBUG_SCREENSHOT_DIR is set.
	if dir := os.Getenv("BRUTUS_DEBUG_SCREENSHOT_DIR"); dir != "" {
		dumpFrame(dir, addr, "sticky_keys", "baseline", baseline, width, height)
		dumpFrame(dir, addr, "sticky_keys", "response", response, width, height)
	}

	// Vision API confirmation is optional: it requires ANTHROPIC_API_KEY and is
	// opted into with --experimental-ai, which the logon entry points pass down
	// as the noVision parameter.
	var visionAPIKey string
	if !noVision {
		visionAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	analysis := runStickyKeysAnalysis(ctx, baseline, response, width, height, visionAPIKey)
	finalizeStickyKeysResult(result, &analysis, diag, stabilized, fast)

	return result, nil
}

// runUtilmanDetection performs the full utilman detection sequence on a non-NLA connection.
// timeout is the per-host budget passed to each session pump phase. budget selects
// the settle profile; fast enforces the never-clean invariant in stabilizedVerdict.
func (p *Plugin) runUtilmanDetection(ctx context.Context, inst *wasmInstance, addr string, noVision bool, timeout time.Duration, budget SettleBudget, fast bool) (*UtilmanResult, error) {
	result := &UtilmanResult{Performed: true}

	cfg := rdpConfig{
		Server:   addr,
		Username: "",
		Password: "",
		Domain:   "",
		SkipAuth: true,
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	connHandle, _, err := p.runConnectorForSession(ctx, inst, configBytes)
	if err != nil {
		result.Performed = false
		result.SkipReason = fmt.Sprintf("connection failed: %v", err)
		return result, nil
	}
	// Ensure connector handle is freed after session use
	callCtx := inst.callCtx(ctx)
	defer func() {
		if freeFn := inst.mod.ExportedFunction("connector_free"); freeFn != nil {
			_, _ = freeFn.Call(callCtx, uint64(connHandle))
		}
	}()

	var diag sessionDiag
	baseline, response, width, height, stabilized, err := p.runUtilmanSession(ctx, inst, connHandle, 1024, 768, timeout, budget, &diag)
	if err != nil {
		result.Performed = false
		result.SessionTerminated = diag.terminated
		result.TerminationReason = diag.reason
		result.SkipReason = fmt.Sprintf("session failed: %v", err)
		return result, nil
	}

	// DEBUG: dump captured frames to PNG when BRUTUS_DEBUG_SCREENSHOT_DIR is set.
	if dir := os.Getenv("BRUTUS_DEBUG_SCREENSHOT_DIR"); dir != "" {
		dumpFrame(dir, addr, "utilman", "baseline", baseline, width, height)
		dumpFrame(dir, addr, "utilman", "response", response, width, height)
	}

	// Vision API confirmation is optional: it requires ANTHROPIC_API_KEY and is
	// opted into with --experimental-ai, which the logon entry points pass down
	// as the noVision parameter.
	var visionAPIKey string
	if !noVision {
		visionAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	analysis := runUtilmanAnalysis(ctx, baseline, response, width, height, visionAPIKey)
	finalizeUtilmanResult(result, &analysis, diag, stabilized, fast)

	return result, nil
}

// stabilizedVerdict downgrades a clean verdict to indeterminate when the render
// never stabilized, OR when fast mode is active (never-clean invariant: a fast
// triage pass may report HIGH/CRITICAL or indeterminate, never a confident clean).
// All other verdicts (positives, vulnerable) pass through unchanged.
func stabilizedVerdict(verdict string, stabilized, fast bool) string {
	if verdict == "clean" && (!stabilized || fast) {
		return verdictIndeterminate
	}
	return verdict
}

// dumpFrame is an env-var-gated DEBUG aid: when dir is non-empty it saves the
// captured framebuffer as a PNG named <sanitizedTarget>_<scanType>_<phase>.png.
// All errors are non-fatal (logged to stderr) so detection is never broken by a
// failed dump. When dir is empty this is a no-op.
//
// target reaches here straight from the scan list. ParseTarget splits it with
// net.SplitHostPort, which validates the shape of a host but not its contents, so a
// targets-file line like "../../../../tmp/pwned:3389" arrives intact. Replacing only
// ':' left that as a relative path, and filepath.Join resolves ".." rather than
// refusing it -- so a scan of an attacker-supplied list wrote a PNG wherever the list
// pointed, as long as BRUTUS_DEBUG_SCREENSHOT_DIR was set.
func dumpFrame(dir, target, scanType, phase string, rgba []byte, w, h uint32) {
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[!] DEBUG screenshot dir %q: %v\n", dir, err)
		return
	}

	path := filepath.Join(dir, fmt.Sprintf("%s_%s_%s.png", safeFilenameComponent(target), scanType, phase))

	// Defense in depth: safeFilenameComponent removes every separator, so this cannot
	// trip today. It stays because a later change to how the name is built would
	// otherwise reintroduce a silent write outside dir.
	if filepath.Dir(path) != filepath.Clean(dir) {
		fmt.Fprintf(os.Stderr, "[!] DEBUG screenshot: refusing to write %q outside %q\n", path, dir)
		return
	}

	if err := saveRGBAScreenshot(rgba, w, h, path); err != nil {
		fmt.Fprintf(os.Stderr, "[!] DEBUG screenshot %q: %v\n", path, err)
	}
}

// safeFilenameComponent reduces s to a single path component that cannot escape a
// directory: every rune outside [A-Za-z0-9.-] becomes '_', which removes the path
// separators and the colon, and a surviving ".." is inert without one.
//
// It sanitizes rather than hashing because this is a debug aid whose whole value is
// being able to tell which capture belongs to which target -- "10.0.0.5_3389" stays
// readable, where a digest would not.
func safeFilenameComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Banner formatting (append detection results to auth banner)
// ---------------------------------------------------------------------------

// finalizeStickyKeysResult folds an analysis outcome into result while KEEPING the session
// diagnostics the analysis knows nothing about.
//
// It exists because `*result = analysis` is a whole-struct assignment: runStickyKeysAnalysis returns a
// FRESH StickyKeysResult, so every field set on result beforehand is discarded. That ordering trap
// silently zeroed SessionTerminated/TerminationReason once already, disabling the
// short-profile retry and the termination banner for the response-phase teardown this
// path was written to handle -- and it did so invisibly, because the scan still
// succeeded. Keeping the order in one small function is what makes the invariant
// test-enforceable instead of a comment someone has to notice.
//
// The stabilizedVerdict call is the cardinal false-negative guard: only a "clean"
// verdict on a render that never stabilized is suspect (or any clean in fast mode --
// never-clean invariant). Positive verdicts already saw the window and are never
// downgraded.
func finalizeStickyKeysResult(result, analysis *StickyKeysResult, diag sessionDiag, stabilized, fast bool) {
	*result = *analysis
	result.Performed = true
	result.Stabilized = stabilized
	result.SessionTerminated = diag.terminated
	result.TerminationReason = diag.reason
	result.OverallVerdict = stabilizedVerdict(result.OverallVerdict, stabilized, fast)
}

// finalizeUtilmanResult folds an analysis outcome into result while KEEPING the session
// diagnostics the analysis knows nothing about.
//
// It exists because `*result = analysis` is a whole-struct assignment: runUtilmanAnalysis returns a
// FRESH UtilmanResult, so every field set on result beforehand is discarded. That ordering trap
// silently zeroed SessionTerminated/TerminationReason once already, disabling the
// short-profile retry and the termination banner for the response-phase teardown this
// path was written to handle -- and it did so invisibly, because the scan still
// succeeded. Keeping the order in one small function is what makes the invariant
// test-enforceable instead of a comment someone has to notice.
//
// The stabilizedVerdict call is the cardinal false-negative guard: only a "clean"
// verdict on a render that never stabilized is suspect (or any clean in fast mode --
// never-clean invariant). Positive verdicts already saw the window and are never
// downgraded.
func finalizeUtilmanResult(result, analysis *UtilmanResult, diag sessionDiag, stabilized, fast bool) {
	*result = *analysis
	result.Performed = true
	result.Stabilized = stabilized
	result.SessionTerminated = diag.terminated
	result.TerminationReason = diag.reason
	result.OverallVerdict = stabilizedVerdict(result.OverallVerdict, stabilized, fast)
}

// retryStickyKeysOnTermination decides whether a terminated scan is re-run on the short
// settle profile, and runs it. The decision is split from the RunStickyKeysCheck call
// so it is reachable from a test: the wiring is the part that silently broke once
// (see finalizeStickyKeysResult), and a predicate nobody calls correctly is no guard
// at all. rerun is invoked at most once.
func retryStickyKeysOnTermination(fast bool, first *StickyKeysResult, rerun func() *StickyKeysResult) *StickyKeysResult {
	if fast || first == nil || !first.SessionTerminated {
		return first
	}
	if !retryAfterTermination(first.OverallVerdict, first.Performed) {
		return first
	}
	return rerun()
}

// retryUtilmanOnTermination decides whether a terminated scan is re-run on the short
// settle profile, and runs it. The decision is split from the RunStickyKeysCheck call
// so it is reachable from a test: the wiring is the part that silently broke once
// (see finalizeStickyKeysResult), and a predicate nobody calls correctly is no guard
// at all. rerun is invoked at most once.
func retryUtilmanOnTermination(fast bool, first *UtilmanResult, rerun func() *UtilmanResult) *UtilmanResult {
	if fast || first == nil || !first.SessionTerminated {
		return first
	}
	if !retryAfterTermination(first.OverallVerdict, first.Performed) {
		return first
	}
	return rerun()
}

// retryAfterTermination reports whether a session-terminated result is worth re-running
// on the short settle profile. A result that already REPORTS an observation --
// confirmed, likely, or the non-NLA "vulnerable" reading -- is NEVER retried: the retry
// can come back indeterminate and would replace a real observation with nothing, the
// false negative the cardinal rule forbids. This is reachable because responseFrame
// analyzes the last frame seen while the session was alive, so a payload that painted
// and only then dropped the session scores a genuine positive alongside terminated=true.
// Everything else -- indeterminate, clean, or a scan that never performed -- saw no
// trustworthy post-trigger render, so a retry can only improve it.
func retryAfterTermination(verdict string, performed bool) bool {
	if !performed {
		return true
	}
	switch verdict {
	case "backdoor_confirmed", "backdoor_likely", "vulnerable":
		return false
	default:
		return true
	}
}

// indeterminateBanner renders the INDETERMINATE banner for a check that produced no
// trustworthy render. When the server ended the session mid-scan it says so and
// names the server's own reason, because "render did not stabilize" sends the
// operator to rerun an identical scan that will fail identically -- the actionable
// step is the short settle profile, which completes inside the window such a host
// allows before it drops the pre-auth session.
func indeterminateBanner(check string, sessionTerminated bool, reason string) string {
	if !sessionTerminated {
		return fmt.Sprintf("[WARN] %s check INDETERMINATE (render did not stabilize — rerun)", check)
	}
	if reason == "" {
		return fmt.Sprintf("[WARN] %s check INDETERMINATE (server ended the session mid-scan — retry with --fast)", check)
	}
	return fmt.Sprintf("[WARN] %s check INDETERMINATE (server ended the session mid-scan: %s — retry with --fast)", check, reason)
}
