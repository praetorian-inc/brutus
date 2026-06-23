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
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// ---------------------------------------------------------------------------
// CLI-level detection wrappers (format results as brutus.Result)
// ---------------------------------------------------------------------------

// DetectStickyKeys performs sticky keys backdoor detection and returns a brutus.Result
// with the verdict formatted as a banner string.
//
// This function wraps RunStickyKeysCheck and interprets the StickyKeysResult into
// a standardized Result format suitable for CLI output.
func DetectStickyKeys(ctx context.Context, target string, timeout time.Duration, username string, noVision bool) *brutus.Result {
	plugin := &Plugin{}
	stickyResult := plugin.RunStickyKeysCheck(ctx, target, timeout, noVision)
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

	if !stickyResult.Performed {
		// A failed connect/instance is NOT a benign skip — it produced no
		// verdict, so surface it loudly as indeterminate (rerun), not clean.
		result.Banner = fmt.Sprintf("[WARN] Sticky keys check INDETERMINATE (could not connect — rerun): %s", stickyResult.SkipReason)
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
		result.Banner = "[WARN] Sticky keys check INDETERMINATE (render did not stabilize — rerun)"
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
// a standardized Result format suitable for CLI output.
func DetectUtilman(ctx context.Context, target string, timeout time.Duration, username string, noVision bool) *brutus.Result {
	plugin := &Plugin{}
	utilmanResult := plugin.RunUtilmanCheck(ctx, target, timeout, noVision)
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

	if !utilmanResult.Performed {
		// A failed connect/instance is NOT a benign skip — it produced no
		// verdict, so surface it loudly as indeterminate (rerun), not clean.
		result.Banner = fmt.Sprintf("[WARN] Utilman check INDETERMINATE (could not connect — rerun): %s", utilmanResult.SkipReason)
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
		result.Banner = "[WARN] Utilman check INDETERMINATE (render did not stabilize — rerun)"
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
// The noVision flag disables Vision API confirmation.
func (p *Plugin) RunStickyKeysCheck(ctx context.Context, target string, timeout time.Duration, noVision bool) *StickyKeysResult {
	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	eng, err := initEngine()
	if err != nil {
		return &StickyKeysResult{Performed: false, SkipReason: fmt.Sprintf("wasm init: %v", err)}
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &StickyKeysResult{Performed: false, SkipReason: fmt.Sprintf("connection failed: %v", err)}
	}
	defer func() { _ = conn.Close() }()

	inst, err := newInstance(ctx, eng, conn)
	if err != nil {
		return &StickyKeysResult{Performed: false, SkipReason: fmt.Sprintf("wasm instance: %v", err)}
	}
	defer func() { _ = inst.close(ctx) }()

	stickyResult, err := p.runStickyKeysDetection(ctx, inst, addr, noVision, timeout)
	if err != nil {
		return &StickyKeysResult{Performed: false, SkipReason: fmt.Sprintf("detection failed: %v", err)}
	}

	return stickyResult
}

// RunUtilmanCheck performs utilman backdoor detection on a separate connection.
func (p *Plugin) RunUtilmanCheck(ctx context.Context, target string, timeout time.Duration, noVision bool) *UtilmanResult {
	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	eng, err := initEngine()
	if err != nil {
		return &UtilmanResult{Performed: false, SkipReason: fmt.Sprintf("wasm init: %v", err)}
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &UtilmanResult{Performed: false, SkipReason: fmt.Sprintf("connection failed: %v", err)}
	}
	defer func() { _ = conn.Close() }()

	inst, err := newInstance(ctx, eng, conn)
	if err != nil {
		return &UtilmanResult{Performed: false, SkipReason: fmt.Sprintf("wasm instance: %v", err)}
	}
	defer func() { _ = inst.close(ctx) }()

	utilmanResult, err := p.runUtilmanDetection(ctx, inst, addr, noVision, timeout)
	if err != nil {
		return &UtilmanResult{Performed: false, SkipReason: fmt.Sprintf("detection failed: %v", err)}
	}

	return utilmanResult
}

// ---------------------------------------------------------------------------
// Detection sequences (non-NLA connection → trigger → analyze)
// ---------------------------------------------------------------------------

// runStickyKeysDetection performs the full detection sequence on a non-NLA connection.
// timeout is the per-host budget passed to each session pump phase.
func (p *Plugin) runStickyKeysDetection(ctx context.Context, inst *wasmInstance, addr string, noVision bool, timeout time.Duration) (*StickyKeysResult, error) {
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

	baseline, response, width, height, stabilized, err := p.runSession(ctx, inst, connHandle, 1024, 768, timeout)
	if err != nil {
		result.Performed = false
		result.SkipReason = fmt.Sprintf("session failed: %v", err)
		return result, nil
	}

	// Vision API confirmation is optional: requires ANTHROPIC_API_KEY and
	// can be disabled with --no-vision flag.
	var visionAPIKey string
	if !noVision {
		visionAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	*result = runStickyKeysAnalysis(ctx, baseline, response, width, height, visionAPIKey)
	result.Performed = true
	result.Stabilized = stabilized

	// Cardinal false-negative guard: only a "clean" verdict on a render that
	// never stabilized is suspect. Positive verdicts (confirmed/likely/
	// vulnerable) already saw the window and are never downgraded.
	result.OverallVerdict = stabilizedVerdict(result.OverallVerdict, stabilized)

	return result, nil
}

// runUtilmanDetection performs the full utilman detection sequence on a non-NLA connection.
// timeout is the per-host budget passed to each session pump phase.
func (p *Plugin) runUtilmanDetection(ctx context.Context, inst *wasmInstance, addr string, noVision bool, timeout time.Duration) (*UtilmanResult, error) {
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

	baseline, response, width, height, stabilized, err := p.runUtilmanSession(ctx, inst, connHandle, 1024, 768, timeout)
	if err != nil {
		result.Performed = false
		result.SkipReason = fmt.Sprintf("session failed: %v", err)
		return result, nil
	}

	// Vision API confirmation is optional: requires ANTHROPIC_API_KEY and
	// can be disabled with --no-vision flag.
	var visionAPIKey string
	if !noVision {
		visionAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	*result = runUtilmanAnalysis(ctx, baseline, response, width, height, visionAPIKey)
	result.Performed = true
	result.Stabilized = stabilized

	// Cardinal false-negative guard: only a "clean" verdict on a render that
	// never stabilized is suspect. Positive verdicts (confirmed/likely/
	// vulnerable) already saw the window and are never downgraded.
	result.OverallVerdict = stabilizedVerdict(result.OverallVerdict, stabilized)

	return result, nil
}

// stabilizedVerdict downgrades a clean verdict to indeterminate when the
// render never stabilized; all other verdicts (including positives) pass through.
func stabilizedVerdict(verdict string, stabilized bool) string {
	if verdict == "clean" && !stabilized {
		return verdictIndeterminate
	}
	return verdict
}

// ---------------------------------------------------------------------------
// Banner formatting (append detection results to auth banner)
// ---------------------------------------------------------------------------

// formatStickyKeysBanner appends sticky keys detection results to the banner.
func formatStickyKeysBanner(existingBanner string, result *StickyKeysResult) string {
	if result == nil {
		return existingBanner
	}
	if !result.Performed {
		banner := existingBanner
		if banner != "" {
			banner += "\n"
		}
		// A failed connect/instance is NOT a benign skip — it produced no
		// verdict, so surface it loudly as indeterminate (rerun), not clean.
		banner += fmt.Sprintf("[WARN] Sticky keys check INDETERMINATE (could not connect — rerun): %s", result.SkipReason)
		return banner
	}

	banner := existingBanner
	if banner != "" {
		banner += "\n"
	}

	switch result.OverallVerdict {
	case "backdoor_confirmed":
		banner += fmt.Sprintf("[CRITICAL] Sticky keys backdoor CONFIRMED (confidence: %.0f%%)\n", result.Confidence*100)
		banner += "sethc.exe has been replaced with cmd.exe or similar.\n"
		banner += "SYSTEM-level unauthenticated access available via 5x Shift.\n"
		banner += "B-TP: malicious persistence (T1546.008), forgotten password recovery, or pentest artifact.\n"
		banner += "Remediation: Boot from Windows install media, restore original sethc.exe, or run sfc /scannow."
	case "backdoor_likely":
		banner += fmt.Sprintf("[HIGH] Sticky keys backdoor likely (confidence: %.0f%%)\n", result.Confidence*100)
		banner += "A dark window appeared after 5x Shift on the login screen.\n"
		banner += "Heuristic: " + result.HeuristicResult
		if result.VisionResult != "" {
			banner += " | Vision: " + result.VisionResult
		}
	case "vulnerable":
		banner += "[INFO] Non-NLA RDP target. Sticky Keys triggers normally (no backdoor detected).\n"
		banner += "Target is vulnerable if sethc.exe is later replaced."
	case verdictIndeterminate:
		banner += "[WARN] Sticky keys check INDETERMINATE (render did not stabilize — rerun)"
	case "clean":
		banner += "[INFO] Sticky keys check: clean (no response to 5x Shift)."
	}

	// Geometry diagnostic (never affects the verdict — confidence/banner only).
	if result.RegionNote != "" {
		banner += fmt.Sprintf(" (%s)", result.RegionNote)
	}

	return banner
}

// formatUtilmanBanner appends utilman detection results to the banner.
func formatUtilmanBanner(existingBanner string, result *UtilmanResult) string {
	if result == nil {
		return existingBanner
	}
	if !result.Performed {
		banner := existingBanner
		if banner != "" {
			banner += "\n"
		}
		// A failed connect/instance is NOT a benign skip — it produced no
		// verdict, so surface it loudly as indeterminate (rerun), not clean.
		banner += fmt.Sprintf("[WARN] Utilman check INDETERMINATE (could not connect — rerun): %s", result.SkipReason)
		return banner
	}

	banner := existingBanner
	if banner != "" {
		banner += "\n"
	}

	switch result.OverallVerdict {
	case "backdoor_confirmed":
		banner += fmt.Sprintf("[CRITICAL] Utilman backdoor CONFIRMED (confidence: %.0f%%)\n", result.Confidence*100)
		banner += "utilman.exe has been replaced with cmd.exe or similar.\n"
		banner += "SYSTEM-level unauthenticated access available via Win+U on login screen.\n"
		banner += "B-TP: malicious persistence (T1546.008), forgotten password recovery, or pentest artifact.\n"
		banner += "Remediation: Boot from Windows install media, restore original utilman.exe, or run sfc /scannow."
	case "backdoor_likely":
		banner += fmt.Sprintf("[HIGH] Utilman backdoor likely (confidence: %.0f%%)\n", result.Confidence*100)
		banner += "A window appeared after Win+U on the login screen.\n"
		banner += "Heuristic: " + result.HeuristicResult
		if result.VisionResult != "" {
			banner += " | Vision: " + result.VisionResult
		}
	case "vulnerable":
		banner += "[INFO] Non-NLA RDP target. Utilman triggers normally (no backdoor detected).\n"
		banner += "Target is vulnerable if utilman.exe is later replaced."
	case verdictIndeterminate:
		banner += "[WARN] Utilman check INDETERMINATE (render did not stabilize — rerun)"
	case "clean":
		banner += "[INFO] Utilman check: clean (no response to Win+U)."
	}

	// Geometry diagnostic (never affects the verdict — confidence/banner only).
	if result.RegionNote != "" {
		banner += fmt.Sprintf(" (%s)", result.RegionNote)
	}

	return banner
}
