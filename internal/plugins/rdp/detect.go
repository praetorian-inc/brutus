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
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// DetectStickyKeys performs sticky keys backdoor detection and returns a brutus.Result
// with the verdict formatted as a banner string.
//
// This function wraps RunStickyKeysCheck and interprets the StickyKeysResult into
// a standardized Result format suitable for CLI output.
func DetectStickyKeys(ctx context.Context, target string, timeout time.Duration, username string) *brutus.Result {
	plugin := &Plugin{}
	stickyResult := plugin.RunStickyKeysCheck(ctx, target, timeout)

	result := &brutus.Result{
		Protocol: "rdp",
		Target:   target,
		Username: username,
		Success:  false,
	}

	if stickyResult == nil {
		result.Error = fmt.Errorf("sticky keys check returned nil")
		return result
	}

	if !stickyResult.Performed {
		result.Banner = fmt.Sprintf("[INFO] Sticky keys check skipped: %s", stickyResult.SkipReason)
		return result
	}

	result.Success = true
	switch stickyResult.OverallVerdict {
	case "backdoor_confirmed":
		result.Banner = fmt.Sprintf("[CRITICAL] Sticky keys backdoor CONFIRMED (confidence: %.0f%%)", stickyResult.Confidence*100)
	case "backdoor_likely":
		result.Banner = fmt.Sprintf("[HIGH] Sticky keys backdoor likely (confidence: %.0f%%)", stickyResult.Confidence*100)
	case "vulnerable":
		result.Banner = "[INFO] Non-NLA target, sticky keys triggers normally (no backdoor)"
	case "clean":
		result.Banner = "[INFO] Sticky keys check: clean (no response to 5x Shift)"
		result.Success = false
	}

	return result
}
