// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build chromedp || e2e

package browser

import (
	"os/exec"
	"runtime"
)

// chromeAvailable checks if Chrome/Chromium is installed and accessible.
func chromeAvailable() bool {
	var candidates []string

	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"google-chrome",
			"chromium",
		}
	case "linux":
		candidates = []string{
			"google-chrome",
			"google-chrome-stable",
			"chromium",
			"chromium-browser",
		}
	case "windows":
		candidates = []string{
			"chrome.exe",
			"chromium.exe",
		}
	default:
		candidates = []string{"google-chrome", "chromium"}
	}

	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate); err == nil {
			return true
		}
	}

	return false
}
