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

import "testing"

// The fixtures here are synthesised to the measurements taken from genuinely
// backdoored and genuinely clean Windows hosts, so the thresholds are exercised
// at the values that actually occur:
//
//	host          changed  rect score  darkInBox  meanBox  outcome
//	2016 backdoor   28.1%        0.80       0.70       40  detected already
//	2019 backdoor   62.0%        1.00       0.93       24  was reported clean
//	2025 backdoor    6.9%        0.11       0.92       28  was reported clean
//	2025 clean      11.6%        0.52       0.46      135  correctly clean
//
// The 2025 backdoor is the case that matters most: its rectangle score of 0.11
// is *below* the clean host's 0.52, because only the title bar and text differ
// from a black background. Any rule keyed on the rectangle score would rank it
// as less suspicious than a clean screen.

const (
	testFrameW = 200
	testFrameH = 200
)

// solidFrame returns a frame filled with one brightness.
func solidFrame(v byte) []byte {
	buf := make([]byte, testFrameW*testFrameH*4)
	for i := 0; i < len(buf); i += 4 {
		buf[i], buf[i+1], buf[i+2], buf[i+3] = v, v, v, 0xFF
	}
	return buf
}

// paint fills a rectangle, using the package's existing paintBox helper.
func paint(buf []byte, x0, y0, x1, y1 int, v byte) {
	paintBox(buf, testFrameW, x0, y0, x1, y1, v)
}

// TestDarkConsoleGeometryConfirmsOnDarkBackground is the Server 2025 case: a
// near-black console on a black logon screen, where the brightness delta is
// almost nothing but the geometry is unmistakable.
func TestDarkConsoleGeometryConfirmsOnDarkBackground(t *testing.T) {
	// A black logon screen.
	baseline := solidFrame(3)

	// A console anchored top-left covering most of the screen. Its body is
	// barely brighter than the background, which is why a brightness delta
	// cannot see it, but it carries a light title bar and bright text.
	response := solidFrame(3)
	paint(response, 10, 10, 189, 149, 12) // console body, near-black
	paint(response, 10, 10, 189, 18, 240) // title bar, light
	for y := 30; y < 140; y += 6 {        // rows of bright text
		paint(response, 14, y, 150, y+1, 200)
	}

	confirmed, note := darkConsoleGeometryConfirms(baseline, response, testFrameW, testFrameH)
	if !confirmed {
		t.Fatalf("a dark console on a dark background was not confirmed; note=%q", note)
	}
	if note == "" {
		t.Error("confirmation produced no explanation for the banner")
	}

	// The point of the test: the brightness delta on its own says clean.
	if v := darkDeltaVerdict(baseline, response, testFrameW, testFrameH); v != "clean" {
		t.Logf("note: darkDeltaVerdict returned %q here, so this fixture no longer "+
			"reproduces the blind spot and should be re-derived from real frames", v)
	}
}

// TestDarkConsoleGeometryRejectsLightDialog covers the legitimate Sticky Keys
// prompt, which is the false positive that matters: a real dialog appears on
// every clean host when Shift is tapped five times.
func TestDarkConsoleGeometryRejectsLightDialog(t *testing.T) {
	baseline := solidFrame(3)

	// A small, centred, light dialog.
	response := solidFrame(3)
	paint(response, 70, 80, 130, 120, 200)

	if confirmed, note := darkConsoleGeometryConfirms(baseline, response, testFrameW, testFrameH); confirmed {
		t.Fatalf("a light centred dialog was confirmed as a dark console: %q", note)
	}
}

// TestDarkConsoleGeometryRejectsDispersedChange covers the wallpaper false
// positive the console gate was originally built to reject: a large changed box
// whose body is not actually dark.
func TestDarkConsoleGeometryRejectsDispersedChange(t *testing.T) {
	baseline := solidFrame(120)

	// A large area shifts brightness without becoming a dark body.
	response := solidFrame(120)
	paint(response, 5, 5, 194, 194, 160)

	if confirmed, note := darkConsoleGeometryConfirms(baseline, response, testFrameW, testFrameH); confirmed {
		t.Fatalf("a dispersed brightness shift was confirmed as a console: %q", note)
	}
}

// TestDarkConsoleGeometryRejectsStaticScreen guards the fabricated-positive
// path: a screen that never repainted must never be read as a console.
func TestDarkConsoleGeometryRejectsStaticScreen(t *testing.T) {
	baseline := solidFrame(3)
	response := solidFrame(3)

	if confirmed, note := darkConsoleGeometryConfirms(baseline, response, testFrameW, testFrameH); confirmed {
		t.Fatalf("an unchanged screen was confirmed as a console: %q", note)
	}
}

// TestDarkConsoleGeometryRejectsTinyChange checks the minimum-change guard, so
// a blinking caret cannot escalate a clean reading.
func TestDarkConsoleGeometryRejectsTinyChange(t *testing.T) {
	baseline := solidFrame(3)

	response := solidFrame(3)
	paint(response, 100, 100, 103, 112, 220) // a caret

	if confirmed, note := darkConsoleGeometryConfirms(baseline, response, testFrameW, testFrameH); confirmed {
		t.Fatalf("a blinking caret was confirmed as a console: %q", note)
	}
}

// TestDarkConsoleEscalatesOnlyToLikely checks the cardinal rule: the escalation
// produces backdoor_likely, which the console gate and the stabilized check can
// still downgrade. It must never short-circuit to confirmed.
func TestDarkConsoleEscalatesOnlyToLikely(t *testing.T) {
	baseline := solidFrame(3)
	response := solidFrame(3)
	paint(response, 10, 10, 189, 149, 12)
	paint(response, 10, 10, 189, 18, 240)
	for y := 30; y < 140; y += 6 {
		paint(response, 14, y, 150, y+1, 200)
	}

	result := runStickyKeysAnalysis(nil, baseline, response, testFrameW, testFrameH, "")
	if result.OverallVerdict == "backdoor_confirmed" {
		t.Fatal("geometry alone reached backdoor_confirmed; only behavioural or " +
			"vision confirmation may do that")
	}
	if result.OverallVerdict == "clean" {
		t.Fatalf("a dark console was still reported clean: %+v", result)
	}
}

// TestDarkConsoleGeometryRejectsFullScreenChange covers the false positive this
// check produced before the upper bound existed.
//
// A clean Server 2019 host transitions from its lock-screen photo to the sign-in
// view, changing about 98% of pixels and leaving a large, dark, top-left box
// that geometry alone cannot distinguish from a full-screen console. The
// changed-pixel ceiling is what separates "a window appeared" from "the whole
// screen was replaced".
func TestDarkConsoleGeometryRejectsFullScreenChange(t *testing.T) {
	// A bright screen becomes a uniformly dark one.
	baseline := solidFrame(150)
	response := solidFrame(10)

	confirmed, note := darkConsoleGeometryConfirms(baseline, response, testFrameW, testFrameH)
	if confirmed {
		t.Fatalf("a full-screen change was confirmed as a console: %q", note)
	}
}
