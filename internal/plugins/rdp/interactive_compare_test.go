package rdp

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestInteractiveBothBackends exercises the InteractiveSession surface the web
// terminal drives — open, wait for frames, capture, click, type — through each
// backend against the same host.
//
// It covers the interactive path specifically, which the detection tests do not:
// those run a fixed script and close, while this one holds a session open and
// drives it the way a browser does, with input arriving from a different
// goroutine than the one reading frames.
func TestInteractiveBothBackends(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interactive comparison in short mode")
	}
	target := os.Getenv(backendCompareHostEnv)
	if target == "" {
		t.Skipf("%s is not set; see GROK.md in the gordp repo for the test servers",
			backendCompareHostEnv)
	}
	for _, b := range []struct{ name, v string }{{"wasm", ""}, {"native", "gordp"}} {
		t.Run(b.name, func(t *testing.T) {
			t.Setenv(backendEnvVar, b.v)

			sess, err := NewInteractiveSession(context.Background(), target,
				30*time.Second, 1024, 768)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer sess.Close()
			t.Logf("size %dx%d", sess.Width(), sess.Height())

			// Let the logon screen paint.
			frames := 0
			for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
				if !sess.WaitForFrame(2 * time.Second) {
					break
				}
				frames++
			}
			t.Logf("frames observed: %d", frames)
			if err := sess.PumpError(); err != nil {
				t.Fatalf("pump: %v", err)
			}

			before, err := sess.CaptureFrame()
			if err != nil {
				t.Fatalf("capture: %v", err)
			}
			if len(before) != int(sess.Width())*int(sess.Height())*4 {
				t.Fatalf("frame is %d bytes, want %d", len(before),
					int(sess.Width())*int(sess.Height())*4)
			}

			// Click the password field and type, which is exactly what the web
			// terminal relays from a browser.
			if err := sess.SendMouse(512, 468, 1, 1); err != nil {
				t.Fatalf("mouse down: %v", err)
			}
			if err := sess.SendMouse(512, 468, 1, 2); err != nil {
				t.Fatalf("mouse up: %v", err)
			}
			if err := sess.TypeString("gordp-webterm"); err != nil {
				t.Fatalf("type: %v", err)
			}
			for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); {
				if !sess.WaitForFrame(1500 * time.Millisecond) {
					break
				}
			}

			after, err := sess.CaptureFrame()
			if err != nil {
				t.Fatalf("capture after: %v", err)
			}
			changed := 0
			for i := 0; i+3 < len(before) && i+3 < len(after); i += 4 {
				if before[i] != after[i] || before[i+1] != after[i+1] || before[i+2] != after[i+2] {
					changed++
				}
			}
			t.Logf("pixels changed after input: %d", changed)
			// The characters have to actually appear. A session that opens,
			// streams frames and accepts input without the server reacting looks
			// healthy from every other angle.
			if changed == 0 {
				t.Error("typing produced no visible change, so input did not reach the server")
			}
			if err := sess.PumpError(); err != nil {
				t.Errorf("pump error after input: %v", err)
			}
		})
	}
}
