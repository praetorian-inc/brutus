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
	"os"
	"time"
)

// Backend selects which RDP implementation the plugin drives.
//
// Two exist during the migration from the IronRDP WASM module to the native Go
// library, so the two can be compared on the same host before the old one is
// removed. The detection and vision logic is shared: it consumes RGBA frames and
// does not know or care which backend produced them.
type Backend int

// Available backends.
const (
	// BackendWASM drives the IronRDP module compiled to WASM through wazero.
	// It is the original implementation.
	BackendWASM Backend = iota
	// BackendGordp drives the native Go library, which needs no Rust toolchain
	// and no copying of frames across a WASM memory boundary.
	BackendGordp
)

// String renders the backend for logs and banners.
func (b Backend) String() string {
	switch b {
	case BackendWASM:
		return "ironrdp-wasm"
	case BackendGordp:
		return "gordp"
	default:
		return "unknown backend"
	}
}

// rdpSession is the session surface the detection logic needs.
//
// The interface is deliberately drawn at the level of a single protocol step
// rather than at "pump until settled". The settling heuristics — the quiet
// window, the minimum pump time, the changed-pixel noise floor — encode tuning
// that took real effort to get right against real hosts, and duplicating them
// per backend would be the fastest way to lose it. Instead one implementation of
// those heuristics drives any session through Step.
type rdpSession interface {
	// Step reads one PDU from the server and applies it, returning whether the
	// framebuffer changed as a result.
	//
	// A read timeout must be reported as (false, nil), not as an error: RDP
	// paints in bursts, and the pump relies on quiet time accumulating across
	// the pauses between them.
	Step(ctx context.Context, readDeadline time.Duration) (updated bool, err error)

	// Frame returns a copy of the current framebuffer as RGBA.
	//
	// It must be an independent copy, not a view of the live buffer. The pump
	// compares each frame against the previous one, and if both were views of
	// the same backing array every comparison would report "unchanged" and the
	// screen would appear to settle instantly — turning a still-painting host
	// into a confident clean verdict.
	Frame(ctx context.Context) ([]byte, error)

	// SendKey injects a PS/2 Set 1 scancode. Extended keys carry the 0xE0 prefix
	// in the high byte, matching the existing scancode tables.
	SendKey(ctx context.Context, scancode uint16, pressed bool) error

	// SendMouse injects a mouse event. button is 0 for none, 1 left, 2 right,
	// 3 middle; eventType is 0 move, 1 press, 2 release.
	SendMouse(ctx context.Context, x, y uint16, button, eventType uint32) error

	// Size returns the framebuffer dimensions in pixels.
	Size() (width, height uint32)

	// TerminationReason returns the server's own explanation for ending the
	// session, or a generic description if it gave none.
	//
	// Windows distinguishes cases an operator needs to tell apart — an idle
	// timeout, a logon timeout, a policy refusal — and collapsing them into one
	// string throws away the only diagnosis available for a host that cannot be
	// scanned.
	TerminationReason() string

	// Terminated reports whether the server has ended the session.
	//
	// This matters for correctness, not tidiness: a torn-down session's
	// framebuffer reads as a perfectly black screen, which analyses as a
	// dramatic change from the baseline and would fabricate a backdoor finding.
	Terminated() bool

	// Close releases the session, disconnecting in an orderly fashion.
	//
	// Windows Server permits only two concurrent RDP sessions, so a scan that
	// abandons sockets exhausts a host and its later connections get logged off
	// seconds after they establish. That presents as flaky detection rather
	// than as the resource problem it is.
	Close(ctx context.Context) error
}

// backendEnvVar selects the RDP backend at runtime.
//
// It exists so the native library can be exercised against real hosts, and
// compared with the WASM module on the same host, before it becomes the default.
// The WASM module stays the default until that comparison has been done broadly.
const backendEnvVar = "BRUTUS_RDP_BACKEND"

// selectedBackend returns the backend to use.
//
// An unrecognised value falls back to the WASM module rather than failing: a
// typo in an environment variable should not turn every scan into an error.
func selectedBackend() Backend {
	switch os.Getenv(backendEnvVar) {
	case "gordp", "native", "go":
		return BackendGordp
	default:
		return BackendWASM
	}
}
