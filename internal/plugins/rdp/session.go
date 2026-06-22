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
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"time"
)

// Session state constants (must match Rust session::STATE_* values)
const (
	stateSessionReady    = 20
	stateFrameAvailable  = 21
	stateInputSent       = 22
	stateSessionError    = 25
	stateSessionNeedSend = 26
	stateSessionNeedRecv = 27
)

// verdictIndeterminate marks a check whose render never stabilized, so a
// "clean" reading cannot be trusted (distinct from a benign clean verdict).
const verdictIndeterminate = "indeterminate"

// StickyKeysResult holds the outcome of sticky keys detection.
type StickyKeysResult struct {
	Performed       bool
	Stabilized      bool // response pump observed N consecutive no-change frames
	SkipReason      string
	OverallVerdict  string  // "backdoor_confirmed", "backdoor_likely", "vulnerable", "clean", "indeterminate"
	Confidence      float64 // 0.0-1.0
	HeuristicResult string
	VisionResult    string
}

// UtilmanResult holds the outcome of utilman backdoor detection.
type UtilmanResult struct {
	Performed       bool
	Stabilized      bool // response pump observed N consecutive no-change frames
	SkipReason      string
	OverallVerdict  string  // "backdoor_confirmed", "backdoor_likely", "vulnerable", "clean", "indeterminate"
	Confidence      float64 // 0.0-1.0
	HeuristicResult string
	VisionResult    string
}

// leftShiftScancode is the scancode for Left Shift key (used for sticky keys detection).
const leftShiftScancode = 0x2A

// stableFrames is the number of consecutive identical frame hashes that signal
// the framebuffer has stopped changing (render complete).
const stableFrames = 3

// runSession creates a session from the connector, pumps it to receive the login screen bitmap,
// sends 5x Shift key presses, then captures the post-keystroke bitmap.
// Returns (baseline_rgba, response_rgba, width, height, stabilized, error).
// stabilized reflects whether the response pump observed a settled framebuffer.
func (p *Plugin) runSession(ctx context.Context, inst *wasmInstance, connHandle uint32,
	width, height uint32) (baselineRGBA, responseRGBA []byte, outWidth, outHeight uint32, stabilized bool, err error) {

	callCtx := inst.callCtx(ctx)

	// Create session from connector
	sessionNewFn := inst.mod.ExportedFunction("session_new")
	if sessionNewFn == nil {
		return nil, nil, 0, 0, false, fmt.Errorf("session_new not exported")
	}
	results, err := sessionNewFn.Call(callCtx, uint64(connHandle), uint64(width), uint64(height))
	if err != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("session_new: %w", err)
	}
	sessHandle := uint32(results[0])
	if sessHandle == 0 {
		return nil, nil, 0, 0, false, fmt.Errorf("session_new returned null handle")
	}

	// Ensure cleanup
	sessionFreeFn := inst.mod.ExportedFunction("session_free")
	defer func() {
		if sessionFreeFn != nil {
			_, _ = sessionFreeFn.Call(callCtx, uint64(sessHandle))
		}
	}()

	// Pump session to get initial login screen (baseline stabilization is ignored).
	if _, pumpErr := p.pumpSession(ctx, inst, sessHandle, 5*time.Second); pumpErr != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("pump baseline: %w", pumpErr)
	}

	// Capture baseline frame
	baseline, err := p.captureFrame(ctx, inst, sessHandle)
	if err != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("capture baseline: %w", err)
	}

	// Send 5x Shift key to trigger sticky keys
	for i := 0; i < 5; i++ {
		if keyErr := p.sendKey(ctx, inst, sessHandle, leftShiftScancode, true); keyErr != nil {
			return nil, nil, 0, 0, false, fmt.Errorf("send shift press %d: %w", i+1, keyErr)
		}
		time.Sleep(50 * time.Millisecond)
		if keyErr := p.sendKey(ctx, inst, sessHandle, leftShiftScancode, false); keyErr != nil {
			return nil, nil, 0, 0, false, fmt.Errorf("send shift release %d: %w", i+1, keyErr)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for response and pump — give cmd.exe time to render before capturing.
	// The exec.go path uses 1s sleep + 2s WaitForFrame; we mirror that here.
	time.Sleep(1500 * time.Millisecond)
	stabilized, pumpErr := p.pumpSession(ctx, inst, sessHandle, 3*time.Second)
	if pumpErr != nil {
		// Non-fatal -- target might not respond
		_ = pumpErr
	}

	// Capture response frame
	response, err := p.captureFrame(ctx, inst, sessHandle)
	if err != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("capture response: %w", err)
	}

	return baseline, response, width, height, stabilized, nil
}

// runUtilmanSession creates a session from the connector, pumps it to receive the login screen bitmap,
// sends Win+U to trigger the Utility Manager (utilman.exe), then captures the post-keystroke bitmap.
// Returns (baseline_rgba, response_rgba, width, height, stabilized, error).
// stabilized reflects whether the response pump observed a settled framebuffer.
func (p *Plugin) runUtilmanSession(ctx context.Context, inst *wasmInstance, connHandle uint32,
	width, height uint32) (baselineRGBA, responseRGBA []byte, outWidth, outHeight uint32, stabilized bool, err error) {

	callCtx := inst.callCtx(ctx)

	// Create session from connector
	sessionNewFn := inst.mod.ExportedFunction("session_new")
	if sessionNewFn == nil {
		return nil, nil, 0, 0, false, fmt.Errorf("session_new not exported")
	}
	results, err := sessionNewFn.Call(callCtx, uint64(connHandle), uint64(width), uint64(height))
	if err != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("session_new: %w", err)
	}
	sessHandle := uint32(results[0])
	if sessHandle == 0 {
		return nil, nil, 0, 0, false, fmt.Errorf("session_new returned null handle")
	}

	// Ensure cleanup
	sessionFreeFn := inst.mod.ExportedFunction("session_free")
	defer func() {
		if sessionFreeFn != nil {
			_, _ = sessionFreeFn.Call(callCtx, uint64(sessHandle))
		}
	}()

	// Pump session to get initial login screen (baseline stabilization is ignored).
	if _, pumpErr := p.pumpSession(ctx, inst, sessHandle, 5*time.Second); pumpErr != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("pump baseline: %w", pumpErr)
	}

	// Capture baseline frame
	baseline, err := p.captureFrame(ctx, inst, sessHandle)
	if err != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("capture baseline: %w", err)
	}

	// Send Win+U to trigger Utility Manager (utilman.exe)
	// Key sequence: press Win, press U, release U, release Win
	if keyErr := p.sendKey(ctx, inst, sessHandle, leftWinScancode, true); keyErr != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("send win press: %w", keyErr)
	}
	time.Sleep(50 * time.Millisecond)
	if keyErr := p.sendKey(ctx, inst, sessHandle, uKeyScancode, true); keyErr != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("send u press: %w", keyErr)
	}
	time.Sleep(50 * time.Millisecond)
	if keyErr := p.sendKey(ctx, inst, sessHandle, uKeyScancode, false); keyErr != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("send u release: %w", keyErr)
	}
	time.Sleep(50 * time.Millisecond)
	if keyErr := p.sendKey(ctx, inst, sessHandle, leftWinScancode, false); keyErr != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("send win release: %w", keyErr)
	}

	// Wait for response and pump — give cmd.exe time to render before capturing.
	time.Sleep(1500 * time.Millisecond)
	stabilized, pumpErr := p.pumpSession(ctx, inst, sessHandle, 3*time.Second)
	if pumpErr != nil {
		// Non-fatal -- target might not respond
		_ = pumpErr
	}

	// Capture response frame
	response, err := p.captureFrame(ctx, inst, sessHandle)
	if err != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("capture response: %w", err)
	}

	return baseline, response, width, height, stabilized, nil
}

// readRDPFrame reads a single complete RDP PDU from the connection.
// RDP uses two frame types:
//   - TPKT (X.224): first byte = 0x03, 4-byte header, length in bytes 2-3 (big-endian u16)
//   - FastPath:     first byte != 0x03, length in byte 1 (or bytes 1-2 if bit 7 of byte 1 is set)
//
// The returned slice contains the complete PDU including its header.
func readRDPFrame(r io.Reader) ([]byte, error) {
	// Read first 2 bytes: header byte + start of length
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] == 0x03 {
		// TPKT: 4-byte header, total length in bytes 2-3
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, fmt.Errorf("tpkt length read: %w", err)
		}
		frameLen := int(binary.BigEndian.Uint16(lenBytes))
		if frameLen < 4 {
			return nil, fmt.Errorf("invalid TPKT length: %d", frameLen)
		}
		frame := make([]byte, frameLen)
		copy(frame[0:2], header)
		copy(frame[2:4], lenBytes)
		if frameLen > 4 {
			if _, err := io.ReadFull(r, frame[4:]); err != nil {
				return nil, fmt.Errorf("tpkt payload read: %w", err)
			}
		}
		return frame, nil
	}

	// FastPath output
	if header[1]&0x80 != 0 {
		// 2-byte length: high 7 bits of byte 1 combined with byte 2
		extraByte := make([]byte, 1)
		if _, err := io.ReadFull(r, extraByte); err != nil {
			return nil, fmt.Errorf("fastpath length2 read: %w", err)
		}
		frameLen := int(header[1]&0x7F)<<8 | int(extraByte[0])
		if frameLen < 3 {
			return nil, fmt.Errorf("invalid FastPath 2-byte length: %d", frameLen)
		}
		frame := make([]byte, frameLen)
		frame[0] = header[0]
		frame[1] = header[1]
		frame[2] = extraByte[0]
		if frameLen > 3 {
			if _, err := io.ReadFull(r, frame[3:]); err != nil {
				return nil, fmt.Errorf("fastpath payload read: %w", err)
			}
		}
		return frame, nil
	}

	// 1-byte length
	frameLen := int(header[1])
	if frameLen < 2 {
		return nil, fmt.Errorf("invalid FastPath 1-byte length: %d", frameLen)
	}
	frame := make([]byte, frameLen)
	frame[0] = header[0]
	frame[1] = header[1]
	if frameLen > 2 {
		if _, err := io.ReadFull(r, frame[2:]); err != nil {
			return nil, fmt.Errorf("fastpath payload read: %w", err)
		}
	}
	return frame, nil
}

// pumpSession drives the session state machine until the framebuffer stabilizes
// or the deadline expires. It returns stabilized=true if it observed
// `stableFrames` consecutive frame-available steps with no pixel change before
// the deadline; false if the deadline cut it off while frames were still
// changing.
func (p *Plugin) pumpSession(ctx context.Context, inst *wasmInstance, sessHandle uint32, timeout time.Duration) (stabilized bool, err error) {
	callCtx := inst.callCtx(ctx)
	sessionStepFn := inst.mod.ExportedFunction("session_step")
	if sessionStepFn == nil {
		return false, fmt.Errorf("session_step not exported")
	}

	deadline := time.Now().Add(timeout)
	conn := inst.activeConn()
	// Reset read deadline when we exit so subsequent operations are not affected.
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var lastHash uint32
	var haveHash bool
	consecutiveStable := 0

	for time.Now().Before(deadline) {
		// Set per-frame read deadline
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		// Read a complete RDP PDU (TPKT or FastPath framed)
		frame, readErr := readRDPFrame(conn)
		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				continue // Timeout is OK, just loop
			}
			return false, fmt.Errorf("read frame: %w", readErr)
		}

		// Write complete frame to WASM
		inputPtr, inputLen, err := inst.writeToWasm(callCtx, frame)
		if err != nil {
			return false, fmt.Errorf("write to wasm: %w", err)
		}

		outPtrSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			inst.freeInWasm(callCtx, inputPtr, inputLen)
			return false, fmt.Errorf("alloc out ptr: %w", err)
		}
		outLenSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			inst.freeInWasm(callCtx, inputPtr, inputLen)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			return false, fmt.Errorf("alloc out len: %w", err)
		}

		results, err := sessionStepFn.Call(callCtx,
			uint64(sessHandle),
			uint64(inputPtr), uint64(inputLen),
			uint64(outPtrSlot), uint64(outLenSlot),
		)

		inst.freeInWasm(callCtx, inputPtr, inputLen)

		if err != nil {
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			return false, fmt.Errorf("session_step: %w", err)
		}

		state := uint32(results[0])

		switch state {
		case stateFrameAvailable:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			// Don't return on the first frame — RDP sends the screen
			// incrementally across many frames. Hash the framebuffer and track
			// consecutive no-change frames; once it stops changing for
			// `stableFrames` steps the render is complete and we can return the
			// slot sooner.
			if frameData, capErr := p.captureFrame(ctx, inst, sessHandle); capErr == nil {
				h := crc32.ChecksumIEEE(frameData)
				if haveHash && h == lastHash {
					consecutiveStable++
				} else {
					consecutiveStable = 0
				}
				lastHash = h
				haveHash = true
				if consecutiveStable >= stableFrames {
					return true, nil
				}
			}

		case stateSessionNeedSend:
			sendData := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			if len(sendData) > 0 {
				if _, writeErr := conn.Write(sendData); writeErr != nil {
					return false, fmt.Errorf("tcp write: %w", writeErr)
				}
			}

		case stateSessionNeedRecv:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			// Continue loop to read more

		case stateSessionError:
			errBytes := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			return false, fmt.Errorf("session error: %s", string(errBytes))

		default:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
		}
	}

	return stabilized, nil // Timeout is not fatal; stabilized stays false if frames were still changing
}

// captureFrame reads the current RGBA frame buffer from the WASM session.
func (p *Plugin) captureFrame(ctx context.Context, inst *wasmInstance, sessHandle uint32) ([]byte, error) {
	callCtx := inst.callCtx(ctx)
	getFrameFn := inst.mod.ExportedFunction("session_get_frame")
	if getFrameFn == nil {
		return nil, fmt.Errorf("session_get_frame not exported")
	}

	outPtrSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		return nil, fmt.Errorf("alloc out ptr: %w", err)
	}
	outLenSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		inst.freeInWasm(callCtx, outPtrSlot, 4)
		return nil, fmt.Errorf("alloc out len: %w", err)
	}

	results, err := getFrameFn.Call(callCtx, uint64(sessHandle), uint64(outPtrSlot), uint64(outLenSlot))
	if err != nil {
		inst.freeInWasm(callCtx, outPtrSlot, 4)
		inst.freeInWasm(callCtx, outLenSlot, 4)
		return nil, fmt.Errorf("session_get_frame: %w", err)
	}

	packed := uint32(results[0])
	if packed == 0 {
		inst.freeInWasm(callCtx, outPtrSlot, 4)
		inst.freeInWasm(callCtx, outLenSlot, 4)
		return nil, fmt.Errorf("no frame available")
	}

	frameData := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
	inst.freeInWasm(callCtx, outPtrSlot, 4)
	inst.freeInWasm(callCtx, outLenSlot, 4)

	if len(frameData) == 0 {
		return nil, fmt.Errorf("empty frame data")
	}

	return frameData, nil
}

// sendKey sends a keyboard event through the WASM session.
func (p *Plugin) sendKey(ctx context.Context, inst *wasmInstance, sessHandle uint32,
	scancode uint16, pressed bool) error {

	callCtx := inst.callCtx(ctx)
	sendKeyFn := inst.mod.ExportedFunction("session_send_key")
	if sendKeyFn == nil {
		return fmt.Errorf("session_send_key not exported")
	}

	pressedVal := uint64(0)
	if pressed {
		pressedVal = 1
	}

	outPtrSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		return fmt.Errorf("alloc out ptr: %w", err)
	}
	outLenSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		inst.freeInWasm(callCtx, outPtrSlot, 4)
		return fmt.Errorf("alloc out len: %w", err)
	}

	results, err := sendKeyFn.Call(callCtx,
		uint64(sessHandle),
		uint64(scancode),
		pressedVal,
		uint64(outPtrSlot), uint64(outLenSlot),
	)
	if err != nil {
		inst.freeInWasm(callCtx, outPtrSlot, 4)
		inst.freeInWasm(callCtx, outLenSlot, 4)
		return fmt.Errorf("session_send_key: %w", err)
	}

	state := uint32(results[0])

	// Send any response data
	sendData := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
	inst.freeInWasm(callCtx, outPtrSlot, 4)
	inst.freeInWasm(callCtx, outLenSlot, 4)

	if len(sendData) > 0 {
		if _, writeErr := inst.activeConn().Write(sendData); writeErr != nil {
			return fmt.Errorf("tcp write: %w", writeErr)
		}
	}

	if state == stateSessionError {
		return fmt.Errorf("key input error")
	}

	return nil
}
