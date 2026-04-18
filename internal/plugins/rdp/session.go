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
	"crypto/tls"
	"encoding/binary"
	"fmt"
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

// StickyKeysResult holds the outcome of sticky keys detection.
type StickyKeysResult struct {
	Performed       bool
	SkipReason      string
	OverallVerdict  string  // "backdoor_confirmed", "backdoor_likely", "vulnerable", "clean"
	Confidence      float64 // 0.0-1.0
	HeuristicResult string
	VisionResult    string
}

// leftShiftScancode is the scancode for Left Shift key (used for sticky keys detection).
const leftShiftScancode = 0x2A

// runConnectorForSession drives the connector state machine and returns the connector handle
// (for session handoff) instead of consuming it. Similar to runConnector but doesn't free the handle.
func (p *Plugin) runConnectorForSession(ctx context.Context, inst *wasmInstance, config []byte) (handle uint32, banner string, err error) { //nolint:unparam // banner reserved for future use
	configPtr, configLen, err := inst.writeToWasm(ctx, config)
	if err != nil {
		return 0, "", fmt.Errorf("write config: %w", err)
	}
	defer inst.freeInWasm(ctx, configPtr, configLen)

	connectorNewFn := inst.mod.ExportedFunction("connector_new")
	if connectorNewFn == nil {
		return 0, "", fmt.Errorf("connector_new not exported")
	}

	callCtx := inst.callCtx(ctx)
	results, err := connectorNewFn.Call(callCtx, uint64(configPtr), uint64(configLen))
	if err != nil {
		return 0, "", fmt.Errorf("connector_new: %w", err)
	}
	handle = uint32(results[0])
	if handle == 0 {
		return 0, "", fmt.Errorf("connector_new returned null handle")
	}

	connectorStepFn := inst.mod.ExportedFunction("connector_step")
	if connectorStepFn == nil {
		return 0, "", fmt.Errorf("connector_step not exported")
	}

	inputPtr := uint32(0)
	inputLen := uint32(0)

	for i := 0; i < maxConnectorIterations; i++ {
		outPtrSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			return 0, banner, fmt.Errorf("alloc out ptr: %w", err)
		}
		outLenSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			return 0, banner, fmt.Errorf("alloc out len: %w", err)
		}

		results, err := connectorStepFn.Call(callCtx,
			uint64(handle),
			uint64(inputPtr), uint64(inputLen),
			uint64(outPtrSlot), uint64(outLenSlot),
		)
		if err != nil {
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			return 0, banner, fmt.Errorf("connector_step: %w", err)
		}

		state := uint32(results[0])

		if inputPtr != 0 {
			inst.freeInWasm(callCtx, inputPtr, inputLen)
			inputPtr = 0
			inputLen = 0
		}

		switch state {
		case stateConnected:
			bannerBytes := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
			if len(bannerBytes) > 0 {
				banner = string(bannerBytes)
			}
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			return handle, banner, nil

		case stateError:
			errBytes := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			// Free the connector handle on error
			if freeFn := inst.mod.ExportedFunction("connector_free"); freeFn != nil {
				_, _ = freeFn.Call(callCtx, uint64(handle))
			}
			errMsg := "connection failed"
			if len(errBytes) > 0 {
				errMsg = string(errBytes)
			}
			return 0, banner, fmt.Errorf("%s", errMsg)

		case stateNeedSend:
			sendData := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			if len(sendData) > 0 {
				if _, writeErr := inst.activeConn().Write(sendData); writeErr != nil {
					return 0, banner, fmt.Errorf("connection error: tcp write: %w", writeErr)
				}
			}
			// Don't read here — the connector will emit NEED_RECV when
			// it actually needs server data.

		case stateNeedRecv:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			buf := make([]byte, tcpReadBufSize)
			n, readErr := inst.activeConn().Read(buf)
			if readErr != nil {
				return 0, banner, fmt.Errorf("connection error: tcp read: %w", readErr)
			}
			inputPtr, inputLen, err = inst.writeToWasm(callCtx, buf[:n])
			if err != nil {
				return 0, banner, fmt.Errorf("write recv to wasm: %w", err)
			}

		case stateNeedTLSUpgrade:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			tlsConf := &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // RDP servers use self-signed certs
			}
			tlsConn := tls.Client(inst.conn, tlsConf)
			if tlsErr := tlsConn.HandshakeContext(ctx); tlsErr != nil {
				return 0, banner, fmt.Errorf("connection error: tls upgrade: %w", tlsErr)
			}
			inst.tls = tlsConn

		default:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			return 0, banner, fmt.Errorf("unknown connector state: %d", state)
		}
	}

	return 0, banner, fmt.Errorf("connector exceeded maximum iterations")
}

// runSession creates a session from the connector, pumps it to receive the login screen bitmap,
// sends 5x Shift key presses, then captures the post-keystroke bitmap.
// Returns (baseline_rgba, response_rgba, width, height, error).
func (p *Plugin) runSession(ctx context.Context, inst *wasmInstance, connHandle uint32,
	width, height uint32) (baselineRGBA, responseRGBA []byte, outWidth, outHeight uint32, err error) {

	callCtx := inst.callCtx(ctx)

	// Create session from connector
	sessionNewFn := inst.mod.ExportedFunction("session_new")
	if sessionNewFn == nil {
		return nil, nil, 0, 0, fmt.Errorf("session_new not exported")
	}
	results, err := sessionNewFn.Call(callCtx, uint64(connHandle), uint64(width), uint64(height))
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("session_new: %w", err)
	}
	sessHandle := uint32(results[0])
	if sessHandle == 0 {
		return nil, nil, 0, 0, fmt.Errorf("session_new returned null handle")
	}

	// Ensure cleanup
	sessionFreeFn := inst.mod.ExportedFunction("session_free")
	defer func() {
		if sessionFreeFn != nil {
			_, _ = sessionFreeFn.Call(callCtx, uint64(sessHandle))
		}
	}()

	// Pump session to get initial login screen
	if pumpErr := p.pumpSession(ctx, inst, sessHandle, 5*time.Second); pumpErr != nil {
		return nil, nil, 0, 0, fmt.Errorf("pump baseline: %w", pumpErr)
	}

	// Capture baseline frame
	baseline, err := p.captureFrame(ctx, inst, sessHandle)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("capture baseline: %w", err)
	}

	// Send 5x Shift key to trigger sticky keys
	for i := 0; i < 5; i++ {
		if keyErr := p.sendKey(ctx, inst, sessHandle, leftShiftScancode, true); keyErr != nil {
			return nil, nil, 0, 0, fmt.Errorf("send shift press %d: %w", i+1, keyErr)
		}
		time.Sleep(50 * time.Millisecond)
		if keyErr := p.sendKey(ctx, inst, sessHandle, leftShiftScancode, false); keyErr != nil {
			return nil, nil, 0, 0, fmt.Errorf("send shift release %d: %w", i+1, keyErr)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for response and pump — give cmd.exe time to render before capturing.
	// The exec.go path uses 1s sleep + 2s WaitForFrame; we mirror that here.
	time.Sleep(1500 * time.Millisecond)
	if pumpErr := p.pumpSession(ctx, inst, sessHandle, 3*time.Second); pumpErr != nil {
		// Non-fatal -- target might not respond
		_ = pumpErr
	}

	// Capture response frame
	response, err := p.captureFrame(ctx, inst, sessHandle)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("capture response: %w", err)
	}

	return baseline, response, width, height, nil
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

// pumpSession drives the session state machine until a frame is available or timeout.
func (p *Plugin) pumpSession(ctx context.Context, inst *wasmInstance, sessHandle uint32, timeout time.Duration) error {
	callCtx := inst.callCtx(ctx)
	sessionStepFn := inst.mod.ExportedFunction("session_step")
	if sessionStepFn == nil {
		return fmt.Errorf("session_step not exported")
	}

	deadline := time.Now().Add(timeout)
	conn := inst.activeConn()
	// Reset read deadline when we exit so subsequent operations are not affected.
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	for time.Now().Before(deadline) {
		// Set per-frame read deadline
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		// Read a complete RDP PDU (TPKT or FastPath framed)
		frame, readErr := readRDPFrame(conn)
		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				continue // Timeout is OK, just loop
			}
			return fmt.Errorf("read frame: %w", readErr)
		}

		// Write complete frame to WASM
		inputPtr, inputLen, err := inst.writeToWasm(callCtx, frame)
		if err != nil {
			return fmt.Errorf("write to wasm: %w", err)
		}

		outPtrSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			inst.freeInWasm(callCtx, inputPtr, inputLen)
			return fmt.Errorf("alloc out ptr: %w", err)
		}
		outLenSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			inst.freeInWasm(callCtx, inputPtr, inputLen)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			return fmt.Errorf("alloc out len: %w", err)
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
			return fmt.Errorf("session_step: %w", err)
		}

		state := uint32(results[0])

		switch state {
		case stateFrameAvailable:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			// Don't return — RDP sends the screen incrementally across many
			// frames.  Keep pumping until timeout to accumulate all bitmap
			// updates into the DecodedImage framebuffer.

		case stateSessionNeedSend:
			sendData := readOutputFromSlots(callCtx, inst, outPtrSlot, outLenSlot)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			if len(sendData) > 0 {
				if _, writeErr := conn.Write(sendData); writeErr != nil {
					return fmt.Errorf("tcp write: %w", writeErr)
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
			return fmt.Errorf("session error: %s", string(errBytes))

		default:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
		}
	}

	return nil // Timeout is not fatal
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
