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
	"sync"
	"time"
)

// InteractiveSession wraps a long-lived RDP session for interactive use.
// It provides thread-safe access to send keyboard/mouse input and read frames.
type InteractiveSession struct {
	plugin     *Plugin
	inst       *wasmInstance
	sessHandle uint32
	connHandle uint32
	conn       net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex // protects WASM calls
	width      uint32
	height     uint32

	// frameNotify is signaled when a new frame is available.
	frameNotify chan struct{}
	// pumpErr holds any fatal error from the background pump goroutine.
	pumpErr error
	pumpMu  sync.Mutex
}

// NewInteractiveSession establishes a non-NLA RDP connection and creates an
// interactive session suitable for sticky keys exploitation/demo.
func NewInteractiveSession(ctx context.Context, target string, timeout time.Duration, width, height uint32) (*InteractiveSession, error) {
	host, port := parseTarget(target)
	addr := net.JoinHostPort(host, port)

	eng, err := initEngine()
	if err != nil {
		return nil, fmt.Errorf("wasm init: %w", err)
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp connect: %w", err)
	}

	inst, err := newInstance(ctx, eng, conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("wasm instance: %w", err)
	}

	p := &Plugin{}

	cfg := rdpConfig{
		Server:   addr,
		Username: "",
		Password: "",
		Domain:   "",
		SkipAuth: true,
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		_ = inst.close(ctx)
		_ = conn.Close()
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	connHandle, _, err := p.runConnectorForSession(ctx, inst, configBytes)
	if err != nil {
		_ = inst.close(ctx)
		_ = conn.Close()
		return nil, fmt.Errorf("connector: %w", err)
	}

	// Create session
	callCtx := inst.callCtx(ctx)
	sessionNewFn := inst.mod.ExportedFunction("session_new")
	if sessionNewFn == nil {
		_ = inst.close(ctx)
		_ = conn.Close()
		return nil, fmt.Errorf("session_new not exported")
	}
	results, err := sessionNewFn.Call(callCtx, uint64(connHandle), uint64(width), uint64(height))
	if err != nil {
		_ = inst.close(ctx)
		_ = conn.Close()
		return nil, fmt.Errorf("session_new: %w", err)
	}
	sessHandle := uint32(results[0])
	if sessHandle == 0 {
		_ = inst.close(ctx)
		_ = conn.Close()
		return nil, fmt.Errorf("session_new returned null handle")
	}

	sessCtx, cancel := context.WithCancel(ctx)

	s := &InteractiveSession{
		plugin:      p,
		inst:        inst,
		sessHandle:  sessHandle,
		connHandle:  connHandle,
		conn:        conn,
		ctx:         sessCtx,
		cancel:      cancel,
		width:       width,
		height:      height,
		frameNotify: make(chan struct{}, 1),
	}

	// Start background pump
	go s.backgroundPump()

	return s, nil
}

// backgroundPump continuously reads server data and processes it through the session.
func (s *InteractiveSession) backgroundPump() {
	conn := s.inst.activeConn()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		frame, err := readRDPFrame(conn)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.pumpMu.Lock()
			s.pumpErr = err
			s.pumpMu.Unlock()
			return
		}

		s.mu.Lock()
		err = s.processFrame(frame)
		s.mu.Unlock()

		if err != nil {
			s.pumpMu.Lock()
			s.pumpErr = err
			s.pumpMu.Unlock()
			return
		}
	}
}

// processFrame feeds a single server PDU through the WASM session. Must be called with s.mu held.
func (s *InteractiveSession) processFrame(frame []byte) error {
	callCtx := s.inst.callCtx(s.ctx)

	sessionStepFn := s.inst.mod.ExportedFunction("session_step")
	if sessionStepFn == nil {
		return fmt.Errorf("session_step not exported")
	}

	inputPtr, inputLen, err := s.inst.writeToWasm(callCtx, frame)
	if err != nil {
		return fmt.Errorf("write to wasm: %w", err)
	}

	outPtrSlot, _, err := s.inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		s.inst.freeInWasm(callCtx, inputPtr, inputLen)
		return fmt.Errorf("alloc out ptr: %w", err)
	}
	outLenSlot, _, err := s.inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		s.inst.freeInWasm(callCtx, inputPtr, inputLen)
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		return fmt.Errorf("alloc out len: %w", err)
	}

	results, err := sessionStepFn.Call(callCtx,
		uint64(s.sessHandle),
		uint64(inputPtr), uint64(inputLen),
		uint64(outPtrSlot), uint64(outLenSlot),
	)

	s.inst.freeInWasm(callCtx, inputPtr, inputLen)

	if err != nil {
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		s.inst.freeInWasm(callCtx, outLenSlot, 4)
		return fmt.Errorf("session_step: %w", err)
	}

	state := uint32(results[0])

	switch state {
	case stateFrameAvailable:
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		s.inst.freeInWasm(callCtx, outLenSlot, 4)
		// Notify frame listeners
		select {
		case s.frameNotify <- struct{}{}:
		default:
		}

	case stateSessionNeedSend:
		sendData := readOutputFromSlots(callCtx, s.inst, outPtrSlot, outLenSlot)
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		s.inst.freeInWasm(callCtx, outLenSlot, 4)
		if len(sendData) > 0 {
			if _, writeErr := s.inst.activeConn().Write(sendData); writeErr != nil {
				return fmt.Errorf("tcp write: %w", writeErr)
			}
		}

	case stateSessionNeedRecv:
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		s.inst.freeInWasm(callCtx, outLenSlot, 4)

	case stateSessionError:
		errBytes := readOutputFromSlots(callCtx, s.inst, outPtrSlot, outLenSlot)
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		s.inst.freeInWasm(callCtx, outLenSlot, 4)
		return fmt.Errorf("session error: %s", string(errBytes))

	default:
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		s.inst.freeInWasm(callCtx, outLenSlot, 4)
	}

	return nil
}

// SendKey sends a keyboard key event. Thread-safe.
func (s *InteractiveSession) SendKey(scancode uint16, pressed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plugin.sendKey(s.ctx, s.inst, s.sessHandle, scancode, pressed)
}

// SendMouse sends a mouse event. Thread-safe.
// button: 0=none(move), 1=left, 2=right, 3=middle
// eventType: 0=move, 1=press, 2=release
func (s *InteractiveSession) SendMouse(x, y uint16, button, eventType uint8) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendMouseLocked(x, y, uint32(button), uint32(eventType))
}

// sendMouseLocked sends a mouse event via the WASM module. Must be called with s.mu held.
func (s *InteractiveSession) sendMouseLocked(x, y uint16, button, eventType uint32) error {
	callCtx := s.inst.callCtx(s.ctx)
	sendMouseFn := s.inst.mod.ExportedFunction("session_send_mouse")
	if sendMouseFn == nil {
		return fmt.Errorf("session_send_mouse not exported")
	}

	outPtrSlot, _, err := s.inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		return fmt.Errorf("alloc out ptr: %w", err)
	}
	outLenSlot, _, err := s.inst.writeToWasm(callCtx, make([]byte, 4))
	if err != nil {
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		return fmt.Errorf("alloc out len: %w", err)
	}

	results, err := sendMouseFn.Call(callCtx,
		uint64(s.sessHandle),
		uint64(x), uint64(y),
		uint64(button), uint64(eventType),
		uint64(outPtrSlot), uint64(outLenSlot),
	)
	if err != nil {
		s.inst.freeInWasm(callCtx, outPtrSlot, 4)
		s.inst.freeInWasm(callCtx, outLenSlot, 4)
		return fmt.Errorf("session_send_mouse: %w", err)
	}

	state := uint32(results[0])

	sendData := readOutputFromSlots(callCtx, s.inst, outPtrSlot, outLenSlot)
	s.inst.freeInWasm(callCtx, outPtrSlot, 4)
	s.inst.freeInWasm(callCtx, outLenSlot, 4)

	if len(sendData) > 0 {
		if _, writeErr := s.inst.activeConn().Write(sendData); writeErr != nil {
			return fmt.Errorf("tcp write: %w", writeErr)
		}
	}

	if state == stateSessionError {
		return fmt.Errorf("mouse input error")
	}

	return nil
}

// CaptureFrame captures the current RGBA framebuffer. Thread-safe.
func (s *InteractiveSession) CaptureFrame() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plugin.captureFrame(s.ctx, s.inst, s.sessHandle)
}

// TypeString types a string by converting each character to scancode press/release events.
// Adds a brief delay between characters for reliable delivery.
func (s *InteractiveSession) TypeString(text string) error {
	for _, ch := range []byte(text) {
		mapping, ok := asciiToScancode[ch]
		if !ok {
			continue // skip unmappable characters
		}

		// Hold shift if needed
		if mapping.shift {
			if err := s.SendKey(leftShiftScancodeSC, true); err != nil {
				return fmt.Errorf("shift press: %w", err)
			}
			time.Sleep(20 * time.Millisecond)
		}

		// Press and release the key
		if err := s.SendKey(mapping.scancode, true); err != nil {
			return fmt.Errorf("key press 0x%02X: %w", mapping.scancode, err)
		}
		time.Sleep(20 * time.Millisecond)
		if err := s.SendKey(mapping.scancode, false); err != nil {
			return fmt.Errorf("key release 0x%02X: %w", mapping.scancode, err)
		}

		// Release shift if needed
		if mapping.shift {
			time.Sleep(20 * time.Millisecond)
			if err := s.SendKey(leftShiftScancodeSC, false); err != nil {
				return fmt.Errorf("shift release: %w", err)
			}
		}

		time.Sleep(30 * time.Millisecond)
	}
	return nil
}

// PressEnter sends an Enter key press/release.
func (s *InteractiveSession) PressEnter() error {
	if err := s.SendKey(enterScancode, true); err != nil {
		return err
	}
	time.Sleep(20 * time.Millisecond)
	return s.SendKey(enterScancode, false)
}

// WaitForFrame blocks until a new frame is available or timeout.
func (s *InteractiveSession) WaitForFrame(timeout time.Duration) bool {
	select {
	case <-s.frameNotify:
		return true
	case <-time.After(timeout):
		return false
	case <-s.ctx.Done():
		return false
	}
}

// Width returns the session screen width.
func (s *InteractiveSession) Width() uint32 { return s.width }

// Height returns the session screen height.
func (s *InteractiveSession) Height() uint32 { return s.height }

// PumpError returns the last fatal pump error, if any.
func (s *InteractiveSession) PumpError() error {
	s.pumpMu.Lock()
	defer s.pumpMu.Unlock()
	return s.pumpErr
}

// Close shuts down the interactive session and frees all resources.
func (s *InteractiveSession) Close() {
	s.cancel()

	callCtx := s.inst.callCtx(context.Background())
	if freeFn := s.inst.mod.ExportedFunction("session_free"); freeFn != nil {
		_, _ = freeFn.Call(callCtx, uint64(s.sessHandle))
	}
	if freeFn := s.inst.mod.ExportedFunction("connector_free"); freeFn != nil {
		_, _ = freeFn.Call(callCtx, uint64(s.connHandle))
	}
	_ = s.inst.close(context.Background())
	_ = s.conn.Close()
}

// parseTarget splits host:port with default port 3389.
func parseTarget(target string) (host, port string) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, "3389"
	}
	if port == "" {
		port = "3389"
	}
	return host, port
}
