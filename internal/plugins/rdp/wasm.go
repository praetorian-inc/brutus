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
	"crypto/rand"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Connector state constants (must match Rust STATE_* values)
const (
	stateNeedSend       = 1
	stateNeedRecv       = 2
	stateNeedTLSUpgrade = 3
	stateConnected      = 4
	stateError          = 5
)

// ctxKey is a private type for context keys to avoid collisions.
type ctxKey struct{}

// instanceKey is the context key used to pass wasmInstance to host functions.
var instanceKey = ctxKey{}

// withInstance returns a context carrying the given wasmInstance.
func withInstance(ctx context.Context, inst *wasmInstance) context.Context {
	return context.WithValue(ctx, instanceKey, inst)
}

// getInstance retrieves the wasmInstance from context.
func getInstance(ctx context.Context) *wasmInstance {
	inst, _ := ctx.Value(instanceKey).(*wasmInstance)
	return inst
}

// wasmEngine holds the singleton compiled module and runtime.
// Thread-safe: compiled module is immutable after init.
type wasmEngine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

var (
	engine     *wasmEngine
	engineOnce sync.Once
	engineErr  error
)

// initEngine compiles the WASM module once on first use (lazy, not at init time).
// Host functions are registered once; per-call instance state is accessed via context.
func initEngine() (*wasmEngine, error) {
	engineOnce.Do(func() {
		ctx := context.Background()

		r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())

		// Instantiate WASI for basic imports (fd, clock, random)
		_, err := wasi_snapshot_preview1.Instantiate(ctx, r)
		if err != nil {
			engineErr = fmt.Errorf("wasi instantiate: %w", err)
			return
		}

		// Register host functions once — they use context to get per-call instance state
		_, err = r.NewHostModuleBuilder("env").
			NewFunctionBuilder().
			WithFunc(hostTcpRead).
			Export("host_tcp_read").
			NewFunctionBuilder().
			WithFunc(hostTcpWrite).
			Export("host_tcp_write").
			NewFunctionBuilder().
			WithFunc(hostTlsUpgrade).
			Export("host_tls_upgrade").
			NewFunctionBuilder().
			WithFunc(hostClockNowMs).
			Export("host_clock_now_ms").
			NewFunctionBuilder().
			WithFunc(hostRandomFill).
			Export("host_random_fill").
			NewFunctionBuilder().
			WithFunc(hostLog).
			Export("host_log").
			NewFunctionBuilder().
			WithFunc(hostGetTlsServerPubkey).
			Export("host_get_tls_server_pubkey").
			Instantiate(ctx)
		if err != nil {
			engineErr = fmt.Errorf("host module: %w", err)
			_ = r.Close(ctx)
			return
		}

		// Compile the embedded WASM module
		compiled, err := r.CompileModule(ctx, ironrdpWasm)
		if err != nil {
			engineErr = fmt.Errorf("compile wasm: %w", err)
			_ = r.Close(ctx)
			return
		}

		engine = &wasmEngine{
			runtime:  r,
			compiled: compiled,
		}
	})

	return engine, engineErr
}

// wasmInstance represents a per-Test() WASM module instance.
// Each instance has isolated linear memory (inherently thread-safe).
type wasmInstance struct {
	mod  api.Module
	conn net.Conn
	tls  *tls.Conn
}

// newInstance creates a fresh WASM instance from the pre-compiled module.
// The conn parameter provides the TCP connection for host functions.
func newInstance(ctx context.Context, eng *wasmEngine, conn net.Conn) (*wasmInstance, error) {
	inst := &wasmInstance{conn: conn}

	// Instantiate a fresh module instance
	mod, err := eng.runtime.InstantiateModule(ctx, eng.compiled,
		wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, fmt.Errorf("instantiate wasm: %w", err)
	}
	inst.mod = mod

	return inst, nil
}

// close releases the WASM instance resources.
func (w *wasmInstance) close(ctx context.Context) error {
	if w.mod != nil {
		return w.mod.Close(ctx)
	}
	return nil
}

// activeConn returns the TLS connection if upgraded, otherwise the raw TCP connection.
func (w *wasmInstance) activeConn() net.Conn {
	if w.tls != nil {
		return w.tls
	}
	return w.conn
}

// callCtx returns a context carrying this instance for host function dispatch.
func (w *wasmInstance) callCtx(ctx context.Context) context.Context {
	return withInstance(ctx, w)
}

// writeToWasm allocates memory in WASM and writes data into it.
// Returns (ptr, len) for passing to WASM functions.
func (w *wasmInstance) writeToWasm(ctx context.Context, data []byte) (ptr, length uint32, err error) {
	allocFn := w.mod.ExportedFunction("wasm_alloc")
	if allocFn == nil {
		return 0, 0, fmt.Errorf("wasm_alloc not exported")
	}

	results, err := allocFn.Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, 0, fmt.Errorf("wasm_alloc(%d): %w", len(data), err)
	}
	ptr = uint32(results[0])
	if ptr == 0 {
		return 0, 0, fmt.Errorf("wasm_alloc returned null")
	}

	if !w.mod.Memory().Write(ptr, data) {
		return 0, 0, fmt.Errorf("memory write failed at ptr=%d len=%d", ptr, len(data))
	}

	return ptr, uint32(len(data)), nil
}

// readFromWasm reads bytes from WASM linear memory, copying to a new slice.
func (w *wasmInstance) readFromWasm(ptr, length uint32) ([]byte, error) {
	data, ok := w.mod.Memory().Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("memory read failed at ptr=%d len=%d", ptr, length)
	}
	result := make([]byte, length)
	copy(result, data)
	return result, nil
}

// freeInWasm deallocates previously allocated WASM memory.
func (w *wasmInstance) freeInWasm(ctx context.Context, ptr, size uint32) {
	deallocFn := w.mod.ExportedFunction("wasm_dealloc")
	if deallocFn == nil {
		return
	}
	_, _ = deallocFn.Call(ctx, uint64(ptr), uint64(size))
}

// --- Host Function Implementations ---
// These are package-level functions that retrieve the wasmInstance from context.

// hostTcpRead: WASM calls this to read from the network connection.
func hostTcpRead(ctx context.Context, m api.Module, fd, bufPtr, bufLen uint32) int32 {
	inst := getInstance(ctx)
	if inst == nil || inst.conn == nil {
		return -1
	}

	buf := make([]byte, bufLen)
	conn := inst.activeConn()

	// Set read deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}

	n, err := conn.Read(buf)
	if err != nil {
		return -1
	}
	if !m.Memory().Write(bufPtr, buf[:n]) {
		return -1
	}
	return int32(n)
}

// hostTcpWrite: WASM calls this to write to the network connection.
func hostTcpWrite(ctx context.Context, m api.Module, fd, bufPtr, bufLen uint32) int32 {
	inst := getInstance(ctx)
	if inst == nil || inst.conn == nil {
		return -1
	}

	data, ok := m.Memory().Read(bufPtr, bufLen)
	if !ok {
		return -1
	}
	conn := inst.activeConn()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}

	n, err := conn.Write(data)
	if err != nil {
		return -1
	}
	return int32(n)
}

// hostTlsUpgrade is a registered host function that the Rust WASM connector can
// call to request a TLS upgrade. Currently, the TLS upgrade is handled on the Go
// side via the stateNeedTLSUpgrade case in runConnector (see rdp.go), which is the
// active code path. This host function is registered but not called by the current
// Rust connector implementation. Both paths are retained because the Rust code MAY
// call this function directly in future CredSSP/NLA implementations that need
// tighter control over the TLS handshake timing from within the WASM module.
func hostTlsUpgrade(ctx context.Context, m api.Module, fd uint32) int32 {
	inst := getInstance(ctx)
	if inst == nil || inst.conn == nil {
		return -1
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // RDP servers use self-signed certs
	}
	inst.tls = tls.Client(inst.conn, tlsConf)
	if err := inst.tls.HandshakeContext(ctx); err != nil {
		inst.tls = nil
		return -1
	}
	return 0
}

// hostClockNowMs: Returns current time in milliseconds since epoch.
func hostClockNowMs(ctx context.Context, m api.Module) uint64 {
	return uint64(time.Now().UnixMilli())
}

// hostRandomFill: Fills a WASM buffer with cryptographically secure random bytes.
func hostRandomFill(ctx context.Context, m api.Module, bufPtr, bufLen uint32) int32 {
	buf := make([]byte, bufLen)
	// WASI random_get should handle this, but provide as fallback
	_, err := rand.Read(buf)
	if err != nil {
		return -1
	}
	if !m.Memory().Write(bufPtr, buf) {
		return -1
	}
	return 0
}

// hostLog: WASM sends a log message to Go.
func hostLog(ctx context.Context, m api.Module, level, msgPtr, msgLen uint32) {
	data, ok := m.Memory().Read(msgPtr, msgLen)
	if ok {
		fmt.Fprintf(os.Stderr, "[wasm] %s\n", string(data))
	}
}

// hostGetTlsServerPubkey: WASM calls this to get the server's public key for CredSSP.
// Returns bytes written to buf, or -1 on error.
//
// Extracts the SubjectPublicKey BIT STRING contents from the server certificate's
// SubjectPublicKeyInfo. This matches IronRDP's native extract_tls_server_public_key
// which uses subject_public_key_info.subject_public_key.as_bytes().
// For CredSSP, sspi-rs uses these raw key bytes in the pubKeyAuth computation:
// v1-4: encrypt(public_key), v5+: encrypt(SHA-256(magic + nonce + public_key)).
func hostGetTlsServerPubkey(ctx context.Context, m api.Module, bufPtr, bufLen uint32) int32 {
	inst := getInstance(ctx)
	if inst == nil || inst.tls == nil {
		return -1
	}

	state := inst.tls.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return -1
	}

	// Parse SubjectPublicKeyInfo to extract the SubjectPublicKey BIT STRING.
	// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(state.PeerCertificates[0].RawSubjectPublicKeyInfo, &spki); err != nil {
		return -1
	}
	pubKeyBytes := spki.PublicKey.Bytes

	if uint32(len(pubKeyBytes)) > bufLen {
		return -1 // Buffer too small
	}

	if !m.Memory().Write(bufPtr, pubKeyBytes) {
		return -1
	}
	return int32(len(pubKeyBytes))
}
