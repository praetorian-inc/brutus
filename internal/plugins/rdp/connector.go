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
	"fmt"
)

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
