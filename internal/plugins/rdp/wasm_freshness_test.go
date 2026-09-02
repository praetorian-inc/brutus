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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEmbeddedWasmIsNotStale guards the one thing this package cannot otherwise
// check: ironrdp.wasm is a 2MB binary built BY HAND from rust/ and committed, and
// no CI job rebuilds it. Nothing else notices when the Rust source moves and the
// artifact does not -- the Go tests happily exercise a months-old binary.
//
// These assertions pin string literals that only exist in one version of the Rust
// source, so a stale artifact fails here instead of silently shipping.
//
// If this test fails after a deliberate Rust change, rebuild the artifact:
//
//	make build-wasm    # or: bash internal/plugins/rdp/rust/build.sh
//
// and update the literals below if the messages changed.
func TestEmbeddedWasmIsNotStale(t *testing.T) {
	require := assert.New(t)
	require.NotEmpty(ironrdpWasm, "the wasm artifact must be embedded")

	// Removed in the DeactivateAll fix: a server-initiated
	// deactivation-reactivation is a normal desktop switch, not a fatal error, and
	// treating it as fatal tore the session down mid-scan. If this string is back,
	// the embedded artifact predates that fix.
	assert.False(t, bytes.Contains(ironrdpWasm, []byte("server deactivation-reactivation not supported")),
		"embedded ironrdp.wasm is STALE: it still carries the pre-fix DeactivateAll error. Rebuild with `make build-wasm`.")

	// Added by the same fix and its review follow-ups. Their absence means the
	// artifact was built before them.
	for _, marker := range []string{
		"reactivation failed: ",
		"reactivation did not finalize within step budget",
		// Refuses a reactivation that comes back at a different desktop size,
		// because the host's geometry is fixed at session_new.
		"reactivation changed desktop size ",
		// Refuses keyboard/mouse input while the ActiveStage is renegotiating.
		"input attempted while reactivation is in flight",
	} {
		assert.True(t, bytes.Contains(ironrdpWasm, []byte(marker)),
			"embedded ironrdp.wasm is STALE: missing %q. Rebuild with `make build-wasm`.", marker)
	}
}

// TestEmbeddedWasmDeclaresHostImports pins the link-time contract that broke the
// build from a clean checkout: the Go-provided host functions in host_io.rs resolve
// through wazero at instantiation, so wasm-ld must emit them as IMPORTS rather than
// fail on undefined symbols. build.sh passes -C link-arg=--allow-undefined for
// exactly this; drop it and the build dies on host_get_tls_server_pubkey.
func TestEmbeddedWasmDeclaresHostImports(t *testing.T) {
	assert.True(t, bytes.Contains(ironrdpWasm, []byte("host_get_tls_server_pubkey")),
		"the wasm must import its host functions; a build without --allow-undefined cannot produce this artifact")
}
