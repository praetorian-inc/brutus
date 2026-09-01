#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Building IronRDP WASM module..."

# host_io.rs declares the Go-provided host functions (host_tcp_read, host_log,
# host_get_tls_server_pubkey, ...) in an `extern "C"` block. Those resolve at
# instantiation time via wazero's host module, not at link time, so wasm-ld must be
# told to emit them as imports instead of failing on undefined symbols. Without
# this the build dies with `undefined symbol: host_get_tls_server_pubkey`, which is
# why a clean checkout could not reproduce the committed ironrdp.wasm.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=--allow-undefined"

cargo build --target wasm32-wasip1 --release

WASM_FILE="target/wasm32-wasip1/release/ironrdp_wasm.wasm"

if [ ! -f "$WASM_FILE" ]; then
    echo "ERROR: WASM binary not found at $WASM_FILE"
    exit 1
fi

# Optimize the WASM binary for size (optional, may fail on some WASM features)
if command -v wasm-opt &> /dev/null; then
    echo "Optimizing with wasm-opt..."
    if wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int "$WASM_FILE" -o "${WASM_FILE%.wasm}.opt.wasm" 2>/dev/null; then
        mv "${WASM_FILE%.wasm}.opt.wasm" "$WASM_FILE"
        echo "wasm-opt optimization applied."
    else
        echo "wasm-opt optimization skipped (unsupported features in binary)."
    fi
fi

# Copy to Go embed location
cp "$WASM_FILE" ../ironrdp.wasm
echo "WASM binary: $(wc -c < ../ironrdp.wasm | tr -d ' ') bytes"
