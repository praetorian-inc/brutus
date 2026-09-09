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

package logon

import (
	"context"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// nlaRequiredReason explains why an NLA-enforcing host cannot be scanned.
const nlaRequiredReason = "NLA/CredSSP enforced; the logon screen is not reachable without credentials (not scannable)"

// unreachableReason explains a host we could not reach over TCP.
const unreachableReason = "no RDP/TCP connection to host:port (not scannable)"

// nlaProbe dials with connectTimeout (short, dead-host-fast) and probes one RTT
// with readDeadline. A FAILED DIAL is classified NegoUnreachable (terminal,
// non-retryable). A successful dial whose ProbeNLA hits a read/parse error
// returns NegoProbeError (fall through to WASM — a failed nego must never skip
// detection). NegoNLARequired / NegoScannable pass through from ProbeNLA. It is
// a swappable seam so tests can classify without a live RDP server.
var nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
	host, port := brutus.ParseTarget(target, "3389")
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), connectTimeout, proxyURL)
	if err != nil {
		return rdp.NegoUnreachable
	}
	defer func() { _ = conn.Close() }()
	return rdp.ProbeNLA(ctx, conn, readDeadline)
}

// NLARequiredResults returns the terminal, non-retryable findings for a host
// that requires NLA (its logon screen is unreachable pre-auth). nla_required is
// a distinct terminal verdict: it is NOT clean and NOT a rerun candidate. The
// checks selection controls which entries are returned.
func NLARequiredResults(target string, checks Check) []Finding {
	return terminalFindings(target, checks, VerdictNLARequired, nlaRequiredReason)
}

// UnreachableResults returns the terminal, non-retryable findings for a host we
// could not reach over TCP. It mirrors NLARequiredResults: unreachable is a
// distinct terminal verdict, NOT clean and NOT a rerun candidate, so the retry
// loop never fires for it.
func UnreachableResults(target string, checks Check) []Finding {
	return terminalFindings(target, checks, VerdictUnreachable, unreachableReason)
}
