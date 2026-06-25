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

// nlaRequiredBanner is the terminal verdict banner for a host that enforces NLA.
// It carries the literal token "nla_required" so JSONL finding/grep and human
// output both surface it, and a leading [INFO] tag so extractFinding renders it.
const nlaRequiredBanner = "[INFO] nla_required (NLA/CredSSP enforced; logon-screen backdoor check not possible without credentials — not scannable)"

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

// NLARequiredResults returns the terminal, non-retryable result pair for a host
// that requires NLA (its logon screen is unreachable pre-auth). It mirrors the
// shape of CancelledResults but with Indeterminate:false — nla_required is a
// distinct terminal state, NOT "clean" and NOT "indeterminate". Success=false.
// The checks selection controls which entries are returned: CheckBoth -> sticky
// then utilman, CheckStickyKeys -> sticky only, CheckUtilman -> utilman only.
func NLARequiredResults(target string, checks Check) []brutus.Result {
	var results []brutus.Result
	if checks != CheckUtilman {
		results = append(results, brutus.Result{
			Protocol: "rdp",
			Target:   target,
			Username: "(sticky-keys)",
			ScanType: "sticky_keys",
			Banner:   nlaRequiredBanner,
		})
	}
	if checks != CheckStickyKeys {
		results = append(results, brutus.Result{
			Protocol: "rdp",
			Target:   target,
			Username: "(utilman)",
			ScanType: "utilman",
			Banner:   nlaRequiredBanner,
		})
	}
	return results
}

// unreachableBanner is the terminal verdict banner for a host we could not TCP-
// connect to. It carries the literal token "unreachable" so JSONL/grep and human
// output both surface it, with a leading [INFO] tag so extractFinding renders it.
const unreachableBanner = "[INFO] unreachable (no RDP/TCP connection to host:port — not scannable)"

// UnreachableResults returns the terminal, non-retryable result pair for a host
// we could not reach over TCP. It mirrors NLARequiredResults: Success=false and
// Indeterminate=false — unreachable is a distinct terminal state, NOT "clean"
// and NOT "indeterminate" (so the retry loop never fires). The checks selector
// controls which entries are returned (CheckBoth -> 2, CheckStickyKeys -> sticky
// only, CheckUtilman -> utilman only).
func UnreachableResults(target string, checks Check) []brutus.Result {
	var results []brutus.Result
	if checks != CheckUtilman {
		results = append(results, brutus.Result{
			Protocol: "rdp",
			Target:   target,
			Username: "(sticky-keys)",
			ScanType: "sticky_keys",
			Banner:   unreachableBanner,
		})
	}
	if checks != CheckStickyKeys {
		results = append(results, brutus.Result{
			Protocol: "rdp",
			Target:   target,
			Username: "(utilman)",
			ScanType: "utilman",
			Banner:   unreachableBanner,
		})
	}
	return results
}
