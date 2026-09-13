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

const nlaRequiredReason = "NLA/CredSSP enforced; the logon screen is not reachable without credentials (not scannable)"
const unreachableReason = "no RDP/TCP connection to host:port (not scannable)"

var nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
	host, port := brutus.ParseTarget(target, "3389")
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), connectTimeout, proxyURL)
	if err != nil {
		return rdp.NegoUnreachable
	}
	defer func() { _ = conn.Close() }()
	return rdp.ProbeNLA(ctx, conn, readDeadline)
}

func NLARequiredResults(target string, checks Check) []Finding {
	return terminalFindings(target, checks, VerdictNLARequired, nlaRequiredReason)
}

func UnreachableResults(target string, checks Check) []Finding {
	return terminalFindings(target, checks, VerdictUnreachable, unreachableReason)
}
