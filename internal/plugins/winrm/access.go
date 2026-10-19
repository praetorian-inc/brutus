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

package winrm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// AccessKind is what a WinRM logon attempt proved.
//
// HTTP 401 is a bad password and must abort a spray (badPwdCount). Access
// denied after NTLM succeeded is authorization, not a lockout increment.
type AccessKind int

const (
	AccessUnknown AccessKind = iota
	AccessAllowed
	AccessDenied
	AccessBadCredentials
	AccessUnreachable
)

func (k AccessKind) String() string {
	switch k {
	case AccessAllowed:
		return "allowed"
	case AccessDenied:
		return "denied"
	case AccessBadCredentials:
		return "bad credentials"
	case AccessUnreachable:
		return "unreachable"
	default:
		return "unknown"
	}
}

// AbortsSpray reports whether this verdict must stop further attempts against
// the same account.
func (k AccessKind) AbortsSpray() bool {
	return k == AccessBadCredentials
}

// AccessReport is the outcome of one host.
type AccessReport struct {
	Host   string     `json:"host"`
	Kind   AccessKind `json:"-"`
	Detail string     `json:"detail"`
}

func (r AccessReport) String() string {
	if r.Detail == "" {
		return fmt.Sprintf("%s\t%s", r.Host, r.Kind)
	}
	return fmt.Sprintf("%s\t%s\t%s", r.Host, r.Kind, r.Detail)
}

// KindName is the stable JSON/CLI label for Kind.
func (r AccessReport) KindName() string { return r.Kind.String() }

// classifyAccessError maps a CreateShell/NTLM failure onto an access verdict.
func classifyAccessError(err error) (AccessKind, string) {
	if err == nil {
		return AccessAllowed, "winrm shell created"
	}
	if errors.Is(err, context.Canceled) {
		return AccessUnknown, err.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return AccessUnreachable, err.Error()
	}

	var execErr *winrm.ExecuteCommandError
	if errors.As(err, &execErr) {
		return AccessDenied, execErr.Error()
	}

	classified := brutus.ClassifyAuthError(err, winrmAuthIndicators)
	if classified == nil {
		return AccessBadCredentials, err.Error()
	}

	msg := err.Error()
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "connect: ") {
		return AccessUnreachable, msg
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return AccessUnreachable, msg
	}
	return AccessUnreachable, classified.Error()
}

func (p *Plugin) encryptedClient(host string, port int, username, password string, timeout time.Duration) (*winrm.Client, error) {
	endpoint := winrm.NewEndpoint(host, port, p.UseHTTPS, true, nil, nil, nil, timeout)
	enc, err := winrm.NewEncryption("ntlm")
	if err != nil {
		return nil, err
	}
	params := winrm.NewParameters(
		fmt.Sprintf("PT%dS", max(int(timeout.Seconds()), 1)),
		"en-US",
		153600,
	)
	params.TransportDecorator = func() winrm.Transporter {
		return enc
	}
	return winrm.NewClientWithParameters(endpoint, username, password, params)
}

// ProbeAccess tries to open a WinRM shell. Success means this account can use
// WinRM on the host (Remote Management Users / Administrators, not LATFP-filtered).
// HTTP 401 is a wrong password. A SOAP AccessDenied after NTLM is valid creds
// without shell rights.
func (p *Plugin) ProbeAccess(ctx context.Context, target, username, password string, timeout time.Duration) AccessReport {
	host, port := parseTarget(target, p.UseHTTPS)
	reportHost := net.JoinHostPort(host, strconv.Itoa(port))

	client, err := p.encryptedClient(host, port, username, password, timeout)
	if err != nil {
		kind, detail := classifyAccessError(err)
		return AccessReport{Host: reportHost, Kind: kind, Detail: detail}
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type shellResult struct {
		shell *winrm.Shell
		err   error
	}
	ch := make(chan shellResult, 1)
	go func() {
		s, e := client.CreateShell()
		select {
		case ch <- shellResult{s, e}:
		case <-timeoutCtx.Done():
			if s != nil {
				_ = s.Close()
			}
		}
	}()

	select {
	case pr := <-ch:
		if pr.err != nil {
			kind, detail := classifyAccessError(pr.err)
			return AccessReport{Host: reportHost, Kind: kind, Detail: detail}
		}
		_ = pr.shell.Close()
		return AccessReport{Host: reportHost, Kind: AccessAllowed, Detail: "winrm shell created"}
	case <-timeoutCtx.Done():
		kind, detail := classifyAccessError(timeoutCtx.Err())
		return AccessReport{Host: reportHost, Kind: kind, Detail: detail}
	}
}
