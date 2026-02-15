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
	"strings"
	"time"

	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("winrm", func() brutus.Plugin {
		return &Plugin{UseHTTPS: false}
	})
	brutus.Register("winrms", func() brutus.Plugin {
		return &Plugin{UseHTTPS: true}
	})
}

// Plugin implements WinRM password authentication.
type Plugin struct {
	UseHTTPS bool
}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	if p.UseHTTPS {
		return "winrms"
	}
	return "winrm"
}

// Test attempts WinRM password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: p.Name(),
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Parse target to extract host and port
	host, port := parseTarget(target, p.UseHTTPS)

	// Create WinRM endpoint
	endpoint := winrm.NewEndpoint(host, port, p.UseHTTPS, true, nil, nil, nil, timeout)

	// Use encrypted NTLM transport: default Windows WinRM has AllowUnencrypted=false,
	// so plain ClientNTLM completes the HTTP-level NTLM handshake but the server rejects
	// the unencrypted SOAP payload with a 401. NewEncryption("ntlm") uses bodgit/ntlmssp
	// to wrap/unwrap SOAP messages with NTLM message-level encryption (sealing).
	enc, err := winrm.NewEncryption("ntlm")
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	params := winrm.NewParameters(
		fmt.Sprintf("PT%dS", max(int(timeout.Seconds()), 1)),
		"en-US",
		153600,
	)
	params.TransportDecorator = func() winrm.Transporter {
		return enc
	}

	client, err := winrm.NewClientWithParameters(endpoint, username, password, params)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Build the endpoint URL for the SOAP request header.
	scheme := "http"
	if p.UseHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/wsman", scheme, host, port)

	// Send a lightweight WS-Management Enumerate request instead of CreateShell.
	// CreateShell targets the "windows/shell/cmd" (WinRS) resource which requires
	// local administrator privileges. Non-admin users in Remote Management Users
	// get "Access Denied" even though their NTLM credentials are valid.
	// An Enumerate against wmi/root/cimv2/* is accessible to any authenticated user
	// and is sufficient to validate credentials.
	message := soap.NewMessage()
	message.Header().
		To(url).
		ReplyTo("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous").
		MaxEnvelopeSize(params.EnvelopeSize).
		Locale(params.Locale).
		Timeout(params.Timeout).
		Action("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate").
		ResourceURI("http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*").
		Build()
	message.NewBody()

	// The encrypted NTLM transport doesn't natively support context cancellation
	// or dial timeouts, so we derive a context with the timeout deadline and run
	// the request in a goroutine to avoid blocking on unreachable hosts.
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type postResult struct {
		resp string
		err  error
	}
	ch := make(chan postResult, 1)
	go func() {
		r, e := enc.Post(client, message)
		ch <- postResult{r, e}
	}()

	select {
	case pr := <-ch:
		if pr.err != nil {
			classified := classifyError(pr.err)
			if errors.Is(classified, errAuthSuccess) {
				// NTLM auth succeeded but SOAP operation was denied — creds are valid
				result.Success = true
				result.Duration = time.Since(start)
				return result
			}
			result.Error = classified
			result.Duration = time.Since(start)
			return result
		}

		// No error means the NTLM handshake and SOAP request both succeeded
		result.Success = true
		result.Duration = time.Since(start)
		return result

	case <-timeoutCtx.Done():
		result.Error = fmt.Errorf("connection error: %w", timeoutCtx.Err())
		result.Duration = time.Since(start)
		return result
	}
}

// parseTarget splits target into host and port.
// If no port is specified, defaults based on protocol:
// - winrm (HTTP): 5985
// - winrms (HTTPS): 5986
func parseTarget(target string, useHTTPS bool) (host string, port int) {
	// Check if target contains port using net.SplitHostPort for IPv6 safety
	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err == nil {
			// Parse port string to int
			var portNum int
			_, err := fmt.Sscanf(p, "%d", &portNum)
			if err == nil {
				return h, portNum
			}
		}
	}

	// No port specified or parsing failed - use default
	defaultPort := 5985
	if useHTTPS {
		defaultPort = 5986
	}
	return target, defaultPort
}

// classifyError classifies WinRM errors into auth failures vs connection errors.
//
// Returns:
//   - nil: authentication failure (invalid credentials) — caller treats as Success=false, Error=nil
//   - authSuccess sentinel: NTLM auth succeeded but SOAP operation was denied — caller treats as valid creds
//   - wrapped error: connection/network problem
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	// A SOAP fault (ExecuteCommandError) means the NTLM handshake succeeded and
	// the server returned an application-level error. The credentials are valid.
	var execErr *winrm.ExecuteCommandError
	if errors.As(err, &execErr) {
		return errAuthSuccess
	}

	errStr := strings.ToLower(err.Error())

	// HTTP 401 after NTLM handshake means invalid credentials
	if strings.Contains(errStr, "http error 401") ||
		strings.Contains(errStr, "http response error: 401") {
		return nil
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}

// errAuthSuccess is a sentinel indicating NTLM auth succeeded despite a SOAP-level error.
var errAuthSuccess = errors.New("auth success")
