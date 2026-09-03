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
	"errors"
	"fmt"
	"net"
	"time"

	gconnector "github.com/UNC1739/gordp/pkg/connector"
	gcredssp "github.com/UNC1739/gordp/pkg/credssp"
	ginput "github.com/UNC1739/gordp/pkg/input"
	gsession "github.com/UNC1739/gordp/pkg/session"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// gordpSession drives an RDP session through the native Go library.
//
// It satisfies rdpSession, so the detection and vision logic runs unchanged
// against it.
type gordpSession struct {
	conn   net.Conn
	stage  *gsession.ActiveStage
	driver *gsession.Driver

	width  uint32
	height uint32

	// terminated records that the server ended the session. Once set it stays
	// set: a caller must not be told a later read simply found nothing when the
	// session is actually gone, because a torn-down framebuffer reads as black
	// and would analyse as a dramatic screen change.
	terminated bool
	// errorInfo holds the server's own explanation for ending the session.
	errorInfo string
}

// gordpDialResult carries what a successful connection produced.
type gordpDialResult struct {
	session *gordpSession
	// banner describes the server, for the same reporting the WASM path does.
	banner string
	// credsspProved reports that CredSSP completed, which is itself proof that
	// the credentials were valid. Without it a completed connection proves
	// nothing and the logon has to be observed separately.
	credsspProved bool
}

// dialGordp performs the whole connection sequence and returns a live session.
//
// credentials may be empty, in which case CredSSP is skipped and the connection
// stops at the server's logon screen. That is the position the sticky keys and
// utilman checks work from: they are pre-authentication checks and must not
// depend on having a password.
func dialGordp(ctx context.Context, addr, proxyURL string, cfg rdpConfig,
	width, height uint32, connectTimeout time.Duration) (*gordpDialResult, error) {

	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, connectTimeout, proxyURL)
	if err != nil {
		return nil, brutus.WrapConnError(err)
	}

	// Any failure past this point must close the connection, or a scan leaks a
	// socket per host and exhausts the target's session slots.
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		_ = conn.SetDeadline(deadline)
	}

	gcfg := gconnector.DefaultConfig()
	gcfg.DesktopSize = gconnector.DesktopSize{Width: uint16(width), Height: uint16(height)}
	// SkipAuth means "reach the logon screen without credentials", which is
	// exactly a connection with CredSSP disabled and autologon off.
	useCredSSP := !cfg.SkipAuth
	gcfg.EnableCredSSP = useCredSSP
	gcfg.AutoLogon = useCredSSP
	gcfg.Credentials = gconnector.Credentials{
		Username: cfg.Username,
		Password: cfg.Password,
		Domain:   cfg.Domain,
	}

	// A credential scan has to reach servers that only speak the older exchange
	// — xrdp, and Windows with NLA switched off — so the downgrade is permitted
	// rather than refused. It is not silent: the result records that it happened,
	// and the logon still has to be proven separately below.
	gcfg.AllowNonNLAFallback = useCredSSP

	var runner gconnector.CredSSPRunner
	if useCredSSP {
		runner = gcredssp.Runner{}
	}

	serverName, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		serverName = addr
	}

	active, framed, result, err := gconnector.Connect(ctx, conn, serverName, gcfg, nil, runner)
	if err != nil {
		return nil, classifyGordpError(err)
	}

	stage, err := gsession.New(result)
	if err != nil {
		return nil, fmt.Errorf("connection error: session: %w", err)
	}

	ok = true
	return &gordpDialResult{
		credsspProved: useCredSSP && !result.CredSSPDowngraded,
		session: &gordpSession{
			conn:   conn,
			stage:  stage,
			driver: gsession.NewDriver(stage, active, framed),
			width:  uint32(result.DesktopSize.Width),
			height: uint32(result.DesktopSize.Height),
		},
		banner: fmt.Sprintf("RDP server, protocol %v, desktop %dx%d at %d bpp",
			result.SelectedProtocol, result.DesktopSize.Width, result.DesktopSize.Height,
			result.ColorDepth),
	}, nil
}

// Step implements rdpSession.
func (s *gordpSession) Step(ctx context.Context, readDeadline time.Duration) (bool, error) {
	if s.terminated {
		return false, fmt.Errorf("session terminated: %s", s.errorInfo)
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
		return false, fmt.Errorf("set read deadline: %w", err)
	}

	outputs, err := s.driver.ReadOne(ctx)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			// Nothing arrived in the window. That is the ordinary quiet case,
			// and the pump counts it as elapsed time rather than an error.
			return false, nil
		}
		return false, err
	}

	updated := false
	for _, out := range outputs {
		switch out.Kind {
		case gsession.OutputGraphicsUpdate:
			updated = true
		case gsession.OutputTerminate, gsession.OutputDeactivateAll:
			s.terminated = true
			s.errorInfo = out.ErrorInfo.String()
			return updated, nil
		}
	}
	return updated, nil
}

// Frame implements rdpSession.
//
// Clone rather than RGBA: the framebuffer is painted in place, so handing out a
// view would make the pump compare a frame against itself.
func (s *gordpSession) Frame(_ context.Context) ([]byte, error) {
	return s.stage.Framebuffer().Clone(), nil
}

// SendKey implements rdpSession.
//
// The scancode encoding matches the existing tables: an extended key carries
// 0xE0 in its high byte.
func (s *gordpSession) SendKey(_ context.Context, scancode uint16, pressed bool) error {
	frame, err := s.stage.SendKey(ginput.FromU16(scancode), pressed)
	if err != nil {
		return err
	}
	return s.driver.Send(frame)
}

// SendMouse implements rdpSession.
func (s *gordpSession) SendMouse(_ context.Context, x, y uint16, button, eventType uint32) error {
	ops := []ginput.Operation{ginput.Move(ginput.MousePosition{X: x, Y: y})}

	if btn, ok := gordpMouseButton(button); ok {
		switch eventType {
		case 1:
			ops = append(ops, ginput.ButtonPressed(btn))
		case 2:
			ops = append(ops, ginput.ButtonReleased(btn))
		}
	}

	frame, err := s.stage.SendInput(ops...)
	if err != nil {
		return err
	}
	return s.driver.Send(frame)
}

// gordpMouseButton maps the plugin's button numbering onto the library's.
func gordpMouseButton(button uint32) (ginput.MouseButton, bool) {
	switch button {
	case 1:
		return ginput.MouseLeft, true
	case 2:
		return ginput.MouseRight, true
	case 3:
		return ginput.MouseMiddle, true
	default:
		return 0, false
	}
}

// Size implements rdpSession.
func (s *gordpSession) Size() (uint32, uint32) { return s.width, s.height }

// Terminated implements rdpSession.
func (s *gordpSession) Terminated() bool { return s.terminated }

// TerminationReason implements rdpSession.
func (s *gordpSession) TerminationReason() string {
	if s.errorInfo == "" {
		return "server ended the session without giving a reason"
	}
	return s.errorInfo
}

// WaitForLogon waits for the server to report a logon verdict.
//
// It is only meaningful when CredSSP was not used: with CredSSP the credentials
// were already proven before the connection completed.
func (s *gordpSession) WaitForLogon(ctx context.Context, timeout time.Duration) (gsession.LogonOutcome, string, error) {
	return s.driver.WaitForLogon(ctx, timeout)
}

// Close implements rdpSession.
func (s *gordpSession) Close(ctx context.Context) error {
	// Shut the session down before dropping the socket. Skipping this occupies
	// one of the host's two RDP session slots until the server times it out, so
	// a repeated scan starts getting logged off mid-session.
	if !s.terminated {
		_ = s.conn.SetDeadline(time.Now().Add(gordpShutdownGrace))
		_ = s.driver.Shutdown(ctx)
	}
	return s.conn.Close()
}

// gordpShutdownGrace bounds the orderly disconnect. It is short because a
// scanner must not wait on a host that has stopped answering.
const gordpShutdownGrace = 2 * time.Second

// gordpVerdict is what a failed dial proved about the credential.
//
// It exists because the previous design flattened the library's typed errors
// into a string and then recovered the verdict by substring-matching that
// string against rdpAuthIndicators. That round trip is lossy by construction:
// every message beginning "authentication failed" read as a rejected password,
// including two that are nothing of the kind. Carrying the verdict as data
// removes the whole class of mistake.
type gordpVerdict int

const (
	// verdictUntestable means the host could not be asked, so the credential is
	// unproven in either direction. It must surface as an error, never as a
	// rejection: a scan that reports "wrong password" for a host it never
	// managed to interrogate quietly concludes that a valid credential does not
	// work.
	verdictUntestable gordpVerdict = iota

	// verdictRejected means the server evaluated the credential and refused it.
	// This is the only outcome that may be reported as a failed attempt.
	verdictRejected

	// verdictProvenValid means the server proved the credential correct and
	// then refused the logon for a reason that is not the password -- a
	// locked-out account, or one that policy bars from this host. The password
	// is right, which is what a credential test is asking.
	verdictProvenValid
)

// gordpDialError is a dial failure that carries what it proved, so callers read
// the verdict as data instead of parsing the message.
type gordpDialError struct {
	verdict gordpVerdict
	detail  string
	cause   error
}

func (e *gordpDialError) Error() string { return e.detail }

// Unwrap keeps errors.As working through this type, which isUnreachable and the
// transport-level checks rely on.
func (e *gordpDialError) Unwrap() error { return e.cause }

// classifyGordpError maps the library's typed errors onto a verdict.
//
// The mapping is the whole point, so each arm says why it lands where it does.
func classifyGordpError(err error) *gordpDialError {
	var authErr *gcredssp.AuthError
	if errors.As(err, &authErr) {
		// A locked-out or restricted account has proven the password is
		// correct. Reporting that as a rejection throws away the one thing the
		// exchange established.
		if authErr.CredentialsAreValid() {
			return &gordpDialError{
				verdict: verdictProvenValid,
				detail: fmt.Sprintf("credentials are valid but this logon was refused: %s",
					authErr.Status),
				cause: err,
			}
		}
		return &gordpDialError{
			verdict: verdictRejected,
			detail:  fmt.Sprintf("authentication failed: %s", authErr.Status),
			cause:   err,
		}
	}

	var negoErr *gconnector.NegotiationError
	if errors.As(err, &negoErr) {
		// Negotiation settles the security protocol before any credential is
		// sent, so a failure here proves nothing about the password. The server
		// demanding NLA the client did not offer is the common case, and it is
		// a host that could not be tested, not a credential that was refused.
		return &gordpDialError{
			verdict: verdictUntestable,
			detail:  fmt.Sprintf("rdp security negotiation did not complete: %s", negoErr.Code),
			cause:   err,
		}
	}

	var serverErr *gconnector.ServerError
	if errors.As(err, &serverErr) {
		if serverErr.IsAccessDenied() {
			return &gordpDialError{
				verdict: verdictRejected,
				detail:  fmt.Sprintf("access denied: %s", serverErr.ErrorInfo),
				cause:   err,
			}
		}
		return &gordpDialError{
			verdict: verdictUntestable,
			detail:  fmt.Sprintf("connection error: %s", serverErr.ErrorInfo),
			cause:   err,
		}
	}

	var logonErr *gconnector.LogonError
	if errors.As(err, &logonErr) {
		return &gordpDialError{
			verdict: verdictRejected,
			detail:  fmt.Sprintf("logon failed: %s", logonErr.Errors.Data),
			cause:   err,
		}
	}

	return &gordpDialError{
		verdict: verdictUntestable,
		detail:  fmt.Sprintf("connection error: %v", err),
		cause:   err,
	}
}
