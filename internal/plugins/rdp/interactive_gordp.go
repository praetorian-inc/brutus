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
	"fmt"
	"time"

	gsession "github.com/UNC1739/gordp/pkg/session"
)

// newInteractiveSessionGordp opens an interactive session through the native
// library.
//
// It connects without credentials, which is what the web terminal and the
// sticky keys exploitation path both want: they drive the server's own logon
// screen, and a session that authenticated first would be past it.
func newInteractiveSessionGordp(ctx context.Context, target string, timeout time.Duration,
	width, height uint32) (*InteractiveSession, error) {

	host, port := parseTarget(target)

	native, result, err := gsession.Connect(ctx, gsession.Options{
		Addr:    host + ":" + port,
		Width:   uint16(width),
		Height:  uint16(height),
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("interactive session: %w", err)
	}

	// The server decides the final size, and it is not obliged to grant what was
	// asked for: Windows Server 2022 commonly returns a different colour depth
	// and may clamp the dimensions. Callers that place clicks by coordinate need
	// the size that was actually granted, not the one requested.
	return &InteractiveSession{
		native: native,
		width:  uint32(result.DesktopSize.Width),
		height: uint32(result.DesktopSize.Height),
	}, nil
}
