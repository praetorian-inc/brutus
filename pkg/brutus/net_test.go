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

package brutus

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "newline", input: "hello\n", want: "hello"},
		{name: "crlf trimmed", input: "  hi  \r\n", want: "hi"},
		{name: "empty line", input: "\n", want: ""},
		{name: "eof without newline", input: "partial", wantErr: io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, err := ReadLine(bufio.NewReader(strings.NewReader(tt.input)))
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, line)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, line)
		})
	}
}

func TestDialWithContext_Refused(t *testing.T) {
	_, err := DialWithContext(context.Background(), "tcp", "127.0.0.1:1", time.Second)
	require.Error(t, err)
}

func TestDialWithContext_Canceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DialWithContext(ctx, "tcp", "127.0.0.1:1", time.Second)
	require.Error(t, err)
}

func TestDialWithContext_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_ = conn.Close()
	}()

	conn, err := DialWithContext(context.Background(), "tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	_ = conn.Close()
	<-done
}
