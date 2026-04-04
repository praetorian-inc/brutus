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

package ftp

import (
	"errors"
	"testing"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	"github.com/stretchr/testify/assert"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "ftp", p.Name())
}

func TestClassifyError(t *testing.T) {
	err := errors.New("dial tcp 10.0.0.1:21: connection refused")
	result := brutus.WrapConnError(err)

	assert.NotNil(t, result)
	assert.Contains(t, result.Error(), "connection error")
	assert.Contains(t, result.Error(), "connection refused")
}

func TestClassifyAuthError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantNil bool // true = auth failure (return nil), false = connection error (return error)
	}{
		{
			name:    "auth failure - 530 Login incorrect",
			err:     errors.New("530 Login incorrect"),
			wantNil: true,
		},
		{
			name:    "auth failure - 530 User cannot log in",
			err:     errors.New("530 User cannot log in"),
			wantNil: true,
		},
		{
			name:    "auth failure - 530 Authentication failed",
			err:     errors.New("530 Authentication failed"),
			wantNil: true,
		},
		{
			name:    "auth failure - 530 with mixed case",
			err:     errors.New("530 Not logged in"),
			wantNil: true,
		},
		{
			name:    "connection error - timeout",
			err:     errors.New("dial tcp 10.0.0.1:21: i/o timeout"),
			wantNil: false,
		},
		{
			name:    "connection error - connection refused",
			err:     errors.New("dial tcp 10.0.0.1:21: connection refused"),
			wantNil: false,
		},
		{
			name:    "connection error - network unreachable",
			err:     errors.New("dial tcp 10.0.0.1:21: network is unreachable"),
			wantNil: false,
		},
		{
			name:    "connection error - EOF",
			err:     errors.New("EOF"),
			wantNil: false,
		},
		{
			name:    "connection error - read error",
			err:     errors.New("read tcp 10.0.0.1:21: connection reset by peer"),
			wantNil: false,
		},
		{
			name:    "nil error",
			err:     nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyAuthError(tt.err)
			if tt.wantNil {
				assert.Nil(t, result, "auth failure should return nil")
			} else {
				assert.NotNil(t, result, "connection error should return error")
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}
