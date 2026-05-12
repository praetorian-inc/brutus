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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHTTPProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     bool
	}{
		{name: "http", protocol: "http", want: true},
		{name: "https", protocol: "https", want: true},
		{name: "couchdb", protocol: "couchdb", want: true},
		{name: "elasticsearch", protocol: "elasticsearch", want: true},
		{name: "influxdb", protocol: "influxdb", want: true},
		{name: "ssh is not HTTP", protocol: "ssh", want: false},
		{name: "ftp is not HTTP", protocol: "ftp", want: false},
		{name: "mysql is not HTTP", protocol: "mysql", want: false},
		{name: "empty protocol", protocol: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHTTPProtocol(tt.protocol)
			assert.Equal(t, tt.want, got)
		})
	}
}
