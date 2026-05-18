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

package input

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadMasscanFile_BasicParse(t *testing.T) {
	// Masscan's actual output format with trailing commas
	json := `[
{   "ip": "192.168.1.1",   "timestamp": "1234567890", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
,
{   "ip": "192.168.1.2",   "timestamp": "1234567891", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128} ] }
]`

	file := writeTempFile(t, "masscan.json", json)
	results, err := LoadMasscanFile(file)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "192.168.1.1", results[0].IP)
	assert.Equal(t, 22, results[0].Port)
	assert.Equal(t, "tcp", results[0].Transport)
	assert.Equal(t, "", results[0].Protocol) // masscan doesn't fingerprint

	assert.Equal(t, "192.168.1.2", results[1].IP)
	assert.Equal(t, 80, results[1].Port)
}

func TestLoadMasscanFile_TrailingComma(t *testing.T) {
	// Masscan sometimes produces a trailing comma before the closing bracket
	json := `[
{   "ip": "10.0.0.1",   "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] },
]`

	file := writeTempFile(t, "masscan-trailing.json", json)
	results, err := LoadMasscanFile(file)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "10.0.0.1", results[0].IP)
	assert.Equal(t, 443, results[0].Port)
}

func TestLoadMasscanFile_SkipsClosedPorts(t *testing.T) {
	json := `[
{"ip": "10.0.0.1", "ports": [
    {"port": 22, "proto": "tcp", "status": "open"},
    {"port": 23, "proto": "tcp", "status": "closed"}
]}
]`

	file := writeTempFile(t, "masscan-closed.json", json)
	results, err := LoadMasscanFile(file)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 22, results[0].Port)
}

func TestLoadMasscanFile_MultiplePorts(t *testing.T) {
	json := `[
{"ip": "10.0.0.1", "ports": [
    {"port": 22, "proto": "tcp", "status": "open"},
    {"port": 80, "proto": "tcp", "status": "open"},
    {"port": 443, "proto": "tcp", "status": "open"}
]}
]`

	file := writeTempFile(t, "masscan-multi.json", json)
	results, err := LoadMasscanFile(file)
	require.NoError(t, err)
	require.Len(t, results, 3)
}

func TestLoadMasscanFile_FileNotFound(t *testing.T) {
	_, err := LoadMasscanFile("/nonexistent/masscan.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opening masscan file")
}

func TestLoadMasscanFile_InvalidJSON(t *testing.T) {
	file := writeTempFile(t, "bad.json", "not json {{{")
	_, err := LoadMasscanFile(file)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing masscan JSON")
}

func TestLoadMasscanFile_EmptyArray(t *testing.T) {
	file := writeTempFile(t, "empty.json", "[]")
	results, err := LoadMasscanFile(file)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestLoadMasscanFile_TargetAddr(t *testing.T) {
	json := `[{"ip": "192.168.1.1", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]}]`
	file := writeTempFile(t, "masscan-addr.json", json)
	results, err := LoadMasscanFile(file)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "192.168.1.1:22", results[0].TargetAddr())
}

func TestLoadMasscanFile_UDPPorts(t *testing.T) {
	json := `[{"ip": "10.0.0.1", "ports": [{"port": 161, "proto": "udp", "status": "open"}]}]`
	file := writeTempFile(t, "masscan-udp.json", json)
	results, err := LoadMasscanFile(file)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "udp", results[0].Transport)
	assert.Equal(t, 161, results[0].Port)
}
