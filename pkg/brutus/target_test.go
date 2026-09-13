package brutus_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestParseTarget_IPv4(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		defaultPort string
		wantHost    string
		wantPort    string
	}{
		{
			name:        "host with port",
			target:      "example.com:5432",
			defaultPort: "5432",
			wantHost:    "example.com",
			wantPort:    "5432",
		},
		{
			name:        "IP with port",
			target:      "10.0.0.5:3306",
			defaultPort: "3306",
			wantHost:    "10.0.0.5",
			wantPort:    "3306",
		},
		{
			name:        "host without port",
			target:      "example.com",
			defaultPort: "5432",
			wantHost:    "example.com",
			wantPort:    "5432",
		},
		{
			name:        "IP without port",
			target:      "192.168.1.1",
			defaultPort: "22",
			wantHost:    "192.168.1.1",
			wantPort:    "22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := brutus.ParseTarget(tt.target, tt.defaultPort)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}

func TestParseTarget_IPv6(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		defaultPort string
		wantHost    string
		wantPort    string
	}{
		{
			name:        "IPv6 with port",
			target:      "[::1]:5432",
			defaultPort: "5432",
			wantHost:    "::1",
			wantPort:    "5432",
		},
		{
			name:        "IPv6 full address with port",
			target:      "[2001:db8::1]:3306",
			defaultPort: "3306",
			wantHost:    "2001:db8::1",
			wantPort:    "3306",
		},
		{
			name:        "IPv6 without port",
			target:      "::1",
			defaultPort: "5432",
			wantHost:    "::1",
			wantPort:    "5432",
		},
		{
			name:        "IPv6 without port (full)",
			target:      "2001:db8::1",
			defaultPort: "22",
			wantHost:    "2001:db8::1",
			wantPort:    "22",
		},
		{
			name:        "bracketed IPv6 without port",
			target:      "[::1]",
			defaultPort: "22",
			wantHost:    "[::1]",
			wantPort:    "22",
		},
		{
			name:        "empty target uses default port",
			target:      "",
			defaultPort: "22",
			wantHost:    "",
			wantPort:    "22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := brutus.ParseTarget(tt.target, tt.defaultPort)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}
