// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

package snmp

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "snmp", p.Name())
}

func TestParseTarget_HostOnly(t *testing.T) {
	host, port, err := parseTarget("192.168.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", host)
	assert.Equal(t, 161, port)
}

func TestParseTarget_HostWithPort(t *testing.T) {
	host, port, err := parseTarget("192.168.1.1:1161")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", host)
	assert.Equal(t, 1161, port)
}

func TestParseTarget_Hostname(t *testing.T) {
	host, port, err := parseTarget("router.local")
	assert.NoError(t, err)
	assert.Equal(t, "router.local", host)
	assert.Equal(t, 161, port)
}

func TestParseTarget_HostnameWithPort(t *testing.T) {
	host, port, err := parseTarget("router.local:162")
	assert.NoError(t, err)
	assert.Equal(t, "router.local", host)
	assert.Equal(t, 162, port)
}

func TestParseTarget_IPv6(t *testing.T) {
	host, port, err := parseTarget("[::1]")
	assert.NoError(t, err)
	assert.Equal(t, "::1", host)
	assert.Equal(t, 161, port)
}

func TestParseTarget_IPv6WithPort(t *testing.T) {
	host, port, err := parseTarget("[::1]:1161")
	assert.NoError(t, err)
	assert.Equal(t, "::1", host)
	assert.Equal(t, 1161, port)
}

func TestParseTarget_InvalidPort(t *testing.T) {
	_, _, err := parseTarget("192.168.1.1:abc")
	assert.Error(t, err)
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Test against non-existent port (should timeout quickly)
	result := p.Test(ctx, "localhost:9999", "", "public", 1*time.Second, brutus.PluginConfig{})

	assert.Equal(t, "snmp", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.Equal(t, "public", result.Password)
	assert.False(t, result.Success)
	// Timeout on non-responsive port = auth failure (nil error), not connection error
	// This is UDP behavior
}

// Integration test helpers
func getTestHost(t *testing.T) string {
	host := os.Getenv("SNMP_TEST_HOST")
	if host == "" {
		t.Skip("SNMP_TEST_HOST not set, skipping integration test. Set to run: export SNMP_TEST_HOST=localhost:161")
	}
	return host
}

// TestPlugin_Integration_ValidCommunity tests successful SNMP authentication
func TestPlugin_Integration_ValidCommunity(t *testing.T) {
	host := getTestHost(t)
	community := os.Getenv("SNMP_TEST_COMMUNITY")
	if community == "" {
		community = "public"
	}

	p := &Plugin{}
	ctx := context.Background()
	result := p.Test(ctx, host, "", community, 5*time.Second, brutus.PluginConfig{})

	require.True(t, result.Success, "Expected valid community string to succeed")
	assert.Nil(t, result.Error, "Valid community should have nil error")
	assert.NotEmpty(t, result.Banner, "Expected sysDescr banner to be captured")
	assert.Equal(t, "snmp", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, community, result.Password)

	t.Logf("Banner captured: %s", result.Banner)
	t.Logf("Duration: %v", result.Duration)
}

// TestPlugin_Integration_InvalidCommunity tests SNMP auth failure behavior
func TestPlugin_Integration_InvalidCommunity(t *testing.T) {
	host := getTestHost(t)

	p := &Plugin{}
	ctx := context.Background()

	// Use random string that won't be a valid community
	result := p.Test(ctx, host, "", "invalid_community_xyz123_test", 2*time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success, "Expected invalid community string to fail")
	assert.Nil(t, result.Error, "Invalid community should return nil error (auth failure, not connection error)")
	assert.Empty(t, result.Banner, "Invalid community should not capture banner")

	t.Logf("Duration for timeout: %v", result.Duration)
}

// TestPlugin_Integration_ReadWriteCommunity tests RW community string
func TestPlugin_Integration_ReadWriteCommunity(t *testing.T) {
	host := getTestHost(t)
	rwCommunity := os.Getenv("SNMP_TEST_COMMUNITY_RW")
	if rwCommunity == "" {
		rwCommunity = "private"
	}

	p := &Plugin{}
	ctx := context.Background()
	result := p.Test(ctx, host, "", rwCommunity, 5*time.Second, brutus.PluginConfig{})

	// RW community may or may not be configured - log result either way
	t.Logf("RW community '%s' result: success=%v, error=%v", rwCommunity, result.Success, result.Error)

	if result.Success {
		assert.NotEmpty(t, result.Banner, "Valid RW community should capture banner")
	}
}

// TestPlugin_Integration_BannerCapture validates banner content is useful
func TestPlugin_Integration_BannerCapture(t *testing.T) {
	host := getTestHost(t)
	community := os.Getenv("SNMP_TEST_COMMUNITY")
	if community == "" {
		community = "public"
	}

	p := &Plugin{}
	ctx := context.Background()
	result := p.Test(ctx, host, "", community, 5*time.Second, brutus.PluginConfig{})

	if !result.Success {
		t.Skip("Skipping banner test - community string not valid")
	}

	// Banner should contain useful system identification info
	assert.NotEmpty(t, result.Banner, "Banner should not be empty")

	// Common patterns in sysDescr banners
	bannerPatterns := []string{
		"Linux", "Windows", "Cisco", "FreeBSD", "Darwin",
		"net-snmp", "HP", "APC", "router", "switch",
	}

	found := false
	for _, pattern := range bannerPatterns {
		if strings.Contains(strings.ToLower(result.Banner), strings.ToLower(pattern)) {
			found = true
			t.Logf("Banner contains known pattern '%s': %s", pattern, result.Banner)
			break
		}
	}

	// Log banner even if no pattern matched (for debugging)
	if !found {
		t.Logf("Banner captured (no common pattern matched): %s", result.Banner)
	}
}

// TestPlugin_Integration_ContextCancellation tests that context cancellation works
func TestPlugin_Integration_ContextCancellation(t *testing.T) {
	host := getTestHost(t)

	p := &Plugin{}

	// Create a context that will be canceled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	result := p.Test(ctx, host, "", "any_community", 10*time.Second, brutus.PluginConfig{})
	elapsed := time.Since(start)

	// Should have returned quickly due to context cancellation
	assert.Less(t, elapsed.Seconds(), 5.0, "Should respect context cancellation")
	assert.False(t, result.Success)

	t.Logf("Context cancellation test completed in %v", elapsed)
}

// TestPlugin_Integration_MultipleCommunities tests brute-forcing multiple strings
func TestPlugin_Integration_MultipleCommunities(t *testing.T) {
	host := getTestHost(t)

	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Test multiple community strings (simulating brute-force behavior)
	testStrings := []string{"wrong1", "wrong2", "public", "wrong3"}

	var foundValid string
	for _, community := range testStrings {
		result := p.Test(ctx, host, "", community, timeout, brutus.PluginConfig{})
		if result.Success {
			foundValid = community
			t.Logf("Found valid community string: %s", community)
			break
		}
	}

	// If public is configured, we should find it
	validCommunity := os.Getenv("SNMP_TEST_COMMUNITY")
	if validCommunity == "" {
		validCommunity = "public"
	}

	if foundValid == "" {
		t.Logf("No valid community found in test set (expected: %s)", validCommunity)
	} else {
		assert.Equal(t, validCommunity, foundValid, "Should find the configured community string")
	}
}

// TestPlugin_Integration_TierDefault tests the default tier community strings
func TestPlugin_Integration_TierDefault(t *testing.T) {
	host := getTestHost(t)

	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Get default tier strings and test first few
	tier := GetCommunityStrings(TierDefault)
	require.GreaterOrEqual(t, len(tier), 20, "Default tier should have at least 20 strings")

	t.Logf("Testing first 5 strings from default tier against %s", host)

	for i, community := range tier[:5] {
		result := p.Test(ctx, host, "", community, timeout, brutus.PluginConfig{})
		t.Logf("[%d] Testing '%s': success=%v", i, community, result.Success)

		if result.Success {
			t.Logf("Found valid community at index %d: %s", i, community)
			t.Logf("Banner: %s", result.Banner)
			return // Found valid, test passes
		}
	}

	t.Log("No valid community found in first 5 of default tier")
}
