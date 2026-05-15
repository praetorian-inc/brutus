// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"testing"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	if p.Name() != "browser" {
		t.Errorf("Name() = %q, want %q", p.Name(), "browser")
	}
}

func TestPlugin_Implements_Interface(t *testing.T) {
	var _ brutus.Plugin = (*Plugin)(nil)
}

func TestPlugin_Test_ReturnsResult(t *testing.T) {
	// Reset browser singleton to avoid interference with other tests
	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	p := &Plugin{
		TabCount:        3, // Match default to avoid singleton issues
		PageLoadTimeout: 2 * time.Second,
	}

	ctx := context.Background()
	// Use localhost with unlikely port - will fail fast but still test the flow
	result := p.Test(ctx, "127.0.0.1:54321", "admin", "admin", 10*time.Second, brutus.PluginConfig{})

	if result == nil {
		t.Fatal("Test() returned nil result")
	}

	if result.Protocol != "browser" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "browser")
	}

	if result.Target != "127.0.0.1:54321" {
		t.Errorf("Target = %q, want %q", result.Target, "127.0.0.1:54321")
	}

	if result.Username != "admin" {
		t.Errorf("Username = %q, want %q", result.Username, "admin")
	}

	if result.Password != "admin" {
		t.Errorf("Password = %q, want %q", result.Password, "admin")
	}

	// Result will have an error (connection refused) but structure should be correct
	// Success should be false since connection will fail
	if result.Success {
		t.Error("Expected Success=false for unreachable target")
	}
}

func TestPlugin_Registration(t *testing.T) {
	// Plugin should be registered via init()
	plugin, err := brutus.GetPlugin("browser")
	if err != nil {
		t.Fatalf("browser plugin not registered: %v", err)
	}

	if plugin.Name() != "browser" {
		t.Errorf("Name() = %q, want %q", plugin.Name(), "browser")
	}
}
