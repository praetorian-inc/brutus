// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build chromedp

package browser

import (
	"testing"
	"time"
)

func TestGetBrowser_ReturnsSingleton(t *testing.T) {
	// Skip if Chrome not available
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	b1, err := GetBrowser(3)
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b1.Close()

	b2, err := GetBrowser(3)
	if err != nil {
		t.Fatalf("GetBrowser second call failed: %v", err)
	}

	if b1 != b2 {
		t.Error("GetBrowser should return same instance (singleton)")
	}
}

func TestBrowser_AcquireTab(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	b, err := GetBrowser(2)
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b.Close()

	// Acquire first tab
	ctx1, release1 := b.AcquireTab()
	if ctx1 == nil {
		t.Error("AcquireTab returned nil context")
	}

	// Acquire second tab
	ctx2, release2 := b.AcquireTab()
	if ctx2 == nil {
		t.Error("AcquireTab returned nil context for second tab")
	}

	// Release tabs
	release1()
	release2()
}

func TestBrowser_AcquireTab_BlocksWhenPoolExhausted(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	// Reset singleton for this test
	resetBrowserSingleton()

	b, err := GetBrowser(1) // Only 1 tab
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b.Close()

	// Acquire the only tab
	_, release := b.AcquireTab()

	// Try to acquire another - should block
	done := make(chan bool)
	go func() {
		ctx, rel := b.AcquireTab()
		if ctx != nil {
			rel()
		}
		done <- true
	}()

	// Should not complete within 100ms
	select {
	case <-done:
		t.Error("AcquireTab should block when pool exhausted")
	case <-time.After(100 * time.Millisecond):
		// Expected - release the tab
		release()
	}

	// Now it should complete
	select {
	case <-done:
		// Expected
	case <-time.After(1 * time.Second):
		t.Error("AcquireTab should unblock after release")
	}
}

func TestBrowser_Navigate(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	resetBrowserSingleton()

	b, err := GetBrowser(1)
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b.Close()

	tabCtx, release := b.AcquireTab()
	defer release()

	// Navigate to a simple URL (using data URL to avoid network)
	err = b.Navigate(tabCtx, "data:text/html,<h1>Test</h1>", 5*time.Second)
	if err != nil {
		t.Errorf("Navigate failed: %v", err)
	}
}
