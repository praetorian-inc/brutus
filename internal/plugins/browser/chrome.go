// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

var (
	browserOnce     sync.Once
	browserInstance *Browser
	browserErr      error
	browserMu       sync.Mutex
	browserVisible  bool // Global flag for visible mode (set before first GetBrowser call)
)

// Browser manages a Chrome instance with a pool of tabs
type Browser struct {
	allocCtx   context.Context
	browserCtx context.Context // Parent context for creating new tabs
	cancel     context.CancelFunc
	tabPool    chan context.Context
	tabCount   int
	tabSem     chan struct{} // Semaphore to limit concurrent tabs
}

// SetBrowserVisible sets whether the browser should be visible (must be called before GetBrowser)
func SetBrowserVisible(visible bool) {
	browserVisible = visible
}

// GetBrowser returns the singleton browser instance
func GetBrowser(tabCount int) (*Browser, error) {
	browserOnce.Do(func() {
		browserInstance, browserErr = startBrowser(tabCount, browserVisible)
	})
	return browserInstance, browserErr
}

// startBrowser initializes Chrome and creates the tab pool
func startBrowser(tabCount int, visible bool) (*Browser, error) {
	// Create allocator context - headless unless visible mode is enabled
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", !visible),
		chromedp.Flag("disable-gpu", !visible), // GPU can be enabled when visible
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	// Add window size for visible mode
	if visible {
		opts = append(opts,
			chromedp.WindowSize(1280, 900),
		)
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Create browser context
	browserCtx, _ := chromedp.NewContext(allocCtx)

	// Start the browser by running an empty task
	if err := chromedp.Run(browserCtx); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start browser: %w", err)
	}

	// Create semaphore to limit concurrent tabs (instead of pre-creating tabs)
	tabSem := make(chan struct{}, tabCount)
	for i := 0; i < tabCount; i++ {
		tabSem <- struct{}{}
	}

	return &Browser{
		allocCtx:   allocCtx,
		browserCtx: browserCtx,
		cancel:     cancel,
		tabPool:    nil, // Not using pre-created pool anymore
		tabCount:   tabCount,
		tabSem:     tabSem,
	}, nil
}

// AcquireTab creates a fresh tab context (blocks if max tabs reached).
// Each call creates a new tab to avoid state corruption issues with tab reuse.
func (b *Browser) AcquireTab() (tabCtx context.Context, release func()) {
	// Wait for semaphore slot
	<-b.tabSem

	// Create fresh tab context for this operation
	tabCtx, tabCancel := chromedp.NewContext(b.browserCtx)

	return tabCtx, func() {
		// Close this tab when done
		tabCancel()
		// Return semaphore slot
		b.tabSem <- struct{}{}
	}
}

// Navigate loads a URL in the given tab context
func (b *Browser) Navigate(tabCtx context.Context, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	return chromedp.Run(ctx, chromedp.Navigate(url))
}

// Screenshot captures a PNG screenshot of the current page
func (b *Browser) Screenshot(tabCtx context.Context) ([]byte, error) {
	// Add a timeout to prevent hanging on problematic pages
	ctx, cancel := context.WithTimeout(tabCtx, 30*time.Second)
	defer cancel()

	var buf []byte
	// Small sleep to let the page finish rendering after navigation
	// Then capture the screenshot
	err := chromedp.Run(ctx,
		chromedp.Sleep(500*time.Millisecond),
		chromedp.CaptureScreenshot(&buf),
	)
	return buf, err
}

// NavigateAndScreenshot navigates to a URL and captures a screenshot in a single operation.
// This avoids context lifecycle issues between separate Navigate and Screenshot calls.
func (b *Browser) NavigateAndScreenshot(tabCtx context.Context, url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.CaptureScreenshot(&buf),
	)
	return buf, err
}

// Close shuts down the browser
func (b *Browser) Close() {
	b.cancel()
}

// resetBrowserSingleton is for testing only
func resetBrowserSingleton() {
	browserMu.Lock()
	defer browserMu.Unlock()

	if browserInstance != nil {
		browserInstance.Close()
		browserInstance = nil
	}
	browserOnce = sync.Once{}
	browserErr = nil
}
