// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Example usage of the browser plugin for IoT device credential testing.
//
// This example demonstrates how to use the browser plugin to:
// 1. Navigate to a web interface
// 2. Detect login pages using AI vision
// 3. Identify the device type (router, printer, camera, etc.)
// 4. Research default credentials
// 5. Attempt authentication
//
// Requirements:
// - Chrome or Chromium installed
// - ANTHROPIC_API_KEY environment variable (for vision analysis)
// - PERPLEXITY_API_KEY environment variable (optional, for credential research)
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	_ "github.com/praetorian-inc/brutus/pkg/builtins"
)

func main() {
	// Check for required API key
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		log.Println("Warning: ANTHROPIC_API_KEY not set, vision analysis disabled")
	}

	// Target IoT device (example: router admin panel)
	target := "192.168.1.1:80"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	fmt.Printf("Testing browser-based login on %s\n\n", target)

	// Configure for browser-based testing
	config := &brutus.Config{
		Target:   target,
		Protocol: "browser",
		// Default IoT credentials to try
		Usernames: []string{"admin", "root", "user"},
		Passwords: []string{"admin", "password", "1234", ""},
		Timeout:   60 * time.Second,
		Threads:   1, // Browser uses tab pooling, not thread-per-credential
		LLMConfig: &brutus.LLMConfig{
			Enabled:  apiKey != "",
			Provider: "claude-vision",
			APIKey:   apiKey,
		},
	}

	// Run credential testing
	results, err := brutus.Brute(config)
	if err != nil {
		log.Fatalf("Brute force failed: %v", err)
	}

	// Print results
	fmt.Println("Results:")
	fmt.Println("--------")

	for i := range results {
		r := &results[i]
		status := "FAIL"
		if r.Success {
			status = "SUCCESS"
		}

		fmt.Printf("[%s] %s:%s", status, r.Username, r.Password)

		if r.Error != nil {
			fmt.Printf(" (error: %v)", r.Error)
		}

		fmt.Printf(" [%v]\n", r.Duration.Round(time.Millisecond))

		// Print banner info (contains device identification)
		if r.Banner != "" && r.Success {
			fmt.Printf("  Device info: %s\n", r.Banner)
		}
	}

	// Summary
	var successCount int
	for i := range results {
		if results[i].Success {
			successCount++
		}
	}

	fmt.Printf("\nSummary: %d/%d credentials successful\n", successCount, len(results))
}
