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
	// Get Claude API key from environment
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		log.Fatal("No LLM API key found. Set ANTHROPIC_API_KEY")
	}
	provider := "claude"

	config := &brutus.Config{
		Target:    "10.0.0.50:22",
		Protocol:  "ssh",
		Usernames: []string{"root", "admin"},
		Passwords: []string{"password", "admin", "toor"}, // Fallback defaults
		Timeout:   5 * time.Second,
		Threads:   10,

		// Enable LLM-based banner analysis
		LLMConfig: &brutus.LLMConfig{
			Enabled:  true,
			Provider: provider,
			APIKey:   apiKey,
		},
	}

	fmt.Printf("Testing %s with LLM provider: %s\n\n", config.Target, provider)

	results, err := brutus.Brute(config)
	if err != nil {
		log.Fatalf("Brute force failed: %v", err)
	}

	// Print results
	fmt.Printf("Results:\n")
	validCount := 0
	llmSuccessCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		if r.Success {
			source := "default"
			if r.LLMSuggested {
				source = "LLM-suggested"
				llmSuccessCount++
			}
			fmt.Printf("[+] Valid (%s): %s:%s (%.2fs)\n",
				source, r.Username, r.Password, r.Duration.Seconds())
			validCount++
		} else if r.Error != nil {
			errorCount++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total tested: %d\n", len(results))
	fmt.Printf("  Valid credentials: %d\n", validCount)
	fmt.Printf("  LLM-suggested valid: %d\n", llmSuccessCount)
	fmt.Printf("  Errors: %d\n", errorCount)

	// Show LLM suggestions for transparency
	if len(results) > 0 {
		fmt.Printf("\nService Banner: %s\n", results[0].Banner)
		if len(results[0].LLMSuggestedCreds) > 0 {
			fmt.Printf("LLM Suggestions: %v\n", results[0].LLMSuggestedCreds)
		}
	}
}
