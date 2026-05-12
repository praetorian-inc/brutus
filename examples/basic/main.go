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
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	_ "github.com/praetorian-inc/brutus/pkg/builtins"
)

func main() {
	// Show registered plugins
	fmt.Printf("Available protocols: %v\n\n", brutus.ListPlugins())

	config := &brutus.Config{
		Target:    "10.0.0.50:22",
		Protocol:  "ssh",
		Usernames: []string{"root", "admin"},
		Passwords: []string{"password", "admin", "toor"},
		Timeout:   5 * time.Second,
		Threads:   10,
	}

	fmt.Printf("Testing %d credentials against %s...\n",
		len(config.Usernames)*len(config.Passwords), config.Target)

	results, err := brutus.Brute(config)
	if err != nil {
		log.Fatalf("Brute force failed: %v", err)
	}

	// Print results
	fmt.Printf("\nResults:\n")
	validCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		if r.Success {
			fmt.Printf("[+] Valid: %s:%s (%.2fs)\n",
				r.Username, r.Password, r.Duration.Seconds())
			validCount++
		} else if r.Error != nil {
			fmt.Printf("[-] Error: %s:%s - %v\n",
				r.Username, r.Password, r.Error)
			errorCount++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total tested: %d\n", len(results))
	fmt.Printf("  Valid credentials: %d\n", validCount)
	fmt.Printf("  Errors: %d\n", errorCount)
}
