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
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum/hunter"
)

// File-local flag variables for the hunter subcommand.
// Separate from flagEnumDomain to avoid cross-command state bleed.
var (
	flagHunterDomain string
	flagHunterAPIKey string
	flagHunterLimit  int
)

// newEnumHunterCmd builds the "hunter" command. A fresh instance is constructed
// per call so the same command can be mounted under two parents (the canonical
// "enum passive hunter" path and the hidden back-compat "enum hunter" alias)
// without sharing one *cobra.Command. All instances bind the same package-level
// flag vars, which is fine since only one runs per invocation.
func newEnumHunterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hunter",
		Short: "Discover people and emails for a domain via Hunter.io Domain Search",
		Long: `Query the Hunter.io Domain Search API to discover people associated with a
domain: email, name, job title, phone, department, seniority, confidence, and
sources. Standalone — does not feed the saas enumeration pipeline.

Requires a Hunter.io API key via the HUNTER_API_KEY environment variable
(or the --api-key flag).`,
		Example: `  # Discover people for a domain (key from HUNTER_API_KEY)
  brutus enum passive hunter --domain example.com

  # Provide the key explicitly (note: visible in process list / shell history)
  brutus enum passive hunter -d example.com --api-key abc123

  # JSONL output to a file
  brutus enum passive hunter -d example.com -o people.jsonl`,
		RunE: runEnumHunter,
	}

	f := cmd.Flags()
	f.StringVarP(&flagHunterDomain, "domain", "d", "", "Domain to search (required)")
	f.StringVar(&flagHunterAPIKey, "api-key", "",
		"Hunter.io API key (overrides HUNTER_API_KEY; WARNING: visible in process list and shell history — prefer HUNTER_API_KEY)")
	f.IntVar(&flagHunterLimit, "limit", 0, "Maximum number of people to return (0 = no cap, return all)")
	_ = cmd.MarkFlagRequired("domain")

	return cmd
}

// runEnumHunter implements the "enum hunter" subcommand.
func runEnumHunter(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	if flagHunterDomain == "" {
		return fmt.Errorf("--domain/-d is required")
	}

	apiKey, err := resolveHunterAPIKey(flagHunterAPIKey)
	if err != nil {
		return err
	}

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Querying Hunter.io Domain Search for %s...\n",
			dim(useColor, SymbolInfo), flagHunterDomain)
	}

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}
	client, err := hunter.NewClient(apiKey, flagTimeout, pageSizeForLimit(flagHunterLimit), proxyURL)
	if err != nil {
		return err
	}
	result, err := client.Search(ctx, flagHunterDomain, flagHunterLimit)
	if err != nil {
		return classifyHunterError(err)
	}

	// Verbose: log counts only — never log the key or URL (P0-1 security requirement).
	logVerbose(flagVerbose, "Hunter returned %d people (total available: %d)",
		len(result.People), result.Total)

	// Plan cap hit: results were truncated. Notify on stderr (not in JSON mode).
	if result.Truncated && !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s hunter: plan result cap reached — returning first %d of %d (more available)\n",
			dim(useColor, SymbolInfo), len(result.People), result.Total)
	}

	if flagJSON {
		outputHunterJSONL(jsonWriter, result)
	} else {
		outputHunterHuman(os.Stdout, result, useColor)
	}
	return nil
}

// resolveHunterAPIKey returns the flag value if set, else HUNTER_API_KEY env var.
// The key is never logged (P0-1 security requirement).
func resolveHunterAPIKey(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if key := os.Getenv("HUNTER_API_KEY"); key != "" {
		return key, nil
	}
	return "", fmt.Errorf("hunter.io API key required: set HUNTER_API_KEY or pass --api-key")
}

// classifyHunterError converts hunter sentinel errors into actionable, key-free messages.
func classifyHunterError(err error) error {
	switch {
	case errors.Is(err, hunter.ErrUnauthorized):
		return fmt.Errorf("hunter: invalid or missing API key (check HUNTER_API_KEY / --api-key)")
	case errors.Is(err, hunter.ErrRateLimited):
		return fmt.Errorf("hunter: rate limit exceeded — wait and retry, or lower --limit")
	case errors.Is(err, hunter.ErrLegalReasons):
		return fmt.Errorf("hunter: results unavailable for legal reasons (HTTP 451)")
	default:
		return fmt.Errorf("hunter domain search failed: %w", err)
	}
}
