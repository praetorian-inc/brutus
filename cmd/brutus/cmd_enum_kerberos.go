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
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	kerberos "github.com/praetorian-inc/brutus/pkg/enum/kerberos"
)

// Kerberos-specific flag variables
var (
	flagKerbDC       string
	flagKerbUsers    string
	flagKerbUserFile string
)

var enumKerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Enumerate Active Directory users via Kerberos AS-REQ",
	Long: `Enumerate whether usernames exist in an Active Directory domain by sending
Kerberos AS-REQ messages without pre-authentication data. No passwords are sent
and no account lockout risk.

Detection is based on KDC error codes:
  PREAUTH_REQUIRED  → user exists (standard account)
  AS-REP success    → user exists, no preauth required (AS-REP roastable)
  PRINCIPAL_UNKNOWN → user does not exist`,
	Example: `  # Enumerate specific users
  brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator,guest,krbtgt

  # Enumerate from file
  brutus enum active kerberos --dc dc01.corp.local --domain CORP.LOCAL -U users.txt

  # Generate usernames and enumerate
  brutus enum generate --format flast | brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -U -

  # JSON output
  brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator --json`,
	RunE: runEnumKerberos,
}

func init() {
	f := enumKerberosCmd.Flags()
	f.StringVar(&flagKerbDC, "dc", "", "KDC (Domain Controller) address (host or host:port)")
	f.StringVarP(&flagKerbUsers, "users", "u", "", "Comma-separated usernames to enumerate")
	f.StringVarP(&flagKerbUserFile, "user-file", "U", "", "File of usernames (one per line, use - for stdin)")
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Kerberos realm / AD domain (e.g., CORP.LOCAL)")
	_ = enumKerberosCmd.MarkFlagRequired("dc")
	_ = enumKerberosCmd.MarkFlagRequired("domain")
}

// runEnumKerberos handles the kerberos enum command.
func runEnumKerberos(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	// Phase 1: Build username list
	var usernames []string

	// From --users flag
	if flagKerbUsers != "" {
		for _, u := range strings.Split(flagKerbUsers, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				usernames = append(usernames, u)
			}
		}
	}

	// From --user-file flag
	if flagKerbUserFile != "" {
		fileUsers, err := loadLinesFromFile(flagKerbUserFile)
		if err != nil {
			return fmt.Errorf("loading user file: %w", err)
		}
		usernames = append(usernames, fileUsers...)
	}

	if len(usernames) == 0 {
		return fmt.Errorf("no usernames to enumerate — provide --users/-u or --user-file/-U")
	}

	// Phase 2: Setup output writer
	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	// Phase 3: Context with signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Phase 4: Worker pool setup
	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Enumerating %d user(s) against %s (%s)...\n",
			dim(useColor, SymbolInfo), len(usernames), flagEnumDomain, flagKerbDC)
	}

	// Create errgroup with bounded concurrency
	g, ctx := errgroup.WithContext(ctx)
	sem := semaphore.NewWeighted(int64(flagThreads))

	// Create rate limiter if configured
	var limiter *rate.Limiter
	if flagRateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(flagRateLimit), 1)
	}

	// Result collection
	type kerbResult struct {
		result *kerberos.Result
		err    error
	}
	resultsCh := make(chan kerbResult, len(usernames))

	// Launch workers
	for _, username := range usernames {
		username := username // Capture loop variable

		g.Go(func() error {
			// Acquire semaphore
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			defer sem.Release(1)

			// Apply rate limiting
			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					return err
				}
			}

			// Apply jitter if configured
			if flagJitter > 0 {
				time.Sleep(time.Duration(flagJitter.Nanoseconds() * int64(1+rand.Float64())))
			}

			// Enumerate user
			result := kerberos.EnumUser(ctx, flagKerbDC, flagEnumDomain, username, flagTimeout)

			// Send result
			select {
			case resultsCh <- kerbResult{result: result, err: nil}:
			case <-ctx.Done():
				return ctx.Err()
			}

			return nil
		})
	}

	// Wait for all workers
	if err := g.Wait(); err != nil && err != context.Canceled {
		return fmt.Errorf("enumeration failed: %w", err)
	}
	close(resultsCh)

	// Phase 5: Collect and output results
	var results []*kerberos.Result
	for r := range resultsCh {
		results = append(results, r.result)
	}

	if flagJSON {
		// JSONL output
		outputKerberosJSONL(jsonWriter, results)
	} else {
		// Human-readable output
		outputKerberosHuman(results, useColor)
	}

	return nil
}

// outputKerberosJSONL outputs Kerberos results in JSONL format.
func outputKerberosJSONL(w io.Writer, results []*kerberos.Result) {
	enc := json.NewEncoder(w)
	for _, r := range results {
		out := map[string]interface{}{
			"type":     "kerberos_enum",
			"username": r.Username,
			"realm":    r.Realm,
			"exists":   r.Exists,
		}

		if r.Exists {
			out["no_preauth"] = r.NoPreAuth
		}

		if r.Error != nil {
			out["error"] = r.Error.Error()
		}

		out["duration"] = r.Duration.String()

		_ = enc.Encode(out)
	}
}

// outputKerberosHuman outputs Kerberos results in human-readable format.
func outputKerberosHuman(results []*kerberos.Result, useColor bool) {
	var exists, notFound, errors int

	for _, r := range results {
		var symbol, status string
		var color string

		switch {
		case r.Error != nil:
			symbol = SymbolError
			status = fmt.Sprintf("ERROR     %-20s %s (%s)", r.Username, r.Error, r.Duration)
			color = ColorRed
			errors++
		case r.Exists:
			symbol = SymbolSuccess
			if r.NoPreAuth {
				status = fmt.Sprintf("EXISTS    %-20s (no preauth — AS-REP roastable, %s)", r.Username, r.Duration)
			} else {
				status = fmt.Sprintf("EXISTS    %-20s (preauth required, %s)", r.Username, r.Duration)
			}
			color = ColorGreen
			exists++
		default:
			symbol = " "
			status = fmt.Sprintf("NOT FOUND %-20s (%s)", r.Username, r.Duration)
			color = ColorDim
			notFound++
		}

		fmt.Printf("  %s%s %s%s\n",
			colorIf(useColor, color),
			symbol,
			status,
			colorIf(useColor, ColorReset))
	}

	// Summary
	if !flagQuiet {
		fmt.Println()
		fmt.Println(heading(useColor, "  Summary"))
		fmt.Printf("    Exists:      %d\n", exists)
		fmt.Printf("    Not found:   %d\n", notFound)
		if errors > 0 {
			fmt.Printf("    Errors:      %d\n", errors)
		}
		fmt.Printf("    Total:       %d\n", len(results))
	}
}
