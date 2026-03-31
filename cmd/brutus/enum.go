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
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// enumMain is the entry point for the "brutus enum" subcommand.
// It delegates to runEnum and exits with the returned code.
func enumMain() {
	os.Exit(runEnum())
}

// runEnum implements the enum subcommand logic and returns an exit code.
// Using a separate function allows defers to run before os.Exit.
func runEnum() int {
	fs := flag.NewFlagSet("enum", flag.ExitOnError)

	// Input flags
	email := fs.String("e", "", "Email address to enumerate")
	emailFile := fs.String("E", "", "File containing email addresses (one per line)")
	services := fs.String("s", "", "Comma-separated service names (default: all)")

	// Execution flags
	threads := fs.Int("t", 10, "Number of concurrent threads")
	timeout := fs.Duration("timeout", 10*time.Second, "Per-check timeout")
	rateLimit := fs.Float64("rate-limit", 0, "Max requests per second (0 = unlimited)")
	jitter := fs.Duration("jitter", 0, "Random delay variance (e.g., 100ms)")

	// Output flags
	jsonOutput := fs.Bool("json", false, "JSON output format")
	outputFile := fs.String("o", "", "Output file (default: stdout)")
	quiet := fs.Bool("q", false, "Quiet mode - only show existing accounts")
	verbose := fs.Bool("v", false, "Verbose mode - show errors to stderr")
	noColor := fs.Bool("no-color", false, "Disable colored output")

	// Mode flags
	discover := fs.Bool("discover", false, "Oracle discovery mode: find which services leak account info")
	listServices := fs.Bool("list-services", false, "List all available enum services")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: brutus enum [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Account enumeration across SaaS services.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  brutus enum -e user@example.com\n")
		fmt.Fprintf(os.Stderr, "  brutus enum -E emails.txt -s microsoft365,okta\n")
		fmt.Fprintf(os.Stderr, "  brutus enum --discover -e known@company.com\n")
		fmt.Fprintf(os.Stderr, "  brutus enum --list-services\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	// Parse flags after "enum" subcommand
	if err := fs.Parse(os.Args[2:]); err != nil {
		return 1
	}

	useColor := isColorEnabled(*noColor)

	// List services mode
	if *listServices {
		enumListServices(useColor)
		return 0
	}

	// Load emails
	emails, err := loadEnumEmails(*email, *emailFile)
	if err != nil {
		errMsg(useColor, "%v", err)
		return 1
	}

	if len(emails) == 0 {
		errMsg(useColor, "no email addresses provided (use -e or -E)")
		fs.Usage()
		return 1
	}

	// Parse services
	var serviceList []string
	if *services != "" {
		serviceList = strings.Split(*services, ",")
	}

	// Setup output
	writer, forceJSON, closeOutput, err := setupOutputWriter(*outputFile)
	if err != nil {
		errMsg(useColor, "%v", err)
		return 1
	}
	defer closeOutput()
	if forceJSON {
		*jsonOutput = true
	}

	// Setup context with signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Discover mode
	if *discover {
		dcfg := &enum.DiscoverConfig{
			KnownValid: emails[0],
			Services:   serviceList,
			Threads:    *threads,
			Timeout:    *timeout,
			Verbose:    *verbose,
		}
		discoverResults, discoverErr := enum.DiscoverOracles(ctx, dcfg)
		if discoverErr != nil {
			errMsg(useColor, "%v", discoverErr)
			return 1
		}
		if *jsonOutput {
			outputDiscoverJSONL(writer, discoverResults)
		} else {
			outputDiscoverHuman(discoverResults, useColor)
		}
		return 0
	}

	// Enumerate mode
	cfg := &enum.Config{
		Emails:    emails,
		Services:  serviceList,
		Threads:   *threads,
		Timeout:   *timeout,
		RateLimit: *rateLimit,
		Jitter:    *jitter,
		Verbose:   *verbose,
	}

	if !*jsonOutput && !*quiet {
		enumPrintInfo(cfg, useColor)
	}

	results, err := enum.EnumerateWithContext(ctx, cfg)
	if err != nil {
		errMsg(useColor, "%v", err)
		return 1
	}

	if *jsonOutput {
		outputEnumJSONL(writer, results)
	} else {
		outputEnumHuman(results, useColor, *quiet)
	}

	// Exit 1 if no accounts found
	for i := range results {
		if results[i].Exists {
			return 0
		}
	}
	return 1
}

// loadEnumEmails loads emails from -e flag and/or -E file.
func loadEnumEmails(email, emailFile string) ([]string, error) {
	var emails []string

	if email != "" {
		emails = append(emails, strings.Split(email, ",")...)
	}

	if emailFile != "" {
		f, err := os.Open(emailFile)
		if err != nil {
			return nil, fmt.Errorf("opening email file: %w", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				emails = append(emails, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading email file: %w", err)
		}
	}

	return emails, nil
}

// enumListServices prints all registered enum services.
func enumListServices(useColor bool) {
	services := enum.ListPlugins()
	if len(services) == 0 {
		fmt.Println("No enum services registered.")
		return
	}
	fmt.Printf("%s\n", heading(useColor, "Available Enum Services"))
	for _, s := range services {
		fmt.Printf("  %s\n", s)
	}
	fmt.Printf("\n%d services available\n", len(services))
}

// enumPrintInfo displays enumeration configuration.
func enumPrintInfo(cfg *enum.Config, useColor bool) {
	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Enum Configuration"))
	fmt.Printf("  Emails:    %d\n", len(cfg.Emails))
	if len(cfg.Services) > 0 {
		fmt.Printf("  Services:  %s\n", strings.Join(cfg.Services, ", "))
	} else {
		fmt.Printf("  Services:  all (%d registered)\n", len(enum.ListPlugins()))
	}
	fmt.Printf("  Threads:   %d\n", cfg.Threads)
	fmt.Println()
}
