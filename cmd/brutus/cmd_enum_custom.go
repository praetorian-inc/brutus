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
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/custom"
)

// maxSpecBytes caps the oracle spec file size before reading (security-lead
// R8/P0-7). A spec is a few KB; 1 MB is generous.
const maxSpecBytes = 1 << 20

// File-local flag variables for the custom subcommand (avoid cross-command
// state bleed, like the hunter subcommand).
var (
	flagCustomFile      string // -f / --file (required)
	flagCustomEmails    string // -e
	flagCustomEmailFile string // -E
	flagCustomGenerate  bool   // --generate
)

var enumCustomCmd = &cobra.Command{
	Use:   "custom",
	Short: "Run a declaratively-described enumeration oracle from a spec file",
	Long: `Run an enumeration oracle described declaratively in a JSON or YAML spec
file (schema v1) — no Go required. The spec defines the HTTP request to send for
each subject and an ordered set of match rules that map the response to an
exists/absent/error verdict, then runs through the existing enum pipeline.

Subjects come from --emails/-e, --email-file/-E, or --generate. Only http/https
URLs are allowed; placeholder substitution is encoding-aware and redirects are
not followed.`,
	Example: `  # Run an oracle against inline subjects
  brutus enum active custom -f oracle.json -e jsmith,asmith

  # Run against a subject file
  brutus enum active custom -f oracle.yaml -E users.txt

  # Generate usernames and run
  brutus enum active custom -f oracle.json --generate --format flast

  # JSON output to a file
  brutus enum active custom -f oracle.json -e jsmith -o results.jsonl`,
	RunE: runEnumCustom,
}

func init() {
	f := enumCustomCmd.Flags()
	f.StringVarP(&flagCustomFile, "file", "f", "", "Oracle spec file (JSON or YAML, required)")
	f.StringVarP(&flagCustomEmails, "emails", "e", "", "Comma-separated subjects (usernames or emails) to enumerate")
	f.StringVarP(&flagCustomEmailFile, "email-file", "E", "", "File of subjects to enumerate (one per line, use - for stdin)")
	f.BoolVar(&flagCustomGenerate, "generate", false, "Generate subjects from embedded name lists")
	f.StringVar(&flagEnumFormat, "format", "first.last", "Username format for generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain for email generation (with --generate)")
	_ = enumCustomCmd.MarkFlagRequired("file")
}

// runEnumCustom implements the "enum active custom" subcommand.
func runEnumCustom(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	spec, err := loadOracleSpec(flagCustomFile)
	if err != nil {
		return err
	}
	plugin := custom.New(spec)

	subjects, err := buildCustomSubjects()
	if err != nil {
		return err
	}
	if len(subjects) == 0 {
		return fmt.Errorf("no subjects: provide -e/-E or --generate")
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

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	cfg := &enum.Config{
		Emails:    subjects,
		Threads:   flagThreads,
		Timeout:   flagTimeout,
		RateLimit: flagRateLimit,
		Jitter:    flagJitter,
		Verbose:   flagVerbose,
		ProxyURL:  proxyURL,
	}
	// Apply the spec's rate-limit hint as a default only when the operator did
	// not explicitly set --rate-limit (operator overrides).
	if spec.Constraints != nil && spec.Constraints.RateLimitRPS > 0 && !isFlagChanged(cmd, "rate-limit") {
		cfg.RateLimit = spec.Constraints.RateLimitRPS
	}

	results, err := enum.EnumerateWithPlugin(ctx, cfg, plugin)
	if err != nil {
		return err
	}

	if flagJSON {
		outputEnumJSONL(jsonWriter, results)
	} else {
		outputEnumHuman(results, useColor)
	}
	return nil
}

// loadOracleSpec stats, size-caps, reads, parses, and validates the spec file.
func loadOracleSpec(path string) (*custom.Spec, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec file: %w", err)
	}
	if info.Size() > maxSpecBytes {
		return nil, fmt.Errorf("spec file too large: %d bytes (max %d)", info.Size(), maxSpecBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening spec file: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxSpecBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading spec file: %w", err)
	}
	if int64(len(data)) > maxSpecBytes {
		return nil, fmt.Errorf("spec file too large: more than %d bytes", maxSpecBytes)
	}

	spec, err := custom.Parse(data)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return spec, nil
}

// buildCustomSubjects assembles the ordered subject list from CLI flags
// (-e/-E/--generate), de-duplicated and preserving first-seen order.
func buildCustomSubjects() ([]string, error) {
	var subjects []string

	if flagCustomEmails != "" {
		for _, e := range strings.Split(flagCustomEmails, ",") {
			if e = strings.TrimSpace(e); e != "" {
				subjects = append(subjects, e)
			}
		}
	}

	if flagCustomEmailFile != "" {
		fileSubjects, err := loadLinesFromFile(flagCustomEmailFile)
		if err != nil {
			return nil, fmt.Errorf("loading subject file: %w", err)
		}
		subjects = append(subjects, fileSubjects...)
	}

	if flagCustomGenerate {
		generated, err := generateCustomSubjects()
		if err != nil {
			return nil, err
		}
		subjects = append(subjects, generated...)
	}

	return dedupe(subjects), nil
}

// generateCustomSubjects generates usernames or emails depending on whether a
// domain was provided.
func generateCustomSubjects() ([]string, error) {
	if flagEnumDomain == "" {
		usernames, err := enum.GenerateUsernames(flagEnumFormat)
		if err != nil {
			return nil, fmt.Errorf("generating usernames: %w", err)
		}
		return usernames, nil
	}
	emails, err := enum.GenerateEmails(flagEnumFormat, flagEnumDomain)
	if err != nil {
		return nil, fmt.Errorf("generating emails: %w", err)
	}
	return emails, nil
}

// dedupe removes duplicate subjects while preserving first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
