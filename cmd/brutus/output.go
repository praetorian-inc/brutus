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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// ANSI Color Constants
const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
	ColorDim    = "\033[2m"
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
)

// Output symbols (ASCII for compatibility)
const (
	SymbolSuccess = "[+]"
	SymbolError   = "[-]"
	SymbolWarning = "[!]"
	SymbolInfo    = "[*]"
	SymbolLLM     = "[AI]"
)

// ASCII Banner
const banner = `
    ____  ____  __  ____________  _______
   / __ )/ __ \/ / / /_  __/ / / / ___/
  / __  / /_/ / / / / / / / / / /\__ \
 / /_/ / _, _/ /_/ / / / / /_/ /___/ /
/_____/_/ |_|\____/ /_/  \____//____/

 Et tu, Brute?
 Praetorian Security, Inc.
`

// --- Color/formatting helpers ---

// colorIf returns the ANSI escape code when useColor is true, empty string otherwise.
func colorIf(useColor bool, code string) string {
	if useColor {
		return code
	}
	return ""
}

// heading returns text formatted as a bold section heading.
func heading(useColor bool, text string) string {
	if useColor {
		return ColorBold + text + ColorReset
	}
	return text
}

// highlight returns text formatted with purple/highlight color.
func highlight(useColor bool, text string) string {
	if useColor {
		return ColorPurple + text + ColorReset
	}
	return text
}

// dim returns text formatted with dim/muted color.
func dim(useColor bool, text string) string {
	if useColor {
		return ColorDim + text + ColorReset
	}
	return text
}

// errMsg prints a colored error message to stderr.
func errMsg(useColor bool, format string, args ...any) {
	if useColor {
		fmt.Fprintf(os.Stderr, ColorRed+SymbolError+" Error: "+ColorReset+format+"\n", args...)
	} else {
		fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	}
}

// warnMsg prints a colored warning message to stderr.
func warnMsg(useColor bool, format string, args ...any) {
	if useColor {
		fmt.Fprintf(os.Stderr, ColorYellow+SymbolWarning+" Warning: "+ColorReset+format+"\n", args...)
	} else {
		fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
	}
}

// logVerbose writes a formatted verbose message to stderr when verbose is true.
func logVerbose(verbose bool, format string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", args...)
	}
}

// --- Banner and version display ---

// printBanner displays the ASCII art banner with color
func printBanner(useColor bool) {
	if useColor {
		fmt.Printf("%s%s%s%s\n", ColorBold, ColorRed, banner, ColorReset)
	} else {
		fmt.Printf("%s\n", banner)
	}
}

// printVersion displays version information with color
func printVersion(useColor bool) {
	switch {
	case useColor:
		fmt.Printf("%sBrutus %s%s\n", ColorBold, Version, ColorReset)
		fmt.Printf("  %sBuild time:%s %s\n", ColorCyan, ColorReset, BuildTime)
		fmt.Printf("  %sCommit:%s     %s\n", ColorCyan, ColorReset, CommitSHA)
		fmt.Printf("  %sGo version:%s %s\n", ColorCyan, ColorReset, runtime.Version())
		fmt.Printf("  %sOS/Arch:%s    %s/%s\n", ColorCyan, ColorReset, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Printf("Brutus %s\n", Version)
		fmt.Printf("  Build time: %s\n", BuildTime)
		fmt.Printf("  Commit:     %s\n", CommitSHA)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	}
}

// printTargetInfo displays target configuration details
func printTargetInfo(target, protocol string, base *runConfig, aiCreds []brutus.Credential) {
	useColor := base.useColor

	isBrowserAI := protocol == "browser"
	isHTTPAI := (protocol == "http" || protocol == "https") && base.aiMode && len(aiCreds) > 0
	isAIMode := isBrowserAI || isHTTPAI

	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Target Information"))
	fmt.Printf("  Target:      %s\n", target)
	fmt.Printf("  Protocol:    %s\n", protocol)

	switch {
	case isBrowserAI:
		fmt.Printf("  Credentials: %s\n", highlight(useColor, "AI Discovery (Claude Vision + Perplexity)"))
	case isHTTPAI:
		fmt.Printf("  Credentials: %s\n", highlight(useColor, "AI Discovery (Perplexity) + admin:admin"))
	default:
		fmt.Printf("  Users:       %d\n", len(base.usernames))
		fmt.Printf("  Passwords:   %d\n", len(base.passwords))
		if len(base.keys) > 0 {
			fmt.Printf("  SSH Keys:    %d\n", len(base.keys))
		}
	}

	if base.llmConfig != nil && base.llmConfig.Enabled && !isAIMode {
		fmt.Printf("  LLM:         %s\n", highlight(useColor, base.llmConfig.Provider+" enabled"))
	} else if !isAIMode {
		fmt.Printf("  LLM:         %s\n", dim(useColor, "disabled"))
	}
	fmt.Printf("  Threads:     %d\n", base.threads)
	fmt.Println()
}

// --- Result output formatters ---

// printSummary prints the results summary to stdout.
func printSummary(validCount, invalidCount, errorCount, total int, useColor bool) {
	if useColor {
		fmt.Printf("\n%s\n", heading(useColor, "Results Summary"))
		if validCount > 0 {
			fmt.Printf("  %sValid:%s     %d\n", ColorGreen, ColorReset, validCount)
		}
		if invalidCount > 0 {
			fmt.Printf("  %sInvalid:%s   %d\n", ColorDim, ColorReset, invalidCount)
		}
		if errorCount > 0 {
			fmt.Printf("  %sErrors:%s    %d\n", ColorRed, ColorReset, errorCount)
		}
		fmt.Printf("  %sTotal:%s     %d\n", ColorCyan, ColorReset, total)
	} else {
		fmt.Printf("Results: %d valid, %d invalid, %d errors (total: %d)\n",
			validCount, invalidCount, errorCount, total)
	}

	if errorCount > 5 {
		if useColor {
			fmt.Printf("\n%s%s Suppressed %d additional errors%s\n", ColorYellow, SymbolWarning, errorCount-5, ColorReset)
		} else {
			fmt.Printf("(Suppressed %d additional errors)\n", errorCount-5)
		}
	}
}

func outputHuman(results []brutus.Result, useColor, quiet bool) {
	validCount := 0
	invalidCount := 0
	errorCount := 0
	skippedUnauth := 0

	for i := range results {
		r := &results[i]
		switch {
		case r.Success:
			// Unauthenticated findings are reported in the Security Findings section, not as credentials
			if r.Username == "(unauthenticated)" {
				skippedUnauth++
				continue
			}
			validCount++
			fmt.Printf("%s[+] VALID: %s %s:%s @ %s (%s)%s\n",
				colorIf(useColor, ColorGreen), r.Protocol, r.Username, r.Password, r.Target, r.Duration, colorIf(useColor, ColorReset))
			if r.LLMSuggested {
				fmt.Printf("    %s\n", highlight(useColor, "(LLM-suggested)"))
			}
		case r.Error != nil:
			errorCount++
			if !quiet && errorCount <= 5 {
				fmt.Printf("%s%s ERROR:%s %s:%s @ %s - %v\n",
					colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset), r.Username, r.Password, r.Target, r.Error)
			}
		default:
			invalidCount++
		}
	}

	// Print security findings from banners (e.g., sticky keys detection)
	// These appear regardless of auth success since they are pre-auth findings.
	for i := range results {
		r := &results[i]
		if r.Banner != "" && hasSecurityFinding(r.Banner) {
			fmt.Printf("\n%s\n", heading(useColor, "Security Findings"))
			fmt.Printf("  %s @ %s\n", r.Protocol, r.Target)
			for _, line := range splitLines(r.Banner) {
				fmt.Printf("  %s\n", line)
			}
			break // One findings block per target
		}
	}

	if !quiet || validCount > 0 {
		printSummary(validCount, invalidCount, errorCount, len(results)-skippedUnauth, useColor)
	}
}

// outputValidOnly prints only successful credentials (for pipeline/large-scale scanning)
func outputValidOnly(results []brutus.Result, useColor bool) {
	for i := range results {
		r := &results[i]
		if r.Success {
			// Skip unauthenticated findings — they are security findings, not credentials
			if r.Username == "(unauthenticated)" {
				continue
			}
			// Simple, parseable format: protocol username:password@target or protocol username:key@target
			cred := r.Username
			if r.Password != "" {
				cred += ":" + r.Password
			} else if len(r.Key) > 0 {
				cred += ":key"
			}
			if useColor {
				fmt.Printf("%s%s %s@%s%s\n", ColorGreen, r.Protocol, cred, r.Target, ColorReset)
			} else {
				fmt.Printf("%s %s@%s\n", r.Protocol, cred, r.Target)
			}
		}
	}
}

// outputJSONL streams successful results as JSONL (one JSON object per line)
// This matches the output format of naabu and nerva for easy piping
func outputJSONL(w io.Writer, results []brutus.Result) {
	type JSONResult struct {
		Protocol     string `json:"protocol"`
		Target       string `json:"target"`
		Username     string `json:"username"`
		Password     string `json:"password,omitempty"`
		Key          bool   `json:"key,omitempty"`
		Duration     string `json:"duration"`
		Banner       string `json:"banner,omitempty"`
		LLMSuggested bool   `json:"llm_suggested,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		if !r.Success {
			continue // Only output successful auths
		}
		// Unauthenticated findings are emitted separately below
		if r.Username == "(unauthenticated)" {
			continue
		}
		jr := JSONResult{
			Protocol:     r.Protocol,
			Target:       r.Target,
			Username:     r.Username,
			Password:     r.Password,
			Key:          len(r.Key) > 0,
			Duration:     r.Duration.String(),
			Banner:       r.Banner,
			LLMSuggested: r.LLMSuggested,
		}
		if err := enc.Encode(jr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		}
	}

	// Output security findings regardless of auth success
	type FindingResult struct {
		Protocol string `json:"protocol"`
		Target   string `json:"target"`
		Finding  string `json:"finding"`
		Banner   string `json:"banner"`
	}
	findingEmitted := make(map[string]bool)
	for i := range results {
		r := &results[i]
		key := r.Protocol + "|" + r.Target
		// Unauthenticated access findings
		if r.Success && r.Username == "(unauthenticated)" && r.Banner != "" {
			fr := FindingResult{
				Protocol: r.Protocol,
				Target:   r.Target,
				Finding:  "unauthenticated_access",
				Banner:   r.Banner,
			}
			if err := enc.Encode(fr); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			}
			findingEmitted[key] = true
			continue
		}
		// Other security findings (e.g., sticky keys detection)
		if !findingEmitted[key] && r.Banner != "" && hasSecurityFinding(r.Banner) {
			fr := FindingResult{
				Protocol: r.Protocol,
				Target:   r.Target,
				Finding:  "security",
				Banner:   r.Banner,
			}
			if err := enc.Encode(fr); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			}
			findingEmitted[key] = true
		}
	}
}

// --- Scan output formatters ---

// outputScanHuman writes scan results in human-readable format.
func outputScanHuman(results []brutus.Result, useColor bool) {
	for i := range results {
		r := &results[i]
		scanType := "Sticky Keys Scan" // default
		switch r.ScanType {
		case "utilman":
			scanType = "Utilman Scan"
		case "sticky_keys":
			scanType = "Sticky Keys Scan"
		}

		finding := extractFinding(r.Banner)
		color, symbol := ColorCyan, SymbolInfo
		switch finding {
		case "[CRITICAL]":
			color, symbol = ColorRed, SymbolError
		case "[HIGH]":
			color, symbol = ColorYellow, SymbolWarning
		case "[WARN]":
			color, symbol = ColorYellow, SymbolWarning
		}

		if useColor {
			fmt.Printf("%s%s %s: %s%s  %s\n", color, symbol, scanType, r.Target, ColorReset, r.Banner)
		} else {
			fmt.Printf("%s: %s  %s\n", scanType, r.Target, r.Banner)
		}
	}
}

// outputScanJSONL writes scan results as JSONL for pipeline consumption.
func outputScanJSONL(w io.Writer, results []brutus.Result) {
	type ScanResult struct {
		Protocol      string `json:"protocol"`
		Target        string `json:"target"`
		ScanType      string `json:"scan_type"`
		Finding       string `json:"finding"`
		Banner        string `json:"banner"`
		Success       bool   `json:"success"`
		Indeterminate bool   `json:"indeterminate"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		scanType := r.ScanType
		if scanType == "" {
			scanType = "sticky_keys" // default for backward compatibility
		}
		sr := ScanResult{
			Protocol:      r.Protocol,
			Target:        r.Target,
			ScanType:      scanType,
			Finding:       extractFinding(r.Banner),
			Banner:        r.Banner,
			Success:       r.Success,
			Indeterminate: r.Indeterminate,
		}
		if err := enc.Encode(sr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding scan JSON: %v\n", err)
		}
	}
}

// --- Helpers ---

// hasSecurityFinding checks if a banner contains security-relevant findings.
func hasSecurityFinding(banner string) bool {
	return strings.Contains(banner, "[CRITICAL]") ||
		strings.Contains(banner, "[HIGH]") ||
		strings.Contains(banner, "[INFO] Sticky keys")
}

// splitLines splits a string into non-empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// extractFinding extracts the severity tag from a banner string.
func extractFinding(banner string) string {
	for _, tag := range []string{"[CRITICAL]", "[HIGH]", "[WARN]", "[INFO]"} {
		if strings.Contains(banner, tag) {
			return tag
		}
	}
	return ""
}
