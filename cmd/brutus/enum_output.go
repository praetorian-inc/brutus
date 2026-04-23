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

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// jsonEnumResult is the JSONL output shape for enum results.
type jsonEnumResult struct {
	Service    string `json:"service"`
	Email      string `json:"email"`
	Exists     bool   `json:"exists"`
	Confidence string `json:"confidence,omitempty"`
	Error      string `json:"error,omitempty"`
	Duration   string `json:"duration"`
}

// jsonOracleResult is the JSONL output shape for oracle discovery results.
type jsonOracleResult struct {
	Service    string `json:"service"`
	IsOracle   bool   `json:"is_oracle"`
	Confidence string `json:"confidence,omitempty"`
	Method     string `json:"method,omitempty"`
	Error      string `json:"error,omitempty"`
}

// outputEnumHuman prints enumeration results in human-readable format.
func outputEnumHuman(results []enum.Result, useColor, quiet bool) {
	existsCount := 0
	notFoundCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			errorCount++
			if !quiet && errorCount <= 5 {
				fmt.Printf("%s%s ERROR:%s %s @ %s - %v\n",
					colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
					r.Email, r.Service, r.Error)
			}
		case r.Exists:
			existsCount++
			fmt.Printf("%s%s EXISTS:%s %s @ %s (confidence: %s, %s)%s\n",
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
				r.Email, r.Service, r.Confidence, r.Duration, colorIf(useColor, ColorReset))
		default:
			notFoundCount++
			if !quiet {
				fmt.Printf("%s%s %s @ %s%s\n",
					colorIf(useColor, ColorDim), dim(useColor, "[ ] NOT FOUND:"),
					r.Email, r.Service, colorIf(useColor, ColorReset))
			}
		}
	}

	if !quiet || existsCount > 0 {
		enumPrintSummary(existsCount, notFoundCount, errorCount, len(results), useColor)
	}
}

// enumPrintSummary prints the enum results summary.
func enumPrintSummary(existsCount, notFoundCount, errorCount, total int, useColor bool) {
	if useColor {
		fmt.Printf("\n%s\n", heading(useColor, "Enum Results"))
		if existsCount > 0 {
			fmt.Printf("  %sExists:%s     %d\n", ColorGreen, ColorReset, existsCount)
		}
		if notFoundCount > 0 {
			fmt.Printf("  %sNot Found:%s  %d\n", ColorDim, ColorReset, notFoundCount)
		}
		if errorCount > 0 {
			fmt.Printf("  %sErrors:%s     %d\n", ColorRed, ColorReset, errorCount)
		}
		fmt.Printf("  %sTotal:%s      %d\n", ColorCyan, ColorReset, total)
	} else {
		fmt.Printf("Enum: %d exists, %d not found, %d errors (total: %d)\n",
			existsCount, notFoundCount, errorCount, total)
	}
}

// outputEnumJSONL streams enum results as JSONL.
func outputEnumJSONL(w io.Writer, results []enum.Result) {
	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		jr := jsonEnumResult{
			Service:    r.Service,
			Email:      r.Email,
			Exists:     r.Exists,
			Confidence: string(r.Confidence),
			Duration:   r.Duration.String(),
		}
		if r.Error != nil {
			jr.Error = r.Error.Error()
		}
		if err := enc.Encode(jr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding enum JSON: %v\n", err)
		}
	}
}

// outputDiscoverHuman prints oracle discovery results in human-readable format.
func outputDiscoverHuman(results []enum.OracleResult, useColor bool) {
	oracleCount := 0

	fmt.Printf("\n%s\n", heading(useColor, "Oracle Discovery Results"))

	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			fmt.Printf("  %s%s ERROR:%s %s - %v\n",
				colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
				r.Service, r.Error)
		case r.IsOracle:
			oracleCount++
			fmt.Printf("  %s%s ORACLE:%s %s (confidence: %s, method: %s)\n",
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
				r.Service, r.Confidence, r.Method)
		default:
			fmt.Printf("  %s%s %s%s\n",
				colorIf(useColor, ColorDim), dim(useColor, "[ ] NOT ORACLE:"),
				r.Service, colorIf(useColor, ColorReset))
		}
	}

	fmt.Printf("\n%d/%d services act as enumeration oracles\n", oracleCount, len(results))
}

// outputDiscoverJSONL streams oracle discovery results as JSONL.
func outputDiscoverJSONL(w io.Writer, results []enum.OracleResult) {
	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		jr := jsonOracleResult{
			Service:    r.Service,
			IsOracle:   r.IsOracle,
			Confidence: string(r.Confidence),
			Method:     r.Method,
		}
		if r.Error != nil {
			jr.Error = r.Error.Error()
		}
		if err := enc.Encode(jr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding oracle JSON: %v\n", err)
		}
	}
}
