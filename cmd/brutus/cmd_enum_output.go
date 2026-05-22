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

// outputDNSReconHuman displays DNS TXT recon results in human-readable format.
func outputDNSReconHuman(result *enum.DNSReconResult, useColor bool) {
	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "DNS TXT Recon: "+result.Domain))
	fmt.Printf("  Records found: %d\n", len(result.Records))

	if len(result.Services) == 0 {
		fmt.Printf("  %s No SaaS services identified from TXT records\n", dim(useColor, SymbolInfo))
		return
	}

	fmt.Printf("\n  %s\n", heading(useColor, "Discovered Services"))
	for _, svc := range result.Services {
		fmt.Printf("    %s%-16s%s %s\n",
			colorIf(useColor, ColorGreen), svc.Name, colorIf(useColor, ColorReset),
			dim(useColor, "("+svc.Indicator+")"))
	}
	fmt.Println()
}

// outputDNSReconJSONL writes DNS recon results as JSONL.
func outputDNSReconJSONL(w io.Writer, result *enum.DNSReconResult) {
	type dnsReconJSON struct {
		Type     string   `json:"type"`
		Domain   string   `json:"domain"`
		Records  []string `json:"records"`
		Services []struct {
			Name      string `json:"name"`
			Indicator string `json:"indicator"`
		} `json:"services"`
	}

	jr := dnsReconJSON{
		Type:    "dns_recon",
		Domain:  result.Domain,
		Records: result.Records,
	}
	for _, svc := range result.Services {
		jr.Services = append(jr.Services, struct {
			Name      string `json:"name"`
			Indicator string `json:"indicator"`
		}{Name: svc.Name, Indicator: svc.Indicator})
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(jr); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding DNS recon JSON: %v\n", err)
	}
}

// outputEnumHuman displays enumeration results in human-readable format.
func outputEnumHuman(results []enum.Result, useColor bool) {
	if len(results) == 0 {
		return
	}

	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Enumeration Results"))

	existsCount := 0
	notExistsCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			errorCount++
			if flagVerbose {
				fmt.Printf("  %s%s ERROR%s  %-40s %-16s %v\n",
					colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
					r.Email, r.Service, r.Error)
			}
		case r.Exists:
			existsCount++
			fmt.Printf("  %s%s EXISTS%s %-40s %-16s %s(%s, %s)%s\n",
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
				r.Email, r.Service,
				colorIf(useColor, ColorDim), r.Confidence, r.Duration, colorIf(useColor, ColorReset))
		default:
			notExistsCount++
			if !flagQuiet {
				fmt.Printf("  %s[ ] NOT FOUND%s %-36s %-16s %s(%s)%s\n",
					colorIf(useColor, ColorDim), colorIf(useColor, ColorReset),
					r.Email, r.Service,
					colorIf(useColor, ColorDim), r.Duration, colorIf(useColor, ColorReset))
			}
		}
	}

	// Summary
	fmt.Printf("\n  %s\n", heading(useColor, "Summary"))
	if existsCount > 0 {
		fmt.Printf("    %sExists:%s     %d\n", colorIf(useColor, ColorGreen), colorIf(useColor, ColorReset), existsCount)
	}
	if notExistsCount > 0 {
		fmt.Printf("    %sNot found:%s  %d\n", colorIf(useColor, ColorDim), colorIf(useColor, ColorReset), notExistsCount)
	}
	if errorCount > 0 {
		fmt.Printf("    %sErrors:%s     %d\n", colorIf(useColor, ColorRed), colorIf(useColor, ColorReset), errorCount)
	}
	fmt.Printf("    %sTotal:%s      %d\n", colorIf(useColor, ColorCyan), colorIf(useColor, ColorReset), len(results))
	fmt.Println()
}

// outputOracleValidationHuman displays oracle validation results.
func outputOracleValidationHuman(results []enum.Result, useColor bool) {
	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Oracle Validation"))
	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			fmt.Printf("  %s%s FAIL%s    %-16s %v\n",
				colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
				r.Service, r.Error)
		case r.Exists:
			fmt.Printf("  %s%s PASS%s    %-16s confirmed (%s, %s)\n",
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
				r.Service, r.Confidence, r.Duration)
		default:
			fmt.Printf("  %s%s FAIL%s    %-16s did not confirm known-valid email (%s)\n",
				colorIf(useColor, ColorYellow), SymbolWarning, colorIf(useColor, ColorReset),
				r.Service, r.Duration)
		}
	}
	fmt.Println()
}

// outputEnumJSONL writes enumeration results as JSONL.
func outputEnumJSONL(w io.Writer, results []enum.Result) {
	type enumResultJSON struct {
		Type       string `json:"type"`
		Service    string `json:"service"`
		Email      string `json:"email"`
		Exists     bool   `json:"exists"`
		Confidence string `json:"confidence,omitempty"`
		Error      string `json:"error,omitempty"`
		Duration   string `json:"duration"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		jr := enumResultJSON{
			Type:       "enum",
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
