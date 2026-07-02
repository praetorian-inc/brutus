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

	pb "github.com/praetorian-inc/brutus/pkg/enum/phantombuster"
)

var (
	flagLinkedinAgentID    string
	flagLinkedinAPIKey     string
	flagLinkedinResultFile string
	flagLinkedinSkipLaunch bool
)

func newEnumLinkedinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "linkedin",
		Short: "Scrape LinkedIn Sales Navigator profiles via PhantomBuster",
		Long: `Launch a pre-configured PhantomBuster Sales Navigator scraper, poll until
the run completes, and fetch the scraped profiles. The agent must already be
configured in the PhantomBuster UI with its script, LinkedIn session cookie,
and search parameters set. This command controls execution only.

Output is a roster of people (name, title, department, company, LinkedIn URL)
— no email addresses. Candidate email generation from these names is handled
downstream by the email-pattern inference pipeline (enum generate).

Requires a PhantomBuster API key via the PHANTOMBUSTER_KEY environment variable
(or the --api-key flag).

Authorized use only: respect LinkedIn's Terms of Service and only enumerate
targets you are authorized to assess.`,
		Example: `  # Launch a Sales Nav scraper and fetch results
  brutus enum passive linkedin --agent-id 1234567890

  # Fetch results from a previous run (skip launching a new one)
  brutus enum passive linkedin --agent-id 1234567890 --skip-launch

  # Specify a custom result filename
  brutus enum passive linkedin --agent-id 1234567890 --result-file result.json

  # Provide the key explicitly (note: visible in process list / shell history)
  brutus enum passive linkedin --agent-id 1234567890 --api-key abc123`,
		RunE: runEnumLinkedin,
	}

	f := cmd.Flags()
	f.StringVar(&flagLinkedinAgentID, "agent-id", "",
		"PhantomBuster agent ID for the Sales Navigator scraper (required)")
	f.StringVar(&flagLinkedinAPIKey, "api-key", "",
		"PhantomBuster API key (overrides PHANTOMBUSTER_KEY; WARNING: visible in process list and shell history — prefer PHANTOMBUSTER_KEY)")
	f.StringVar(&flagLinkedinResultFile, "result-file", "result.csv",
		"Result filename to download from S3 (default: result.csv)")
	f.BoolVar(&flagLinkedinSkipLaunch, "skip-launch", false,
		"Skip launching the agent — fetch results from the most recent run instead")
	_ = cmd.MarkFlagRequired("agent-id")

	return cmd
}

func runEnumLinkedin(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	apiKey, err := resolvePhantomBusterKey(flagLinkedinAPIKey)
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

	client := pb.NewClient(apiKey, flagTimeout)

	var resultData []byte

	if flagLinkedinSkipLaunch {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Fetching results from previous run (agent %s)...\n",
				dim(useColor, SymbolInfo), flagLinkedinAgentID)
		}
		info, err := client.FetchAgentInfo(ctx, flagLinkedinAgentID)
		if err != nil {
			return classifyPhantomBusterError(err)
		}
		resultData, err = client.DownloadResult(ctx, info, flagLinkedinResultFile)
		if err != nil {
			return classifyPhantomBusterError(err)
		}
	} else {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Launching PhantomBuster agent %s...\n",
				dim(useColor, SymbolInfo), flagLinkedinAgentID)
		}

		onProgress := func(status pb.OutputStatus) {
			if flagQuiet || flagJSON {
				return
			}
			if status.Progress != nil {
				pct, _ := status.Progress.Value.Float64()
				fmt.Fprintf(os.Stderr, "\r%s Progress: %.0f%% %s",
					dim(useColor, SymbolInfo),
					pct*100,
					status.Progress.Label)
			}
		}

		resultData, err = client.RunAndFetch(ctx, flagLinkedinAgentID, flagLinkedinResultFile, onProgress)
		if err != nil {
			return classifyPhantomBusterError(err)
		}

		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "\n")
		}
	}

	result, err := pb.ParseSalesNavCSV(resultData)
	if err != nil {
		return fmt.Errorf("parsing Sales Navigator results: %w", err)
	}
	result.AgentID = flagLinkedinAgentID

	logVerbose(flagVerbose, "LinkedIn returned %d profiles", result.Total)

	if flagJSON {
		outputLinkedinJSONL(jsonWriter, result)
	} else {
		outputLinkedinHuman(os.Stdout, result, useColor)
	}

	return nil
}

func resolvePhantomBusterKey(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if key := os.Getenv("PHANTOMBUSTER_KEY"); key != "" {
		return key, nil
	}
	return "", fmt.Errorf("PhantomBuster API key required: set PHANTOMBUSTER_KEY or pass --api-key")
}

func classifyPhantomBusterError(err error) error {
	switch {
	case errors.Is(err, pb.ErrUnauthorized):
		return fmt.Errorf("phantombuster: invalid or missing API key (check PHANTOMBUSTER_KEY / --api-key)")
	case errors.Is(err, pb.ErrNotFound):
		return fmt.Errorf("phantombuster: agent not found (check --agent-id)")
	case errors.Is(err, pb.ErrRateLimited):
		return fmt.Errorf("phantombuster: rate limit exceeded — wait and retry")
	case errors.Is(err, pb.ErrAgentFailed):
		return fmt.Errorf("phantombuster: %w", err)
	}
	return fmt.Errorf("phantombuster: %w", err)
}
