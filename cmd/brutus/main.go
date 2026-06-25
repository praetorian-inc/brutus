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
	"errors"
	"fmt"
	"os"

	// Import plugins and analyzers to register them
	_ "github.com/praetorian-inc/brutus/internal/analyzers"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins"
	_ "github.com/praetorian-inc/brutus/internal/plugins"
)

// Version info - set by ldflags during build
var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

// errNoSuccess is a sentinel error returned when all targets were tested
// but none succeeded. It signals main() to exit with code 1 without
// printing an error message.
var errNoSuccess = errors.New("no successful credentials found")

// errIndeterminate is a sentinel error returned when a scan completed but at
// least one host produced an indeterminate result (e.g. CPU-starved render or
// failed connect) and nothing succeeded. It signals main() to exit with code 2
// (distinct from a clean-nothing exit 1) so callers can rerun the affected hosts.
var errIndeterminate = errors.New("indeterminate results; rerun")

func main() {
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, errIndeterminate) {
			os.Exit(2)
		}
		if errors.Is(err, errNoSuccess) {
			os.Exit(1)
		}
		useColor := isColorEnabled(flagNoColor)
		errMsg(useColor, "%v", err)
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}
}
