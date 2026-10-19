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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/internal/plugins/winrm"
	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
)

var (
	flagWinRMUser    string
	flagWinRMPass    string
	flagWinRMHTTPS   bool
	flagWinRMDelay   time.Duration
	flagWinRMWorkers int
)

var winrmCmd = &cobra.Command{
	Use:   "winrm",
	Short: "Spray one WinRM credential across hosts (lockout-safe access map)",
	Long: `Try one username/password against many WinRM hosts and report which
allow this account to open a shell.

This is not a password brute. It is the map from "these domain creds work" to
"these hosts actually allow this user over WinRM".

Verdicts:
  allowed          NTLM succeeded and a WinRM shell was created
  denied           NTLM succeeded but the shell was refused (not in Remote
                   Management Users, or a UAC-filtered local admin)
  bad credentials  HTTP 401 — wrong password; the spray aborts so badPwdCount
                   stops incrementing
  unreachable      no WinRM listener / timeout

A denied host does not increment badPwdCount. Use --https for winrms (5986).`,
	Example: `  # One host
  brutus winrm --target 10.0.0.5 -u CORP\\bob -p 'hunter2'

  # Many hosts
  brutus winrm --targets-file hosts.txt -u CORP\\bob -p 'hunter2'

  # HTTPS
  brutus winrm --targets-file hosts.txt -u bob -p 'hunter2' --https`,
	RunE: runWinRM,
}

func init() {
	f := winrmCmd.Flags()
	f.StringVarP(&flagWinRMUser, "username", "u", "", "Username (DOMAIN\\user or user)")
	f.StringVarP(&flagWinRMPass, "password", "p", "", "Password")
	f.BoolVar(&flagWinRMHTTPS, "https", false, "Use HTTPS WinRM (port 5986)")
	f.DurationVar(&flagWinRMDelay, "delay", 200*time.Millisecond, "Pause after each host attempt")
	f.IntVar(&flagWinRMWorkers, "workers", 4, "Concurrent probes (aborts on bad credentials)")
}

func runWinRM(_ *cobra.Command, _ []string) error {
	if flagWinRMUser == "" {
		return fmt.Errorf("--username is required")
	}
	if flagWinRMPass == "" {
		return fmt.Errorf("--password is required")
	}
	hosts, err := collectWinRMHosts()
	if err != nil {
		return err
	}

	workers := flagWinRMWorkers
	if workers <= 0 {
		workers = 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !flagJSON && !flagQuiet {
		fmt.Printf("spraying %s against %d hosts (%d workers, delay %s, timeout %s)\n",
			flagWinRMUser, len(hosts), workers, flagWinRMDelay, flagTimeout)
		fmt.Println("abort on bad credentials; access denied does not increment badPwdCount")
	}

	var allowed, denied, unreachable, other int
	enc := json.NewEncoder(os.Stdout)
	_, err = winrm.Spray(ctx, winrm.SprayConfig{
		Hosts:    hosts,
		Username: flagWinRMUser,
		Password: flagWinRMPass,
		Timeout:  flagTimeout,
		Delay:    flagWinRMDelay,
		Workers:  workers,
		HTTPS:    flagWinRMHTTPS,
		Each: func(r winrm.AccessReport) {
			switch r.Kind {
			case winrm.AccessAllowed:
				allowed++
			case winrm.AccessDenied:
				denied++
			case winrm.AccessUnreachable:
				unreachable++
			default:
				other++
			}
			if flagJSON {
				_ = enc.Encode(map[string]any{
					"host":   r.Host,
					"kind":   r.KindName(),
					"detail": r.Detail,
					"abort":  r.Kind.AbortsSpray(),
				})
				return
			}
			if flagQuiet && r.Kind != winrm.AccessAllowed {
				return
			}
			fmt.Println(r.String())
		},
	})

	if !flagJSON {
		fmt.Printf("summary: allowed=%d denied=%d unreachable=%d other=%d\n",
			allowed, denied, unreachable, other)
	}
	return err
}
func collectWinRMHosts() ([]string, error) {
	var hosts []string
	if flagTargetsFile != "" {
		list, err := brutusinput.LoadTargetsFromFile(flagTargetsFile)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, list...)
	}
	if flagTarget != "" {
		hosts = append(hosts, strings.TrimSpace(flagTarget))
	}
	seen := map[string]struct{}{}
	var out []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || strings.HasPrefix(h, "#") {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("provide --target or --targets-file")
	}
	return out, nil
}
