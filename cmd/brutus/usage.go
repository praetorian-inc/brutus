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
	"fmt"
	"os"
)

// customUsage displays custom help message
func customUsage() {
	fmt.Fprintf(os.Stderr, `Brutus - Et tu, Brute?

Usage:
  brutus --target <host:port> --protocol <proto> [options]                # Single target mode
  naabu ... | nerva --json | brutus [options]                      # Pipeline mode (stdin auto-detected)
  naabu ... | nerva --json | brutus --experimental-ai [options]                 # AI-powered credential detection

Target Options:
  --target <host:port>   Target host and port (requires --protocol)
  --nerva         Read targets from nerva JSON on stdin
  --protocol <proto>     Protocol to use (auto-detected in pipeline mode)

Credential Options:
  -u <usernames>         Comma-separated usernames (default: "root,admin")
  -U <file>              Username file (one per line)
  -p <passwords>         Comma-separated passwords
  -P <file>              Password file (one per line)
  -k <keyfile>           SSH private key file

SSH Options:
  --badkeys-only         Only test bad SSH keys (skip password wordlists and non-SSH protocols)
  --no-badkeys           Disable embedded bad key testing (badkeys are tested by default for SSH)

RDP Options:
  --sticky-keys          Enable sticky keys backdoor detection for RDP targets
  --sticky-keys-exec <cmd>  Execute a command via sticky keys backdoor (demo/pentest)
  --sticky-keys-web      Start interactive web terminal via sticky keys backdoor
  --sticky-keys-open     Auto-open default browser for sticky keys web terminal

Performance Options:
  -t <threads>           Number of concurrent threads (default: 10)
  --timeout <duration>   Per-credential timeout (default: 10s)
  --stop-on-success      Stop after first valid credential (default: true)
  --rate-limit <rps>     Max requests per second (0 = unlimited, default: 0)
  --jitter <duration>    Random delay variance for rate limiting (e.g., 100ms)
  --max-attempts <n>     Max password attempts per user (0 = unlimited, default: 0)
  --spray                Password spraying: try each password across all users
  --retries <n>          Max retries per credential on connection error (default: 2, 0 = disabled)

Output Options:
  --json                 JSON output format
  -o <file>              Output file for JSON results (implies --json)
  --banner               Show ASCII banner (default: true)
  --no-color             Disable colored output
  -q                     Quiet mode - only show successful credentials
  -v                     Verbose mode - show detailed progress (to stderr)

SNMP Options:

TLS Options:
  --verify-tls           Require strict TLS certificate verification (default: disabled)
                         Note: Default is no TLS/SSL validation since we're testing
                         default credentials. nerva TLS detection auto-upgrades
                         to skip-verify mode when TLS is detected.
  --snmp-tier <tier>     SNMP community string tier: default (20), extended (50), full (120)

AI Options (automatic credential detection for HTTP services):
  --experimental-ai                          AI-powered credential detection:
                                  - Claude Vision identifies devices and suggests credentials
                                  - Perplexity (optional) searches for additional credentials online

                                  For HTTP Basic Auth: analyzes headers, researches credentials
                                  For form-based login: screenshot analysis + credential research

                                  Requires: ANTHROPIC_API_KEY (Claude Vision)
                                  Optional: PERPLEXITY_API_KEY (additional web search)
                                  (Non-HTTP protocols like SSH are unaffected)
  --experimental-ai-verify                   Use Claude Vision to verify login success by comparing
                                  before/after screenshots (more accurate but slower/costlier)
  --browser-timeout <duration>  Total timeout for browser operations (default: 60s)
  --browser-tabs <n>            Number of concurrent browser tabs (default: 3)
  --browser-visible             Show browser window for debugging/demo (default: headless)
  --https                       Use HTTPS for browser connections

Other Options:
  --version              Show version information
  -h, --help             Show this help message

Nerva Integration:
  Brutus integrates seamlessly with nerva for automated service discovery
  and credential testing. Use naabu for port discovery, nerva for service
  fingerprinting (with --json output), then pipe to Brutus:

    naabu -host <targets> -silent | nerva --json | brutus --nerva [options]

  For known open ports, pipe directly to nerva:

    echo "host:port" | nerva --json | brutus --nerva [options]

  Brutus automatically detects protocols from nerva JSON output,
  eliminating the need to specify -protocol manually.

Supported Protocols:
  Network:      ssh, rdp, ftp, telnet, vnc
  Enterprise:   smb, ldap, winrm
  Databases:    mysql, postgresql, mssql, mongodb, redis, neo4j, cassandra,
                couchdb, elasticsearch, influxdb
  NoSQL:        mongodb, redis, neo4j, cassandra, couchdb, elasticsearch, influxdb
  Mail:         smtp, imap, pop3
  Web:          http, https (use --experimental-ai for form-based login pages)
  Other:        snmp

Examples:
  # Scan network range with naabu, fingerprint services, and test credentials
  naabu -host 192.168.1.0/24 -silent | nerva --json | brutus --nerva -P passwords.txt

  # Targeted port scan with service fingerprinting and credential testing
  naabu -host 10.0.0.1 -p 22,3306 -silent | nerva --json | brutus --nerva -u root -p "toor,admin"

  # Fingerprint known open ports and test with private keys
  echo "192.168.1.10:22" | nerva --json | brutus --nerva -u root,ubuntu -k ~/.ssh/id_rsa

  # Single target mode
  brutus --target 192.168.1.10:22 --protocol ssh -p "password,Password1"

  # With LLM-augmented password suggestions (HTTP Basic Auth only)
  brutus --target example.com:80 --protocol http --llm claude

  # SNMP community string testing
  brutus --target 192.168.1.1:161 --protocol snmp --snmp-tier full

  # Quiet mode (only show valid credentials)
  brutus --target 192.168.1.10:22 --protocol ssh -p "pass123" -q

  # SSH with embedded bad keys (tested by default for SSH)
  brutus --target 192.168.1.10:22 --protocol ssh

  # Test ONLY bad keys (skip password wordlists and non-SSH protocols)
  naabu -host 10.0.0.0/24 -p 22 -silent | nerva --json | brutus --badkeys-only

  # Disable bad key testing
  brutus --target 192.168.1.10:22 --protocol ssh --no-badkeys -p "password"

  # Pipeline mode with output to file
  naabu -host 10.0.0.0/8 -p 22,3306 -rate 1000 -silent | nerva --json | brutus -t 20 -o findings.json

  # AI-powered credential detection for HTTP services (auto-detects Basic Auth vs form)
  brutus --target 192.168.1.1:80 --protocol http --experimental-ai -u admin -p "admin,password"

  # AI mode in pipeline - auto-login to any HTTP service with default device credentials
  naabu -host 192.168.1.0/24 -p 80,443,8080 -silent | nerva --json | brutus --experimental-ai

  # RDP credential testing with sticky keys backdoor detection (heuristic only)
  brutus --target 10.0.0.50:3389 --protocol rdp --sticky-keys -u administrator -p "Password1"

  # RDP with Vision API confirmation (requires --experimental-ai + ANTHROPIC_API_KEY)
  brutus --target 10.0.0.50:3389 --protocol rdp --sticky-keys --experimental-ai

  # Execute a command via sticky keys backdoor
  brutus --target 10.0.0.50:3389 --protocol rdp --sticky-keys --sticky-keys-exec "whoami"

  # Interactive web terminal via sticky keys backdoor (opens browser-based RDP viewer)
  brutus --target 10.0.0.50:3389 --protocol rdp --sticky-keys --sticky-keys-web
`)
}
