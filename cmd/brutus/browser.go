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
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

// openBrowser validates rawURL and launches it in the default browser. It does
// not block waiting for the browser to exit.
func openBrowser(rawURL string) error {
	if !isAllowedVerificationURL(rawURL) {
		return fmt.Errorf("refusing to open URL: not an https Microsoft URL")
	}
	name, args, err := browserCommand(runtime.GOOS, rawURL)
	if err != nil {
		return err
	}
	return exec.Command(name, args...).Start()
}

// isAllowedVerificationURL reports whether raw is a safe Microsoft device-login
// URL to hand to a browser: an https URL whose host is microsoft.com or
// microsoftonline.com (or a subdomain). The verification URL comes from a server
// response, so we validate it before opening rather than trusting it blindly.
func isAllowedVerificationURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	for _, base := range []string{"microsoft.com", "microsoftonline.com"} {
		if host == base || strings.HasSuffix(host, "."+base) {
			return true
		}
	}
	return false
}

// browserCommand returns the executable and args to open rawURL on the given
// GOOS. It is pure (executes nothing) so it can be unit-tested across platforms.
func browserCommand(goos, rawURL string) (executable string, args []string, err error) {
	switch goos {
	case "darwin":
		return "open", []string{rawURL}, nil
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}, nil
	case "linux", "freebsd", "openbsd", "netbsd":
		return "xdg-open", []string{rawURL}, nil
	default:
		return "", nil, fmt.Errorf("opening a browser is not supported on %q", goos)
	}
}
