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

// Package sdk provides a capability-sdk compatible wrapper around the Brutus
// credential testing library. It implements capability.Capability[capmodel.Port]
// so that Brutus can be registered as a Chariot capability.
package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	_ "github.com/praetorian-inc/brutus/pkg/builtins"
)

const (
	UsernameParam  = "usernames"
	PasswordParam  = "passwords"
	RateLimitParam = "ratelimit"
	ProtocolParam  = "protocol"
)

// Capability implements capability.Capability[capmodel.Port] using the Brutus
// credential testing library.
type Capability struct{}

// Compile-time interface check.
var _ capability.Capability[capmodel.Port] = (*Capability)(nil)

// NewCapability returns a new Brutus SDK capability instance.
func NewCapability() *Capability {
	return &Capability{}
}

// bruteFunc is the function used to run brute force sweeps. It is a package-level
// variable so that tests can inject a stub without a broad DI refactor.
var bruteFunc = brutus.BruteWithContext

func (c *Capability) Name() string        { return "brutus" }
func (c *Capability) Description() string { return "credential testing against network services" }
func (c *Capability) Input() any          { return capmodel.Port{} }

func (c *Capability) Parameters() []capability.Parameter {
	return []capability.Parameter{
		capability.String(UsernameParam, "Comma-separated list of usernames to test (defaults to brutus-provided list)"),
		capability.String(PasswordParam, "Comma-separated list of passwords to test (defaults to brutus-provided list)"),
		capability.Float(RateLimitParam, "Requests per second, supports fractional values like 0.5 (defaults to unlimited)"),
		capability.String(ProtocolParam, "The protocol to use (defaults to the protocol detected on this port)"),
	}
}

func (c *Capability) Match(ctx capability.ExecutionContext, _ capmodel.Port) error { //nolint:gocritic // hugeParam: signature required by capability.Capability interface
	if !ctx.Manual {
		return fmt.Errorf("brutus may only be run manually")
	}
	return nil
}

func (c *Capability) Invoke(ctx capability.ExecutionContext, input capmodel.Port, output capability.Emitter) error { //nolint:gocritic // hugeParam: signature required by capability.Capability interface
	if !ctx.Manual {
		return fmt.Errorf("brutus may only be run manually")
	}

	protocol := input.Service
	if p, ok := ctx.Parameters.GetString(ProtocolParam); ok && p != "" {
		protocol = p
	}
	if protocol == "" {
		return fmt.Errorf("no protocol specified and port has no service detected")
	}

	// Validate port number
	if input.Port < 1 || input.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", input.Port)
	}

	// Validate hostname
	if input.Parent.DNS == "" {
		return fmt.Errorf("no hostname specified in port parent asset")
	}

	target := fmt.Sprintf("%s:%d", input.Parent.DNS, input.Port)

	cfg := &brutus.Config{
		Target:      target,
		Protocol:    protocol,
		UseDefaults: true,
	}

	if usernames, ok := ctx.Parameters.GetString(UsernameParam); ok && usernames != "" {
		cfg.Usernames = splitAndTrim(usernames)
	}

	if passwords, ok := ctx.Parameters.GetString(PasswordParam); ok && passwords != "" {
		cfg.Passwords = splitAndTrim(passwords)
	}

	if rateLimit, ok := ctx.Parameters.GetFloat(RateLimitParam); ok {
		if rateLimit < 0 {
			return fmt.Errorf("invalid ratelimit %g: must be non-negative", rateLimit)
		}
		// rateLimit == 0 is treated as "unlimited" per parameter description.
		if rateLimit > 0 {
			cfg.RateLimit = rateLimit
		}
	}

	results, runErr := bruteFunc(context.Background(), cfg)
	var errs []error
	if runErr != nil {
		errs = append(errs, fmt.Errorf("brute force execution failed: %w", runErr))
	}

	for i := range results {
		r := &results[i]
		if !r.Success {
			continue
		}

		proof, err := json.Marshal(map[string]string{
			"username": r.Username,
			"password": r.Password,
			"protocol": r.Protocol,
			"target":   r.Target,
			"banner":   r.Banner,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal proof: %w", err)
		}

		risk := capmodel.Risk{
			TargetName: target,
			Name:       "Weak Credentials",
			Source:     "brutus",
			Status:     "OH",
			Proof:      proof,
			Target:     input,
		}

		if err := output.Emit(risk); err != nil {
			errs = append(errs, fmt.Errorf("failed to emit risk for %s: %w", r.Username, err))
		}
	}

	return errors.Join(errs...)
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
