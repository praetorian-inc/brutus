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

package custom

import (
	"context"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// Plugin adapts a validated *Spec to the enum.Plugin interface. It holds only
// the immutable parsed spec (with precompiled regexes), so it is safe for
// concurrent use across the worker pool (enum.Plugin contract).
type Plugin struct {
	spec *Spec
}

// New constructs a Plugin from a spec that has already passed Validate().
func New(spec *Spec) *Plugin {
	return &Plugin{spec: spec}
}

// Name returns the oracle name (used as the Result.Service field).
func (p *Plugin) Name() string {
	return p.spec.Oracle.Name
}

// Check runs the oracle against one subject and maps the response to a Result.
func (p *Plugin) Check(ctx context.Context, subject string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{Service: p.Name(), Email: subject}

	req, err := buildRequest(p.spec, ctx, subject)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	client := enum.HTTPClientFromContext(ctx)
	if client == nil {
		client = enum.NewEnumHTTPClient(timeout)
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	// Read at most 1 MB (security-lead R6/P0-6) — never io.ReadAll(resp.Body).
	body, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	verdict, conf := p.spec.evaluate(matchInput{
		status: resp.StatusCode,
		body:   body,
		header: resp.Header,
	})
	applyVerdict(result, verdict, conf, resp.StatusCode)
	result.Duration = time.Since(start)
	return result
}
