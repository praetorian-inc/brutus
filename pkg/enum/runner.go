// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// pkg/enum/runner.go
package enum

import (
	"context"
	"errors"
)

// EnumerateWithPlugin runs the addresses in cfg against a single provided Plugin
// instance, bypassing the registry. It is used by runtime-constructed oracles
// (e.g. the custom declarative oracle) that are not registered globally.
//
// The addresses come from cfg.resolveTargets(), so a caller may supply either
// Targets or the legacy Emails. Each Target's First/Last is stamped onto the
// Result it produced, on every path including errors and panics. The Plugin
// itself only ever sees the email — see runTasks.
//
// The same Plugin instance is shared across all goroutines, so the Plugin MUST
// be stateless (enum.Plugin contract). cfg.Services is ignored.
func EnumerateWithPlugin(ctx context.Context, cfg *Config, p Plugin) ([]Result, error) {
	if cfg == nil {
		return nil, errors.New("enum: nil config")
	}
	if p == nil {
		return nil, errors.New("enum: nil plugin")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	targets := cfg.resolveTargets()
	tasks := make([]enumTask, 0, len(targets))
	for _, subject := range targets {
		tasks = append(tasks, enumTask{
			email:   subject.Email,
			first:   subject.First,
			last:    subject.Last,
			service: p.Name(),
			plugin:  p,
		})
	}
	return runTasks(ctx, cfg, tasks)
}
