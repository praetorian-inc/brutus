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

package clisurface

// Repo-relative paths of the generated artifacts and of the documents the linter
// reads, plus the one command that refreshes them. They live in their own file
// because both the linter and the artifact plumbing need them, and the gate
// test, the Makefile target and the CI workflow all have to name the same files.
const (
	JSONPath     = "docs/cli-surface.json"
	MarkdownPath = "docs/CLI.md"
	READMEPath   = "README.md"
)

// RegenerateCommand is the single documented way to refresh every artifact.
const RegenerateCommand = "make cli-docs"
