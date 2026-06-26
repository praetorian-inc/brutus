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

//go:build !windows

package main

import "syscall"

// oNoFollow makes os.OpenFile refuse to follow a symlink at the token path, so
// a pre-existing symlink cannot redirect the credential write elsewhere (see
// saveTeamsTokenFile). syscall.O_NOFOLLOW is Unix-only, hence the build split.
const oNoFollow = syscall.O_NOFOLLOW
