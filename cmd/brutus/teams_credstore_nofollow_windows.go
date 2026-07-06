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

//go:build windows

package main

// Windows has no O_NOFOLLOW; creating a file symlink on Windows requires special
// privilege, and Go's os layer does not follow them here, so 0 is the safe
// portable fallback (the symlink-redirect concern from the Unix path does not
// apply the same way).
const oNoFollow = 0
