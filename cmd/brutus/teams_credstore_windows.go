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

import "os"

// openCredStoreFile opens the credential store for writing on Windows. Windows
// has no O_NOFOLLOW flag, so it is omitted here; this is acceptable because
// creating symlinks on Windows requires elevated privileges, so the symlink
// redirection that O_NOFOLLOW guards against on Unix (P0-1) is not reachable by
// an unprivileged attacker.
func openCredStoreFile(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
}
