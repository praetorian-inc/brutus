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

package input

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadPasswordsFromFile reads passwords from a file.
// Lines starting with # are skipped as comments. The marker <EMPTY> is
// converted to an empty string. Blank lines are preserved as empty passwords.
func LoadPasswordsFromFile(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening password file: %w", err)
	}

	var passwords []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Support <EMPTY> marker for empty passwords
		if trimmed == "<EMPTY>" {
			passwords = append(passwords, "")
			continue
		}
		// Include all non-comment lines (empty lines = empty passwords)
		passwords = append(passwords, trimmed)
	}

	if err := scanner.Err(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("reading password file: %w", err)
	}

	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("closing password file: %w", err)
	}

	return passwords, nil
}

// LoadUsernamesFromFile reads usernames from a file.
// Lines starting with # and blank lines are skipped.
func LoadUsernamesFromFile(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening username file: %w", err)
	}

	var usernames []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		usernames = append(usernames, trimmed)
	}

	if err := scanner.Err(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("reading username file: %w", err)
	}

	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("closing username file: %w", err)
	}

	return usernames, nil
}

// LoadTargetsFromFile reads a list of host:port targets from a file, one
// per line. Lines starting with '#' and blank lines are skipped, mirroring
// the username/password file conventions. Whitespace around each target is
// trimmed.
//
// The function does not validate the host:port shape — that's left to the
// per-target dispatch path so a bad line surfaces with the same error as a
// bad --target flag, with the line number included for context.
//
// See https://github.com/praetorian-inc/brutus/issues/80.
func LoadTargetsFromFile(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening targets file: %w", err)
	}

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		targets = append(targets, trimmed)
	}

	scanErr := scanner.Err()
	_ = f.Close()

	if scanErr != nil {
		return nil, fmt.Errorf("reading targets file: %w", scanErr)
	}

	return targets, nil
}

// LoadKeyFile reads an SSH/TLS key file, enforcing a 1 MB size limit.
func LoadKeyFile(filePath string) ([][]byte, error) {
	if filePath == "" {
		return nil, nil
	}

	// Check file size to prevent OOM from excessively large files
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("accessing key file %s: %w", filePath, err)
	}
	const maxKeyFileSize = 1 << 20 // 1MB - generous limit for SSH/TLS keys
	if info.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("key file %s is %d bytes (max %d bytes)", filePath, info.Size(), maxKeyFileSize)
	}

	key, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", filePath, err)
	}

	return [][]byte{key}, nil
}
