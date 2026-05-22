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

package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/praetorian-inc/brutus/pkg/badkeys"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// generateTestKey creates a valid RSA private key for testing.
func generateTestKey(t *testing.T) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM
}

func TestPlugin_TestKey_ParseValidKey(t *testing.T) {
	plugin := &Plugin{}

	// Generate valid test key
	validKey := generateTestKey(t)

	// Test should parse the key without error
	// This will fail initially because TestKey doesn't exist yet
	ctx := context.Background()
	result := plugin.TestKey(ctx, "example.com:22", "testuser", validKey, 5*time.Second, brutus.PluginConfig{})

	// Result should be non-nil even if connection fails
	if result == nil {
		t.Fatal("TestKey returned nil result")
	}

	// Should have protocol, target, username set
	if result.Protocol != "ssh" {
		t.Errorf("expected protocol 'ssh', got %q", result.Protocol)
	}
	if result.Target != "example.com:22" {
		t.Errorf("expected target 'example.com:22', got %q", result.Target)
	}
	if result.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %q", result.Username)
	}
}

func TestPlugin_TestKey_InvalidKey(t *testing.T) {
	plugin := &Plugin{}

	// Invalid key data
	invalidKey := []byte("not a valid private key")

	ctx := context.Background()
	result := plugin.TestKey(ctx, "example.com:22", "testuser", invalidKey, 5*time.Second, brutus.PluginConfig{})

	// Should return error for invalid key
	if result == nil {
		t.Fatal("TestKey returned nil result")
	}

	if result.Success {
		t.Error("expected Success=false for invalid key")
	}

	if result.Error == nil {
		t.Error("expected Error!=nil for invalid key parsing failure")
	}
}

func TestPlugin_TestKey_EmptyKey(t *testing.T) {
	plugin := &Plugin{}

	ctx := context.Background()
	result := plugin.TestKey(ctx, "example.com:22", "testuser", nil, 5*time.Second, brutus.PluginConfig{})

	// Should return error for empty key
	if result == nil {
		t.Fatal("TestKey returned nil result")
	}

	if result.Success {
		t.Error("expected Success=false for empty key")
	}

	if result.Error == nil {
		t.Error("expected Error!=nil for empty key")
	}
}

func TestPlugin_TestKey_PassphraseProtected(t *testing.T) {
	plugin := &Plugin{}

	// Simulate a passphrase-protected key
	// For Phase 1B, this should return an error as specified in PRD
	passphraseKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,1234567890ABCDEF

encrypted data here
-----END RSA PRIVATE KEY-----`)

	ctx := context.Background()
	result := plugin.TestKey(ctx, "example.com:22", "testuser", passphraseKey, 5*time.Second, brutus.PluginConfig{})

	// Should return error for passphrase-protected key (Phase 1B limitation)
	if result == nil {
		t.Fatal("TestKey returned nil result")
	}

	if result.Success {
		t.Error("expected Success=false for passphrase-protected key")
	}

	if result.Error == nil {
		t.Error("expected Error!=nil for passphrase-protected key (not supported in Phase 1B)")
	}
}

func TestPlugin_TestKey_ConnectionError(t *testing.T) {
	plugin := &Plugin{}

	validKey := generateTestKey(t)

	// Use invalid target to force connection error
	ctx := context.Background()
	result := plugin.TestKey(ctx, "127.0.0.1:1", "testuser", validKey, 1*time.Second, brutus.PluginConfig{})

	// Should return connection error
	if result == nil {
		t.Fatal("TestKey returned nil result")
	}

	if result.Success {
		t.Error("expected Success=false for connection error")
	}

	if result.Error == nil {
		t.Error("expected Error!=nil for connection error")
	}
}

func TestPlugin_TestKey_ContextCancellation(t *testing.T) {
	plugin := &Plugin{}

	validKey := generateTestKey(t)

	// Create canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := plugin.TestKey(ctx, "example.com:22", "testuser", validKey, 5*time.Second, brutus.PluginConfig{})

	// Should handle context cancellation
	if result == nil {
		t.Fatal("TestKey returned nil result")
	}

	if result.Success {
		t.Error("expected Success=false for canceled context")
	}

	if result.Error == nil {
		t.Error("expected Error!=nil for canceled context")
	}
}

// getKeyTestConfig returns test configuration from environment variables.
// Returns empty strings if not configured (test should skip).
func getKeyTestConfig() (host, user string) {
	host = os.Getenv("SSH_KEY_TEST_HOST")
	user = os.Getenv("SSH_KEY_TEST_USER")
	return
}

// Integration test - tests SSH key authentication against CI server
func TestPlugin_TestKey_Integration(t *testing.T) {
	host, user := getKeyTestConfig()
	if host == "" {
		t.Skip("Skipping: SSH_KEY_TEST_HOST not configured")
	}
	if user == "" {
		user = "vagrant" // default to vagrant user
	}

	// Get the Vagrant insecure key from embedded badkeys
	// Use "vagrant-default" from rapid7 collection (the "vagrant" key has corrupted RSA params)
	vagrantKey, ok := badkeys.GetKeyByName("vagrant-default")
	if !ok {
		t.Fatal("Failed to get vagrant-default key from badkeys package")
	}

	plugin := &Plugin{}
	ctx := context.Background()
	timeout := 10 * time.Second

	// Test 1: Valid key should authenticate successfully
	t.Run("ValidKey", func(t *testing.T) {
		result := plugin.TestKey(ctx, host, user, vagrantKey, timeout, brutus.PluginConfig{})

		if result == nil {
			t.Fatal("TestKey returned nil result")
		}
		if result.Protocol != "ssh" {
			t.Errorf("expected protocol 'ssh', got %q", result.Protocol)
		}
		if result.Target != host {
			t.Errorf("expected target %q, got %q", host, result.Target)
		}
		if result.Username != user {
			t.Errorf("expected username %q, got %q", user, result.Username)
		}
		if !result.Success {
			t.Errorf("expected Success=true for valid vagrant key, got false. Error: %v", result.Error)
		}
		if result.Error != nil {
			t.Errorf("expected nil error for successful auth, got: %v", result.Error)
		}
		if result.Duration <= 0 {
			t.Error("expected positive duration")
		}
	})

	// Test 2: Invalid key should fail authentication (but not error)
	t.Run("InvalidKey", func(t *testing.T) {
		// Generate a random valid RSA key that isn't authorized
		invalidKey := generateTestKey(t)

		result := plugin.TestKey(ctx, host, user, invalidKey, timeout, brutus.PluginConfig{})

		if result == nil {
			t.Fatal("TestKey returned nil result")
		}
		if result.Success {
			t.Error("expected Success=false for unauthorized key")
		}
		// Authentication failure (not connection error) should have nil Error
		if result.Error != nil {
			t.Logf("Note: got error %v (may be connection-level or auth-level)", result.Error)
		}
		if result.Duration <= 0 {
			t.Error("expected positive duration")
		}
	})

	// Test 3: Wrong username with valid key should fail
	t.Run("WrongUsername", func(t *testing.T) {
		result := plugin.TestKey(ctx, host, "nonexistentuser", vagrantKey, timeout, brutus.PluginConfig{})

		if result == nil {
			t.Fatal("TestKey returned nil result")
		}
		if result.Success {
			t.Error("expected Success=false for wrong username")
		}
		if result.Duration <= 0 {
			t.Error("expected positive duration")
		}
	})
}

// TestPlugin_TestKey_KeySpraying tests the key spraying workflow:
// spray a single private key across multiple usernames.
// This simulates the use case: "found a key, spray it across the network"
func TestPlugin_TestKey_KeySpraying(t *testing.T) {
	host, _ := getKeyTestConfig()
	if host == "" {
		t.Skip("Skipping: SSH_KEY_TEST_HOST not configured")
	}

	// Get the Vagrant insecure key - simulates "found key on compromised system"
	vagrantKey, ok := badkeys.GetKeyByName("vagrant-default")
	if !ok {
		t.Fatal("Failed to get vagrant-default key from badkeys package")
	}

	plugin := &Plugin{}
	ctx := context.Background()
	timeout := 10 * time.Second

	// Spray the key across multiple common usernames
	// This is the key spraying use case: one key, many users
	usernames := []string{"root", "admin", "ubuntu", "vagrant", "deploy", "ec2-user"}

	var successCount int
	var results []*struct {
		username string
		success  bool
	}

	for _, username := range usernames {
		result := plugin.TestKey(ctx, host, username, vagrantKey, timeout, brutus.PluginConfig{})
		results = append(results, &struct {
			username string
			success  bool
		}{username, result.Success})

		if result.Success {
			successCount++
			t.Logf("[+] Key valid for user: %s", username)
		}
	}

	// The vagrant key should work for at least the vagrant user
	if successCount == 0 {
		t.Error("Key spraying found no valid username for the vagrant key")
		t.Log("Tested usernames and results:")
		for _, r := range results {
			t.Logf("  %s: success=%v", r.username, r.success)
		}
	} else {
		t.Logf("Key spraying found %d valid username(s) for the compromised key", successCount)
	}
}

// TestPlugin_TestKey_BadKeysIntegration tests authentication using all embedded bad keys.
// This is a comprehensive test that verifies the badkeys package integration.
func TestPlugin_TestKey_BadKeysIntegration(t *testing.T) {
	host, user := getKeyTestConfig()
	if host == "" {
		t.Skip("Skipping: SSH_KEY_TEST_HOST not configured")
	}
	if user == "" {
		user = "vagrant"
	}

	// Test that at least one vagrant key works
	vagrantCreds := badkeys.GetCredentialsByProduct("vagrant")
	if len(vagrantCreds) == 0 {
		t.Fatal("No vagrant credentials found in badkeys package")
	}

	plugin := &Plugin{}
	ctx := context.Background()
	timeout := 10 * time.Second

	successCount := 0
	for _, cred := range vagrantCreds {
		t.Run(cred.Name, func(t *testing.T) {
			// Use the test user, not the credential's default user
			result := plugin.TestKey(ctx, host, user, cred.Key, timeout, brutus.PluginConfig{})

			if result == nil {
				t.Fatal("TestKey returned nil result")
			}

			t.Logf("Key %s: Success=%v, Duration=%v", cred.Name, result.Success, result.Duration)

			if result.Success {
				successCount++
			}
		})
	}

	// At least one vagrant key should work against the vagrant-configured server
	if successCount == 0 {
		t.Error("Expected at least one vagrant key to authenticate successfully")
	}
}
