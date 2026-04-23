// pkg/enum/enum_test.go
package enum

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate_NoEmails(t *testing.T) {
	cfg := &Config{}
	err := cfg.validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "emails required")
}

func TestConfig_Validate_Defaults(t *testing.T) {
	cfg := &Config{
		Emails: []string{"user@example.com"},
	}
	err := cfg.validate()
	assert.NoError(t, err)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
	assert.Equal(t, 10, cfg.Threads)
}

func TestConfig_Validate_CustomValues(t *testing.T) {
	cfg := &Config{
		Emails:  []string{"user@example.com"},
		Threads: 5,
		Timeout: 30 * time.Second,
	}
	err := cfg.validate()
	assert.NoError(t, err)
	assert.Equal(t, 5, cfg.Threads)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
}

func TestConfig_Validate_NegativeThreads(t *testing.T) {
	cfg := &Config{
		Emails:  []string{"user@example.com"},
		Threads: -1,
	}
	err := cfg.validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threads must not be negative")
}

func TestConfig_Validate_NegativeRateLimit(t *testing.T) {
	cfg := &Config{
		Emails:    []string{"user@example.com"},
		RateLimit: -1,
	}
	err := cfg.validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit must not be negative")
}
