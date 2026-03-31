// pkg/enum/plugin_test.go
package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfidenceValues(t *testing.T) {
	assert.Equal(t, Confidence("high"), ConfidenceHigh)
	assert.Equal(t, Confidence("medium"), ConfidenceMedium)
	assert.Equal(t, Confidence("low"), ConfidenceLow)
}

func TestResultDefaults(t *testing.T) {
	r := &Result{
		Service: "test",
		Email:   "user@example.com",
	}
	assert.False(t, r.Exists)
	assert.Nil(t, r.Error)
	assert.Equal(t, Confidence(""), r.Confidence)
}
