package brutus_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestClassifyAuthError_Nil(t *testing.T) {
	result := brutus.ClassifyAuthError(nil, []string{"denied"})
	assert.Nil(t, result)
}

func TestClassifyAuthError_AuthFailure(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		indicators []string
		wantNil    bool
	}{
		{
			name:       "exact match",
			err:        errors.New("Access denied for user 'root'"),
			indicators: []string{"Access denied for user"},
			wantNil:    true,
		},
		{
			name:       "case insensitive match",
			err:        errors.New("access DENIED for user"),
			indicators: []string{"access denied"},
			wantNil:    true,
		},
		{
			name:       "different case in error",
			err:        errors.New("ACCESS DENIED"),
			indicators: []string{"access denied"},
			wantNil:    true,
		},
		{
			name:       "connection error (no match)",
			err:        errors.New("connection refused"),
			indicators: []string{"access denied", "invalid password"},
			wantNil:    false,
		},
		{
			name:       "network timeout (no match)",
			err:        errors.New("i/o timeout"),
			indicators: []string{"authentication failed"},
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := brutus.ClassifyAuthError(tt.err, tt.indicators)
			if tt.wantNil {
				assert.Nil(t, result, "should return nil for auth failure")
			} else {
				require.NotNil(t, result, "should return wrapped error for connection error")
				assert.Contains(t, result.Error(), "connection error")
				assert.ErrorIs(t, result, tt.err, "should wrap original error")
			}
		})
	}
}

func TestClassifyAuthError_EmptyIndicators(t *testing.T) {
	err := errors.New("some error")
	result := brutus.ClassifyAuthError(err, []string{})

	require.NotNil(t, result)
	assert.Contains(t, result.Error(), "connection error")
}

func TestWrapConnError(t *testing.T) {
	assert.Nil(t, brutus.WrapConnError(nil))

	orig := errors.New("i/o timeout")
	wrapped := brutus.WrapConnError(orig)
	require.NotNil(t, wrapped)
	assert.Contains(t, wrapped.Error(), "connection error")
	assert.ErrorIs(t, wrapped, orig)
}

func TestNewClassifier(t *testing.T) {
	classify := brutus.NewClassifier([]string{"Access denied"})

	assert.Nil(t, classify(nil))
	assert.Nil(t, classify(errors.New("Access denied for user 'root'")))

	timeout := errors.New("i/o timeout")
	wrapped := classify(timeout)
	require.NotNil(t, wrapped)
	assert.Contains(t, wrapped.Error(), "connection error")
	assert.ErrorIs(t, wrapped, timeout)

	empty := brutus.NewClassifier(nil)
	alwaysWrapped := empty(errors.New("anything"))
	require.NotNil(t, alwaysWrapped)
	assert.Contains(t, alwaysWrapped.Error(), "connection error")
}
