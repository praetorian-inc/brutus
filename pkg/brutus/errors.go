package brutus

import (
	"fmt"
	"strings"
)

// ClassifyAuthError classifies authentication errors.
//
// Returns nil if the error matches any auth failure indicator (case-insensitive).
// Returns wrapped error for connection/network errors.
//
// This function is used by plugins to distinguish:
//   - Authentication failures (wrong credentials) → return nil
//   - Connection/network errors (retry or escalate) → return wrapped error
//
// All string matching is case-insensitive to handle server implementation variations.
func ClassifyAuthError(err error, authIndicators []string) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check if error matches any auth failure indicator
	for _, indicator := range authIndicators {
		if strings.Contains(errStr, strings.ToLower(indicator)) {
			// This is an authentication failure (wrong credentials)
			// Return nil to signal "try next credential"
			return nil
		}
	}

	// All other errors are connection/network problems
	return fmt.Errorf("connection error: %w", err)
}

// WrapConnError wraps an error as a connection error.
// Returns nil if err is nil.
// This is a shared helper for plugins that need to wrap non-auth errors.
func WrapConnError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("connection error: %w", err)
}

// NewClassifier returns an error classifier function for the given auth indicators.
// This is a convenience wrapper around ClassifyAuthError for plugins that need a
// package-local classifyError function.
func NewClassifier(authIndicators []string) func(error) error {
	return func(err error) error {
		return ClassifyAuthError(err, authIndicators)
	}
}
