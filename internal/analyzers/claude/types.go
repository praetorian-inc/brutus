// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package claude

import "context"

// PageAnalysis contains the result of AI vision analysis
type PageAnalysis struct {
	IsLoginPage          bool            `json:"is_login_page"`
	Confidence           float64         `json:"confidence"`
	Application          ApplicationInfo `json:"application"`
	FormHints            *FormHints      `json:"form_hints,omitempty"`  // Deprecated
	FormLabels           *FormLabels     `json:"form_labels,omitempty"` // Visible text labels
	SuggestedCredentials []Credential    `json:"suggested_credentials,omitempty"`
}

// Credential represents a username/password pair
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ApplicationInfo identifies the detected application/device
type ApplicationInfo struct {
	Type       string  `json:"type"`       // router, printer, camera, nas, enterprise, unknown
	Vendor     string  `json:"vendor"`     // TP-Link, HP, Hikvision, Synology, etc.
	Model      string  `json:"model"`      // Specific model if detected
	Confidence float64 `json:"confidence"` // 0.0-1.0
}

// FormHints provides CSS selectors for form fields (when detected by AI)
//
// Deprecated: Use FormLabels instead
type FormHints struct {
	UsernameSelector string `json:"username_selector,omitempty"`
	PasswordSelector string `json:"password_selector,omitempty"`
	SubmitSelector   string `json:"submit_selector,omitempty"`
}

// FormLabels provides visible text labels from the page (what AI can actually see)
type FormLabels struct {
	SubmitButtonText string `json:"submit_button_text,omitempty"` // e.g., "Log In", "Sign In"
	UsernameLabel    string `json:"username_label,omitempty"`     // e.g., "User ID", "Username"
	PasswordLabel    string `json:"password_label,omitempty"`     // e.g., "Password", "Passcode"
}

// LoginVerification contains the result of AI-based login verification
type LoginVerification struct {
	Success    bool    `json:"success"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// VisionAnalyzer defines the Claude Vision capabilities for screenshot analysis.
type VisionAnalyzer interface {
	// AnalyzeScreenshot analyzes a page screenshot and returns page analysis
	AnalyzeScreenshot(ctx context.Context, screenshot []byte) (*PageAnalysis, error)

	// VerifyLogin compares before/after screenshots to determine login success
	VerifyLogin(ctx context.Context, beforeScreenshot, afterScreenshot []byte) (*LoginVerification, error)

	// ReadTerminalOutput extracts text from a terminal screenshot via OCR
	ReadTerminalOutput(ctx context.Context, screenshot []byte) (string, error)
}
