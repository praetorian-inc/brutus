// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"testing"
)

func TestDetectFormFields_StandardForm(t *testing.T) {
	// HTML with standard login form
	html := `
	<html>
	<body>
		<form>
			<input type="text" name="username" id="user">
			<input type="password" name="password" id="pass">
			<button type="submit">Login</button>
		</form>
	</body>
	</html>`

	fields, err := DetectFormFields(html)
	if err != nil {
		t.Fatalf("DetectFormFields failed: %v", err)
	}

	if fields.UsernameSelector == "" {
		t.Error("Expected username selector to be detected")
	}

	if fields.PasswordSelector == "" {
		t.Error("Expected password selector to be detected")
	}

	if fields.SubmitSelector == "" {
		t.Error("Expected submit selector to be detected")
	}
}

func TestDetectFormFields_VariousPatterns(t *testing.T) {
	testCases := []struct {
		name         string
		html         string
		wantUsername string
		wantPassword string
	}{
		{
			name:         "id_based",
			html:         `<input id="username"><input type="password" id="pwd">`,
			wantUsername: "#username",
			wantPassword: "#pwd",
		},
		{
			name:         "name_based",
			html:         `<input name="user"><input type="password" name="pass">`,
			wantUsername: `input[name="user"]`,
			wantPassword: `input[name="pass"]`,
		},
		{
			name:         "placeholder_based",
			html:         `<input placeholder="Username"><input type="password" placeholder="Password">`,
			wantUsername: `input[placeholder="Username"]`,
			wantPassword: `input[type="password"]`,
		},
		{
			name:         "class_based",
			html:         `<input class="login-username"><input type="password" class="login-password">`,
			wantUsername: `.login-username`,
			wantPassword: `input[type="password"]`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fields, err := DetectFormFields(tc.html)
			if err != nil {
				t.Fatalf("DetectFormFields failed: %v", err)
			}

			if fields.UsernameSelector == "" {
				t.Error("Username selector not detected")
			}

			if fields.PasswordSelector == "" {
				t.Error("Password selector not detected")
			}
		})
	}
}

func TestDetectFormFields_ExpandedIndicators(t *testing.T) {
	testCases := []struct {
		name         string
		html         string
		wantUsername string
	}{
		{
			name:         "uname_indicator",
			html:         `<input name="uname"><input type="password">`,
			wantUsername: `input[name="uname"]`,
		},
		{
			name:         "signin_indicator",
			html:         `<input id="signin-field"><input type="password">`,
			wantUsername: "#signin-field",
		},
		{
			name:         "logon_indicator",
			html:         `<input name="logon_name"><input type="password">`,
			wantUsername: `input[name="logon_name"]`,
		},
		{
			name:         "auth_indicator",
			html:         `<input id="auth-user"><input type="password">`,
			wantUsername: "#auth-user",
		},
		{
			name:         "uid_indicator",
			html:         `<input name="uid"><input type="password">`,
			wantUsername: `input[name="uid"]`,
		},
		{
			name:         "usr_indicator",
			html:         `<input placeholder="Enter usr"><input type="password">`,
			wantUsername: `input[placeholder="Enter usr"]`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fields, err := DetectFormFields(tc.html)
			if err != nil {
				t.Fatalf("DetectFormFields failed: %v", err)
			}
			if fields.UsernameSelector != tc.wantUsername {
				t.Errorf("username selector = %q, want %q", fields.UsernameSelector, tc.wantUsername)
			}
		})
	}
}

func TestDetectFormFields_NoLoginForm(t *testing.T) {
	html := `<html><body><h1>Welcome</h1><p>No form here</p></body></html>`

	fields, err := DetectFormFields(html)
	if err == nil && fields.PasswordSelector != "" {
		t.Error("Expected no password field to be detected")
	}
}

func TestDetectSubmitButton(t *testing.T) {
	testCases := []struct {
		name string
		html string
		want string
	}{
		{
			name: "button_submit",
			html: `<button type="submit">Login</button>`,
			want: `button[type="submit"]`,
		},
		{
			name: "input_submit",
			html: `<input type="submit" value="Sign In">`,
			want: `input[type="submit"]`,
		},
		{
			name: "button_text_login",
			html: `<button>Login</button>`,
			want: `button`,
		},
		{
			name: "button_id",
			html: `<button id="login-btn">Go</button>`,
			want: `#login-btn`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fields, _ := DetectFormFields(tc.html + `<input type="password">`)
			if fields.SubmitSelector == "" {
				t.Error("Submit selector not detected")
			}
		})
	}
}
