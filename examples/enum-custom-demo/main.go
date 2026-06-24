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

// Command enum-custom-demo is an INTENTIONALLY account-enumeration-VULNERABLE
// HTTP server used as a teaching target for Brutus's "enum custom" declarative
// oracle. Two endpoints leak whether an account exists: the responses for valid
// vs. invalid accounts differ in both HTTP status and message body — exactly the
// signal a custom oracle spec keys off of.
//
// This is demo/teaching code. Do NOT deploy it. It listens on localhost by
// default and holds a tiny hardcoded set of fake accounts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// validAccounts is the hardcoded set of "real" demo accounts. A leak that lets
// an attacker tell these apart from non-accounts is the enumeration vulnerability
// this server demonstrates. Keys are lowercased so matching is case-insensitive.
var validAccounts = map[string]bool{
	"alice@demo.local": true,
	"bob@demo.local":   true,
	"carol@demo.local": true,
	"admin@demo.local": true,
}

func main() {
	addr := flag.String("addr", ":8080", "listen address (host:port)")
	flag.Parse()

	// PORT env overrides the default port when -addr was not customised, so the
	// demo runs unchanged on platforms that inject a PORT.
	if port := os.Getenv("PORT"); port != "" && *addr == ":8080" {
		*addr = ":" + port
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/forgot-password", handleForgotPassword)
	mux.HandleFunc("/api/login", handleLogin)

	printBanner(*addr)

	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// =============================================================================
// HANDLERS
// =============================================================================

// handleForgotPassword is the primary enumeration oracle. A valid email returns
// HTTP 200 with a "reset link sent" message; an invalid one returns HTTP 404
// with a "No account found" message. The status + message difference is the leak.
func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, response{Status: "error", Message: "method not allowed"})
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Status: "error", Message: "invalid JSON body"})
		logRequest(r, req.Email, "bad-request")
		return
	}

	if accountExists(req.Email) {
		logRequest(r, req.Email, "exists")
		writeJSON(w, http.StatusOK, response{Status: "ok", Message: "Password reset link sent to your email"})
		return
	}

	logRequest(r, req.Email, "absent")
	writeJSON(w, http.StatusNotFound, response{Status: "error", Message: "No account found for that email address"})
}

// handleLogin is a second enumeration vector. A valid email (any password)
// returns HTTP 401 "Incorrect password"; an invalid email returns HTTP 404
// "No account with that email". The 401-vs-404 split leaks account existence.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, response{Message: "method not allowed"})
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Message: "invalid JSON body"})
		logRequest(r, req.Email, "bad-request")
		return
	}

	if accountExists(req.Email) {
		// Real account: we never reveal "wrong password" only for real accounts in
		// a secure design — but this demo does exactly that, which is the bug.
		logRequest(r, req.Email, "exists")
		writeJSON(w, http.StatusUnauthorized, response{Message: "Incorrect password"})
		return
	}

	logRequest(r, req.Email, "absent")
	writeJSON(w, http.StatusNotFound, response{Message: "No account with that email"})
}

// handleIndex serves a short human-readable description of the demo target.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, indexText)
}

// =============================================================================
// HELPERS
// =============================================================================

// response is the JSON envelope returned by both API endpoints. Status is
// omitted from the login responses (which only carry a message).
type response struct {
	Status  string `json:"status,omitempty"`
	Message string `json:"message"`
}

// accountExists reports whether email is one of the hardcoded demo accounts,
// matching case-insensitively after trimming surrounding whitespace.
func accountExists(email string) bool {
	return validAccounts[strings.ToLower(strings.TrimSpace(email))]
}

// decodeJSON decodes the request body into v, rejecting unknown fields so a
// malformed body produces a clean 400.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

// writeJSON writes status and the JSON-encoded body.
func writeJSON(w http.ResponseWriter, status int, body response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// logRequest emits one request line to stderr so the demo is visible as Brutus
// probes the target.
func logRequest(r *http.Request, email, verdict string) {
	log.Printf("%s %s email=%q -> %s", r.Method, r.URL.Path, email, verdict)
}

// printBanner prints the startup banner, including the loud "do not deploy"
// warning and the list of valid demo accounts.
func printBanner(addr string) {
	log.Printf("⚠ INTENTIONALLY VULNERABLE demo target — do not deploy.")
	log.Printf("Valid demo accounts: alice@demo.local, bob@demo.local, carol@demo.local, admin@demo.local")
	log.Printf("Listening on %s (POST /api/forgot-password, POST /api/login, GET /)", addr)
}

// indexText is the GET / landing page explaining the demo.
const indexText = `enum-custom-demo — INTENTIONALLY account-enumeration-vulnerable target

This server exists to demonstrate Brutus's "enum custom" declarative oracle.
Do NOT deploy it. It leaks whether an account exists.

Endpoints:
  POST /api/forgot-password  {"email":"..."}
      valid email   -> 200 {"status":"ok","message":"Password reset link sent to your email"}
      invalid email -> 404 {"status":"error","message":"No account found for that email address"}

  POST /api/login            {"email":"...","password":"..."}
      valid email   -> 401 {"message":"Incorrect password"}
      invalid email -> 404 {"message":"No account with that email"}

  GET  /                     this page

There are 4 demo accounts: alice@demo.local, bob@demo.local, carol@demo.local, admin@demo.local
`
