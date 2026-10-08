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

package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRunCUPS models olbat/cupsd. To troubleshoot against the real server:
//
//	docker run -d --name cups --platform linux/amd64 -p 631:631 olbat/cupsd
//
// GET /admin is open. GET /admin/conf challenges. print:print is 200. A wrong
// password is 401. Upstream CUPS does not ship this password; the image does.
func TestRunCUPS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/conf" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "print" || pass != "print" {
			w.Header().Set("WWW-Authenticate", `Basic realm="CUPS"`)
			w.Header().Set("Server", "CUPS/2.4 IPP/2.1")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Server", "CUPS/2.4 IPP/2.1")
		_, _ = w.Write([]byte(`<title>Administration - CUPS 2.4.18</title>`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"cups"})
	if len(selected) != 1 || selected[0].ID != "cups" {
		t.Fatalf("cups match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "print" || hits[0].Password != "print" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "CUPS/2.4 IPP/2.1")
		_, _ = w.Write([]byte(`<title>Administration - CUPS 2.4.18</title>`))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open admin page reported a credential hit: %+v", hits)
	}
}
