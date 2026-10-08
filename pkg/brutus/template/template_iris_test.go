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
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestRunIRIS models the Community Edition portal. To troubleshoot against
// the real app:
//
//	docker run -d --name iris --platform linux/arm64 \
//	  -p 52773:52773 -p 1972:1972 \
//	  intersystems/iris-community:latest-cd-linux-arm64
//
// Login is POST /csp/sys/UtilHome.csp. Keep the CSPSESSIONID cookie and the
// IRISSessionToken from the GET of that same URL. _SYSTEM:SYS and
// SuperUser:SYS hit the password-change page. system:sys does not.
func TestRunIRIS(t *testing.T) {
	var mu sync.Mutex
	sessions := map[string]string{}
	next := 0
	issue := func(w http.ResponseWriter) string {
		next++
		id := fmt.Sprintf("s%d", next)
		token := fmt.Sprintf("t%d", next)
		sessions[id] = token
		http.SetCookie(w, &http.Cookie{Name: "CSPSESSIONID", Value: id, Path: "/"})
		return token
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/csp/sys/UtilHome.csp" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			token := issue(w)
			fmt.Fprintf(w, `<title>Login IRIS</title><form><input type="hidden" name="IRISSessionToken" value="%s"><input name="IRISUsername"><input name="IRISPassword"></form>`, token)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		cookie, err := r.Cookie("CSPSESSIONID")
		token := r.Form.Get("IRISSessionToken")
		if err != nil || sessions[cookie.Value] != token {
			http.SetCookie(w, &http.Cookie{Name: "CSPSESSIONID", Value: "stale", Path: "/"})
			_, _ = w.Write([]byte(`<title>Login IRIS</title><input name="IRISUsername">`))
			return
		}
		delete(sessions, cookie.Value)
		user, pass := r.Form.Get("IRISUsername"), r.Form.Get("IRISPassword")
		if (user == "_SYSTEM" || user == "SuperUser") && pass == "SYS" {
			_, _ = w.Write([]byte(`<title>Password change IRIS</title><input name="IRISOldPassword">`))
			return
		}
		_, _ = w.Write([]byte(`<title>Login IRIS</title><input name="IRISUsername">`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"intersystems-iris"})
	if len(selected) != 1 || selected[0].ID != "iris" {
		t.Fatalf("iris match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[0].Username != "_SYSTEM" || hits[0].Password != "SYS" || hits[1].Username != "SuperUser" {
		t.Fatalf("hits = %+v", hits)
	}
}
