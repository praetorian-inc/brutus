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

func TestEmbeddedRoundcube(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "roundcube" {
			if tpl.Path != "/" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template roundcube")
}

func TestRunGitea(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input type="hidden" name="_csrf" value="gitea-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("user_name")
		postedCSRF = r.Form.Get("_csrf")
		if postedUser == "gitadmin" && r.Form.Get("password") == "secret" && postedCSRF == "gitea-token" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		w.Header().Set("Location", "/user/login")
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"gitea"})
	if len(selected) != 1 || selected[0].ID != "gitea" {
		t.Fatalf("gitea match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "gitadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "gitadmin" || postedCSRF != "gitea-token" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "gitadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunMikroTik(t *testing.T) {
	var postedName, postedPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedName = r.Form.Get("name")
		postedPass = r.Form.Get("password")
		if postedName == "admin" && postedPass == "" {
			w.Header().Set("Set-Cookie", "username=admin; path=/")
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Authentication failed"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"mikrotik-routeros"})
	if len(selected) != 1 || selected[0].ID != "mikrotik" {
		t.Fatalf("mikrotik match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedName != "admin" || postedPass != "" {
		t.Fatalf("posted name=%q password=%q", postedName, postedPass)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunPfSense(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="usernamefld"><input name="passwordfld"><input name="__csrf_magic" value="sid:abc">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("usernamefld")
		postedCSRF = r.Form.Get("__csrf_magic")
		if postedUser == "admin" && r.Form.Get("passwordfld") == "secret" && postedCSRF == "sid:abc" {
			w.Header().Set("Location", "/index.php")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<input name="usernamefld">Login failed`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"pfsense"})
	if len(selected) != 1 || selected[0].ID != "pfsense" {
		t.Fatalf("pfsense match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedCSRF != "sid:abc" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunOPNsense(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<div class="login-modal-container"><input name="usernamefld"><input name="passwordfld"><input name="__csrf_magic" value="sid:opn"></div>`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("usernamefld")
		postedCSRF = r.Form.Get("__csrf_magic")
		if postedUser == "root" && r.Form.Get("passwordfld") == "secret" && postedCSRF == "sid:opn" {
			w.Header().Set("Location", "/ui/core/dashboard")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<div class="login-modal-container">Login failed</div>`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"opnsense"})
	if len(selected) != 1 || selected[0].ID != "opnsense" {
		t.Fatalf("opnsense match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "root", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "root" || postedCSRF != "sid:opn" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "root", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunJuniper(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="username"><input name="password"><input name="antiCSRFToken" value="junos-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedCSRF = r.Form.Get("antiCSRFToken")
		if postedUser == "root" && r.Form.Get("password") == "" && postedCSRF == "junos-token" {
			w.Header().Set("Location", "/dashboard")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"juniper-srx"})
	if len(selected) != 1 || selected[0].ID != "juniper" {
		t.Fatalf("juniper match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "root" || postedCSRF != "junos-token" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Username != "root" || hits[0].Password != "" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "root", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunRoundcube(t *testing.T) {
	var postedUser, postedTask string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("_user")
		postedTask = r.Form.Get("_task")
		if postedUser == "mailuser" && r.Form.Get("_pass") == "secret" && postedTask == "login" && r.Form.Get("_action") == "login" {
			w.Header().Set("Location", "/?_task=mail")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Login failed"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"roundcube"})
	if len(selected) != 1 || selected[0].ID != "roundcube" {
		t.Fatalf("roundcube match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "mailuser", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "mailuser" || postedTask != "login" {
		t.Fatalf("posted user=%q task=%q", postedUser, postedTask)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "mailuser", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunGitLab(t *testing.T) {
	var postedUser, postedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/sign_in" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="authenticity_token" value="gitlab-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("user[login]")
		postedToken = r.Form.Get("authenticity_token")
		if postedUser == "root" && r.Form.Get("user[password]") == "secret" && postedToken == "gitlab-token" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/users/sign_in")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"gitlab"})
	if len(selected) != 1 || selected[0].ID != "gitlab" || selected[0].Path != "/users/sign_in" {
		t.Fatalf("gitlab match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "root", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "root" || postedToken != "gitlab-token" {
		t.Fatalf("posted user=%q token=%q", postedUser, postedToken)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "root", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunJenkins(t *testing.T) {
	var postedUser, postedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postedPath = r.URL.Path
		if r.URL.Path != "/j_spring_security_check" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("j_username")
		if postedUser == "admin" && r.Form.Get("j_password") == "admin" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/loginError")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"jenkins"})
	if len(selected) != 1 || selected[0].ID != "jenkins-login" || selected[0].Path != "/j_spring_security_check" {
		t.Fatalf("jenkins match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedPath != "/j_spring_security_check" {
		t.Fatalf("posted path=%q", postedPath)
	}
	if len(hits) != 1 || hits[0].Password != "admin" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunConfluence(t *testing.T) {
	var postedUser, postedDest string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dologin.action" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("os_username")
		postedDest = r.Form.Get("os_destination")
		if postedUser == "wikiadmin" && r.Form.Get("os_password") == "secret" && postedDest == "/" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login.action")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"confluence"})
	if len(selected) != 1 || selected[0].ID != "confluence" || selected[0].Path != "/dologin.action" {
		t.Fatalf("confluence match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "wikiadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "wikiadmin" || postedDest != "/" {
		t.Fatalf("posted user=%q destination=%q", postedUser, postedDest)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "wikiadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunElasticsearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="elasticsearch"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "elastic" && pass == "changeme" {
			_, _ = w.Write([]byte(`{"tagline":"You Know, for Search"}`))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"elasticsearch"})
	if len(selected) != 1 || selected[0].ID != "elasticsearch-http" || selected[0].Path != "/" {
		t.Fatalf("elasticsearch match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "elastic" || hits[0].Password != "changeme" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tagline":"You Know, for Search"}`))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open Elasticsearch HTTP API reported a credential hit: %+v", hits)
	}
}

func TestRunLangfuse(t *testing.T) {
	var postedEmail, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/csrf" {
			_, _ = w.Write([]byte(`{"csrfToken":"lf-token"}`))
			return
		}
		if r.URL.Path != "/api/auth/callback/credentials" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedEmail = r.Form.Get("email")
		postedCSRF = r.Form.Get("csrfToken")
		if postedEmail == "user@example.com" && r.Form.Get("password") == "secret" && postedCSRF == "lf-token" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/api/auth/signin?error=CredentialsSignin")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"langfuse"})
	if len(selected) != 1 || selected[0].ID != "langfuse" {
		t.Fatalf("langfuse match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@example.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedEmail != "user@example.com" || postedCSRF != "lf-token" {
		t.Fatalf("posted email=%q csrf=%q", postedEmail, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@example.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunGradio(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "gradio" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"gradio"})
	if len(selected) != 1 || selected[0].ID != "gradio" || selected[0].Path != "/login" {
		t.Fatalf("gradio match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "gradio", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "gradio" {
		t.Fatalf("posted user=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "gradio", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
