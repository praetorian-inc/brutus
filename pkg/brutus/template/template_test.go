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
	"strings"
	"testing"
	"time"
)

func TestLoadEmbedded(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, tplt := range tpls {
		if ids[tplt.ID] {
			t.Errorf("duplicate template id %s", tplt.ID)
		}
		ids[tplt.ID] = true
		if len(tplt.Nerva) == 0 || !strings.HasPrefix(tplt.Path, "/") {
			t.Errorf("%s missing nerva name or path", tplt.ID)
		}
	}
}

func TestMatchRequiresTechnology(t *testing.T) {
	tpls := []Template{{
		ID:     "fixture",
		Nerva:  []string{"fixture"},
		Method: MethodBasic,
		Path:   "/",
	}}
	if got := Match(tpls, nil); len(got) != 0 {
		t.Fatalf("empty technologies matched %d templates", len(got))
	}
	got := Match(tpls, []string{"Fixture"})
	if len(got) != 1 || got[0].ID != "fixture" {
		t.Fatalf("fixture match = %+v", got)
	}
	if len(Match(tpls, []string{"nginx"})) != 0 {
		t.Fatal("unrelated technology must not select a template")
	}
}

func TestRunBasicExecutor(t *testing.T) {
	tpl := Template{
		ID:     "basic-fixture",
		Name:   "Basic fixture",
		Nerva:  []string{"basic-fixture"},
		Method: MethodBasic,
		Path:   "/secret",
		Creds:  []string{"user:secret", "admin:admin"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secret" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "user" && pass == "secret" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	hits, err := Run(context.Background(), srv.URL, []Template{tpl}, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "user" || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, []Template{tpl}, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open path reported hits: %+v", hits)
	}
}

func TestRunFormExecutor(t *testing.T) {
	tpl := Template{
		ID:            "form-fixture",
		Name:          "Form fixture",
		Nerva:         []string{"form-fixture"},
		Method:        MethodForm,
		Path:          "/login",
		UsernameField: "username",
		PasswordField: "password",
		Prefetch: &Prefetch{
			Path:    "/login",
			Extract: map[string]string{"token": `name="token" value="([^"]+)"`},
		},
		Extra: map[string]string{"token": "{{token}}"},
		Success: Matchers{
			Status:     []int{200},
			Body:       []string{"welcome"},
			BodyAbsent: []string{"access denied"},
		},
		Creds: []string{"user:secret"},
	}
	var postedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="token" value="abc123">`))
			return
		}
		_ = r.ParseForm()
		postedToken = r.Form.Get("token")
		if r.Form.Get("password") == "secret" {
			_, _ = w.Write([]byte("welcome"))
			return
		}
		_, _ = w.Write([]byte("Access denied"))
	}))
	defer srv.Close()

	hits, err := Run(context.Background(), srv.URL, []Template{tpl}, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedToken != "abc123" {
		t.Fatalf("prefetch token = %q", postedToken)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	weak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	}))
	defer weak.Close()
	hits, err = Run(context.Background(), weak.URL, []Template{tpl}, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("weak matcher reported hits: %+v", hits)
	}
}

func TestRunJSONExecutor(t *testing.T) {
	tpl := Template{
		ID:            "json-fixture",
		Name:          "JSON fixture",
		Nerva:         []string{"json-fixture"},
		Method:        MethodJSON,
		Path:          "/login",
		UsernameField: "user",
		PasswordField: "password",
		Success: Matchers{
			Status:     []int{200},
			Body:       []string{"logged in"},
			BodyAbsent: []string{"invalid"},
		},
		Creds: []string{"admin:admin"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 256)
		n, _ := r.Body.Read(body)
		raw := string(body[:n])
		if strings.Contains(raw, `"password":"admin"`) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"Logged in"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid username or password"}`))
	}))
	defer srv.Close()

	hits, err := Run(context.Background(), srv.URL, []Template{tpl}, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].TemplateID != "json-fixture" || hits[0].Password != "admin" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, []Template{tpl}, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}

	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not a login</html>"))
	}))
	defer html.Close()
	hits, err = Run(context.Background(), html.URL, []Template{tpl}, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("unrelated HTML reported a hit: %+v", hits)
	}
}

func TestParseNerva(t *testing.T) {
	in := strings.NewReader(`{"ip":"10.0.0.5","port":443,"protocol":"https","tls":true,"metadata":{"technologies":["fortinet-fortigate"]}}
{"ip":"10.0.0.6","port":22,"protocol":"ssh","metadata":{"technologies":["openssh"]}}
{"url":"http://panel.example","technologies":["adminer"]}
{"ip":"10.0.0.7","port":80,"protocol":"http"}
`)
	got, err := ParseNerva(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("targets = %+v", got)
	}
	if got[0].BaseURL != "https://10.0.0.5:443" || got[0].Technologies[0] != "fortinet-fortigate" {
		t.Fatalf("first target = %+v", got[0])
	}
	if got[1].BaseURL != "http://panel.example" {
		t.Fatalf("second target = %+v", got[1])
	}
}
