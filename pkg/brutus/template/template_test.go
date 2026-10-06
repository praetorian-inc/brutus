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
	"io"
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
	if len(tpls) < 10 {
		t.Fatalf("embedded templates = %d, want at least 10", len(tpls))
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
	for _, id := range []string{"tomcat-manager", "grafana-login", "phpmyadmin", "adminer", "fortigate", "gitlab", "pgadmin", "watchguard", "qnap", "synology", "guacamole", "portainer", "hikvision", "unifi", "dahua", "webmin", "gitea", "harbor", "artifactory", "keycloak", "keycloak-wildfly", "rancher", "apc-nmc", "mikrotik", "zyxel", "sonicwall", "tp-link", "draytek", "hp-ilo", "pfsense", "opnsense", "juniper", "bigip", "ivanti", "citrix", "checkpoint"} {
		if !ids[id] {
			t.Errorf("missing embedded template %s", id)
		}
	}
}

func TestMatchRequiresTechnology(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if got := Match(tpls, nil); len(got) != 0 {
		t.Fatalf("empty technologies matched %d templates", len(got))
	}
	got := Match(tpls, []string{"Adminer"})
	if len(got) != 1 || got[0].ID != "adminer" {
		t.Fatalf("adminer match = %+v", got)
	}
	if len(Match(tpls, []string{"nginx"})) != 0 {
		t.Fatal("unrelated technology must not select a template")
	}
}

func TestRunBasicHitAndOpenSkip(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manager/html" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="tomcat"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sawAuth = user + ":" + pass
		if user == "tomcat" && pass == "tomcat" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Tomcat Web Application Manager"))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	hits, err := Run(context.Background(), srv.URL, Match(tpls, []string{"tomcat"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "tomcat" || hits[0].Password != "tomcat" {
		t.Fatalf("hits = %+v, last auth %q", hits, sawAuth)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, Match(tpls, []string{"tomcat"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open path reported hits: %+v", hits)
	}
}

func TestRunFormUsesPrefetchAndRejectsWeakMatcher(t *testing.T) {
	var postedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="token" value="abc123">`))
			return
		}
		_ = r.ParseForm()
		postedToken = r.Form.Get("token")
		if r.Form.Get("pma_password") == "root" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("server databases"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Access denied"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	hits, err := Run(context.Background(), srv.URL, Match(tpls, []string{"phpmyadmin"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedToken != "abc123" {
		t.Fatalf("prefetch token = %q", postedToken)
	}
	if len(hits) != 1 || hits[0].Password != "root" {
		t.Fatalf("hits = %+v", hits)
	}

	weak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("always ok"))
	}))
	defer weak.Close()
	hits, err = Run(context.Background(), weak.URL, Match(tpls, []string{"phpmyadmin"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("weak matcher reported hits: %+v", hits)
	}
}

func TestRunJSON(t *testing.T) {
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

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	hits, err := Run(context.Background(), srv.URL, Match(tpls, []string{"grafana"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].TemplateID != "grafana-login" {
		t.Fatalf("hits = %+v", hits)
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

func TestRunPgAdmin(t *testing.T) {
	var postedToken, postedEmail string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form><input name="csrf_token" value="pga-token"><title>pgAdmin 4</title></form>`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedToken = r.Form.Get("csrf_token")
		postedEmail = r.Form.Get("email")
		if r.Form.Get("email") == "admin@example.com" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/browser/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login?error=1")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("invalid login"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"pgadmin-login"})
	if len(selected) != 1 || selected[0].ID != "pgadmin" {
		t.Fatalf("pgadmin-login match = %+v", selected)
	}
	creds := []Pair{{Username: "admin@example.com", Password: "secret"}}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second, Creds: creds})
	if err != nil {
		t.Fatal(err)
	}
	if postedToken != "pga-token" || postedEmail != "admin@example.com" {
		t.Fatalf("posted token=%q email=%q", postedToken, postedEmail)
	}
	if len(hits) != 1 || hits[0].Username != "admin@example.com" || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin@example.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunWatchGuard(t *testing.T) {
	var postedUser, postedDomain string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("user")
		postedDomain = r.Form.Get("domain")
		if r.Form.Get("user") == "admin" && r.Form.Get("password") == "secret" && r.Form.Get("domain") == "Firebox-DB" {
			w.Header().Set("Location", "/auth/dashboard")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/auth/login?failed=1")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"watchguard-firebox"})
	if len(selected) != 1 || selected[0].ID != "watchguard" {
		t.Fatalf("watchguard match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedDomain != "Firebox-DB" {
		t.Fatalf("posted user=%q domain=%q", postedUser, postedDomain)
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

func TestRunQNAP(t *testing.T) {
	var postedUser, postedPwd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/authLogin.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("user")
		postedPwd = r.Form.Get("pwd")
		w.Header().Set("Content-Type", "text/xml")
		if postedUser == "admin" && postedPwd == "admin" {
			_, _ = w.Write([]byte(`<QDocRoot><authPassed><![CDATA[1]]></authPassed><authSid><![CDATA[sid]]></authSid></QDocRoot>`))
			return
		}
		_, _ = w.Write([]byte(`<QDocRoot><authPassed><![CDATA[0]]></authPassed></QDocRoot>`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"qnap-qts"})
	if len(selected) != 1 || selected[0].ID != "qnap" {
		t.Fatalf("qnap match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedPwd != "admin" {
		t.Fatalf("posted user=%q pwd=%q", postedUser, postedPwd)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "admin" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestRunSynology(t *testing.T) {
	var postedAccount, postedAPI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webapi/auth.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedAccount = r.Form.Get("account")
		postedAPI = r.Form.Get("api")
		w.Header().Set("Content-Type", "application/json")
		if postedAccount == "nasadmin" && r.Form.Get("passwd") == "secret" && postedAPI == "SYNO.API.Auth" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"abc"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":400}}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"synology-dsm"})
	if len(selected) != 1 || selected[0].ID != "synology" {
		t.Fatalf("synology match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "nasadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedAccount != "nasadmin" || postedAPI != "SYNO.API.Auth" {
		t.Fatalf("posted account=%q api=%q", postedAccount, postedAPI)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "nasadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunGuacamole(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/guacamole/api/tokens" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "guacadmin" && r.Form.Get("password") == "guacadmin" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authToken":"token","username":"guacadmin"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Invalid login"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"guacamole-login"})
	if len(selected) != 1 || selected[0].ID != "guacamole" {
		t.Fatalf("guacamole match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "guacadmin" {
		t.Fatalf("posted username=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Username != "guacadmin" || hits[0].Password != "guacadmin" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "guacadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunPortainer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"Username":"admin"`) && strings.Contains(raw, `"Password":"secret"`) {
			_, _ = w.Write([]byte(`{"jwt":"token"}`))
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Invalid credentials","details":"Unauthorized"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"portainer"})
	if len(selected) != 1 || selected[0].ID != "portainer" {
		t.Fatalf("portainer match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "secret" {
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

func TestRunHikvision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ISAPI/System/deviceInfo" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Hikvision"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "admin" && pass == "12345" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema"><model>DS-2CD</model></DeviceInfo>`))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"hikvision"})
	if len(selected) != 1 || selected[0].ID != "hikvision" {
		t.Fatalf("hikvision match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "12345" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema"/>`))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("unauthenticated ISAPI reported a credential hit: %+v", hits)
	}
}

func TestRunUniFi(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"username":"ubnt"`) && strings.Contains(raw, `"password":"ubnt"`) {
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"meta":{"rc":"error","msg":"api.err.Invalid"},"data":[]}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"unifi-controller"})
	if len(selected) != 1 || selected[0].ID != "unifi" {
		t.Fatalf("unifi match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "ubnt" || hits[0].Password != "ubnt" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "ubnt", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunDahua(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/magicBox.cgi" || r.URL.Query().Get("action") != "getDeviceType" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Dahua"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "admin" && pass == "admin" {
			_, _ = w.Write([]byte("IPC-HDW"))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"dahua"})
	if len(selected) != 1 || selected[0].ID != "dahua" {
		t.Fatalf("dahua match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "admin" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("IPC-HDW"))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("unauthenticated magicBox reported a credential hit: %+v", hits)
	}
}

func TestRunWebmin(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/session_login.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("user")
		if postedUser == "root" && r.Form.Get("pass") == "secret" {
			w.Header().Set("Location", "/")
			w.Header().Set("Set-Cookie", "sid=abc")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/session_login.cgi?failed=1")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("Login to Webmin failed"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"webmin"})
	if len(selected) != 1 || selected[0].ID != "webmin" {
		t.Fatalf("webmin match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "root", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "root" {
		t.Fatalf("posted user=%q", postedUser)
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

func TestRunHarbor(t *testing.T) {
	var postedPrincipal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/c/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedPrincipal = r.Form.Get("principal")
		if postedPrincipal == "admin" && r.Form.Get("password") == "Harbor12345" {
			w.Header().Set("Set-Cookie", "sid=abc; Path=/")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"harbor"})
	if len(selected) != 1 || selected[0].ID != "harbor" {
		t.Fatalf("harbor match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedPrincipal != "admin" {
		t.Fatalf("posted principal=%q", postedPrincipal)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "Harbor12345" {
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

func TestRunArtifactory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/artifactory/api/system/ping" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Artifactory"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "admin" && pass == "password" {
			_, _ = w.Write([]byte("OK"))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"artifactory"})
	if len(selected) != 1 || selected[0].ID != "artifactory" {
		t.Fatalf("artifactory match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "password" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open Artifactory ping reported a credential hit: %+v", hits)
	}
}

func TestRunKeycloak(t *testing.T) {
	var postedGrant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/master/protocol/openid-connect/token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedGrant = r.Form.Get("grant_type")
		if r.Form.Get("username") == "kcadmin" && r.Form.Get("password") == "secret" && r.Form.Get("client_id") == "admin-cli" && postedGrant == "password" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid user credentials"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"keycloak"})
	modern := 0
	for _, tplt := range selected {
		if tplt.ID == "keycloak" || tplt.ID == "keycloak-wildfly" {
			modern++
		}
	}
	if modern != 2 {
		t.Fatalf("keycloak match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "kcadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedGrant != "password" {
		t.Fatalf("posted grant_type=%q", postedGrant)
	}
	if len(hits) != 1 || hits[0].TemplateID != "keycloak" || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "kcadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunRancher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3-public/localProviders/local" || r.URL.Query().Get("action") != "login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"username":"rancher"`) && strings.Contains(raw, `"password":"secret"`) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"token-abc","type":"token"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","status":"401","message":"Invalid username or password"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"rancher_dashboard"})
	if len(selected) != 1 || selected[0].ID != "rancher" {
		t.Fatalf("rancher match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "rancher", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "rancher", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunAPCNMC(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Forms/login1" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("login_username")
		if postedUser == "apc" && r.Form.Get("login_password") == "apc" {
			w.Header().Set("Location", "/home.htm")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		w.Header().Set("Location", "/logon.htm")
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"apc-nmc"})
	if len(selected) != 1 || selected[0].ID != "apc-nmc" {
		t.Fatalf("apc-nmc match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "apc" {
		t.Fatalf("posted user=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Username != "apc" || hits[0].Password != "apc" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "apc", Password: "wrong"}},
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

func TestRunZyxel(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/weblogin.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "admin" && r.Form.Get("password") == "1234" {
			w.Header().Set("Location", "/ext-js/index.html")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/weblogin.cgi")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"zyxel-firewall"})
	if len(selected) != 1 || selected[0].ID != "zyxel" {
		t.Fatalf("zyxel match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" {
		t.Fatalf("posted username=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "1234" {
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

func TestRunSonicWall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sonicos/auth" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"user":"admin"`) && strings.Contains(raw, `"password":"password"`) {
			_, _ = w.Write([]byte(`{"status":{"success":true,"info":[{"message":"Success."}]}}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":{"success":false,"info":[{"message":"Authentication failed"}]}}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"sonicwall"})
	if len(selected) != 1 || selected[0].ID != "sonicwall" {
		t.Fatalf("sonicwall match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "password" {
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

func TestRunTPLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webpages/login.html" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="TP-LINK"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "admin" && pass == "admin" {
			_, _ = w.Write([]byte("<title>TP-LINK</title>"))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"tp-link-router"})
	if len(selected) != 1 || selected[0].ID != "tp-link" {
		t.Fatalf("tp-link match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "admin" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>TP-LINK</title>"))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open TP-Link login page reported a credential hit: %+v", hits)
	}
}

func TestRunDraytek(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/wlogin.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("aa")
		if postedUser == "admin" && r.Form.Get("ab") == "admin" {
			w.Header().Set("Location", "/index.htm")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/weblogin.htm")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"draytek-vigor"})
	if len(selected) != 1 || selected[0].ID != "draytek" {
		t.Fatalf("draytek match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" {
		t.Fatalf("posted user=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "admin" {
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

func TestRunHPiLO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/SessionService/Sessions" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"UserName":"Administrator"`) && strings.Contains(raw, `"Password":"secret"`) {
			w.Header().Set("X-Auth-Token", "token")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/SessionService/Sessions/1","Id":"1"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"unauthorized"}}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"hp-ilo"})
	if len(selected) != 1 || selected[0].ID != "hp-ilo" {
		t.Fatalf("hp-ilo match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "Administrator", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "Administrator" || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "Administrator", Password: "wrong"}},
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

func TestRunBigIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mgmt/tm/sys/version" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="BIG-IP"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "admin" && pass == "admin" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"kind":"tm:sys:version:versionstats"}`))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"f5-bigip"})
	if len(selected) != 1 || selected[0].ID != "bigip" {
		t.Fatalf("bigip match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "admin" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"kind":"tm:sys:version:versionstats"}`))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open BIG-IP version endpoint reported a credential hit: %+v", hits)
	}
}

func TestRunIvanti(t *testing.T) {
	var postedUser, postedRealm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dana-na/auth/url_default/login.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedRealm = r.Form.Get("realm")
		if postedUser == "vpnuser" && r.Form.Get("password") == "secret" && postedRealm == "Users" {
			w.Header().Set("Location", "/dana/home/index.cgi")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/dana-na/auth/url_default/welcome.cgi?p=failed")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"ivanti-connect-secure"})
	if len(selected) != 1 || selected[0].ID != "ivanti" {
		t.Fatalf("ivanti match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "vpnuser", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "vpnuser" || postedRealm != "Users" {
		t.Fatalf("posted user=%q realm=%q", postedUser, postedRealm)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "vpnuser", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunCitrix(t *testing.T) {
	var postedLogin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedLogin = r.Form.Get("login")
		if postedLogin == "nsroot" && r.Form.Get("passwd") == "nsroot" {
			w.Header().Set("Set-Cookie", "NSC_AAAC=abc; Path=/")
			w.Header().Set("Location", "/menu/neo")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Incorrect credentials"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"citrix-netscaler"})
	if len(selected) != 1 || selected[0].ID != "citrix" {
		t.Fatalf("citrix match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedLogin != "nsroot" {
		t.Fatalf("posted login=%q", postedLogin)
	}
	if len(hits) != 1 || hits[0].Username != "nsroot" || hits[0].Password != "nsroot" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "nsroot", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunCheckPoint(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/home.tcl" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("userName")
		if postedUser == "admin" && r.Form.Get("userPass") == "secret" {
			w.Header().Set("Location", "/cgi-bin/home.tcl?session=1")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<input name="userPass">Invalid user name or password`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"checkpoint-gateway"})
	if len(selected) != 1 || selected[0].ID != "checkpoint" {
		t.Fatalf("checkpoint match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" {
		t.Fatalf("posted user=%q", postedUser)
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
