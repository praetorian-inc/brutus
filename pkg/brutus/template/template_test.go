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
	for _, id := range []string{"tomcat-manager", "grafana-login", "phpmyadmin", "adminer", "fortigate", "gitlab", "pgadmin", "watchguard", "qnap", "synology", "guacamole", "portainer", "hikvision", "unifi", "dahua", "webmin", "gitea", "harbor", "artifactory", "keycloak", "keycloak-wildfly", "rancher", "apc-nmc", "mikrotik", "zyxel", "sonicwall", "tp-link", "draytek", "hp-ilo", "pfsense", "opnsense", "juniper", "bigip", "ivanti", "citrix", "checkpoint", "sitecore", "kentico", "craftcms", "aem", "papercut", "screenconnect", "simplehelp", "veeam", "nakivo", "crushftp", "goanywhere", "moveit", "quest-kace", "exchange", "sharepoint", "adfs", "zimbra", "solarwinds-whd", "manageengine", "beyondtrust-pra", "adcs", "telerik", "commvault", "vmware-horizon", "metabase", "superset", "redash", "airflow", "doccano", "mlflow", "jupyterhub", "open-webui", "dify", "globalprotect"} {
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

func TestRunSitecore(t *testing.T) {
	var postedUser, postedView string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sitecore/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="UserName"><input name="Password"><input name="__VIEWSTATE" value="vs123">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("UserName")
		postedView = r.Form.Get("__VIEWSTATE")
		if postedUser == "admin" && r.Form.Get("Password") == "b" && postedView == "vs123" {
			w.Header().Set("Location", "/sitecore/shell")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/sitecore/login")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("Login failed"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"sitecore"})
	if len(selected) != 1 || selected[0].ID != "sitecore" {
		t.Fatalf("sitecore match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedView != "vs123" {
		t.Fatalf("posted user=%q viewstate=%q", postedUser, postedView)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "b" {
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

func TestRunKentico(t *testing.T) {
	var postedUser, postedView string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/CMSPages/logon.aspx" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="Login1$UserName"><input name="Login1$Password"><input name="__VIEWSTATE" value="kvs">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("Login1$UserName")
		postedView = r.Form.Get("__VIEWSTATE")
		if postedUser == "administrator" && r.Form.Get("Login1$Password") == "secret" && postedView == "kvs" {
			w.Header().Set("Location", "/Admin/CMSAdministration.aspx")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/CMSPages/logon.aspx")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"kentico-cms"})
	if len(selected) != 1 || selected[0].ID != "kentico" {
		t.Fatalf("kentico match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "administrator", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "administrator" || postedView != "kvs" {
		t.Fatalf("posted user=%q viewstate=%q", postedUser, postedView)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "administrator", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunCraftCMS(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="loginName"><input name="password"><input name="CRAFT_CSRF_TOKEN" value="craft-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("loginName")
		postedCSRF = r.Form.Get("CRAFT_CSRF_TOKEN")
		if postedUser == "editor" && r.Form.Get("password") == "secret" && postedCSRF == "craft-token" {
			w.Header().Set("Location", "/admin")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/admin/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"craftcms"})
	if len(selected) != 1 || selected[0].ID != "craftcms" {
		t.Fatalf("craftcms match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "editor", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "editor" || postedCSRF != "craft-token" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "editor", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunAEM(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/libs/granite/core/content/login.html/j_security_check" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("j_username")
		if postedUser == "admin" && r.Form.Get("j_password") == "admin" {
			w.Header().Set("Location", "/aem/start.html")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/libs/granite/core/content/login.html?error=true")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"adobe_experience_manager"})
	if len(selected) != 1 || selected[0].ID != "aem" {
		t.Fatalf("aem match = %+v", selected)
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

func TestRunPaperCut(t *testing.T) {
	var postedUser, postedService string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("inputUsername")
		postedService = r.Form.Get("service")
		if postedUser == "printadmin" && r.Form.Get("inputPassword") == "secret" && postedService == "page/Login" {
			w.Header().Set("Location", "/app?service=page/Home")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/app?service=page/Login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"papercut"})
	if len(selected) != 1 || selected[0].ID != "papercut" {
		t.Fatalf("papercut match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "printadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "printadmin" || postedService != "page/Login" {
		t.Fatalf("posted user=%q service=%q", postedUser, postedService)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "printadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunScreenConnect(t *testing.T) {
	var postedUser, postedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postedPath = r.URL.Path
		if r.URL.Path != "/Login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("UserName")
		if postedUser == "host" && r.Form.Get("Password") == "secret" {
			w.Header().Set("Location", "/Host")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/Login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"screenconnect"})
	if len(selected) != 1 || selected[0].ID != "screenconnect" || selected[0].Path != "/Login" {
		t.Fatalf("screenconnect match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "host", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedPath != "/Login" || postedUser != "host" {
		t.Fatalf("posted path=%q user=%q", postedPath, postedUser)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "host", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunSimpleHelp(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/technician" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "tech" && r.Form.Get("password") == "secret" {
			w.Header().Set("Set-Cookie", "session=abc; Path=/")
			_, _ = w.Write([]byte("technician console"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid password"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"simplehelp"})
	if len(selected) != 1 || selected[0].ID != "simplehelp" {
		t.Fatalf("simplehelp match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "tech", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "tech" {
		t.Fatalf("posted user=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "tech", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunVeeam(t *testing.T) {
	var postedUser, postedView string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login.aspx" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="txtLogin"><input name="txtPassword"><input name="__VIEWSTATE" value="veeam-vs">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("txtLogin")
		postedView = r.Form.Get("__VIEWSTATE")
		if postedUser == "veeamadmin" && r.Form.Get("txtPassword") == "secret" && postedView == "veeam-vs" {
			w.Header().Set("Location", "/default.aspx")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login.aspx")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"veeam_backup_enterprise_manager_web"})
	if len(selected) != 1 || selected[0].ID != "veeam" {
		t.Fatalf("veeam match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "veeamadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "veeamadmin" || postedView != "veeam-vs" {
		t.Fatalf("posted user=%q viewstate=%q", postedUser, postedView)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "veeamadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunNakivo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/c/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"username":"director"`) && strings.Contains(raw, `"password":"secret"`) {
			_, _ = w.Write([]byte(`{"token":"abc"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"invalid credentials"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"nakivo"})
	if len(selected) != 1 || selected[0].ID != "nakivo" {
		t.Fatalf("nakivo match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "director", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "director" || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "director", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunCrushFTP(t *testing.T) {
	var postedUser, postedCommand string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/WebInterface/function/" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedCommand = r.Form.Get("command")
		if postedUser == "crushadmin" && r.Form.Get("password") == "secret" && postedCommand == "login" {
			_, _ = w.Write([]byte(`<response>success</response>`))
			return
		}
		_, _ = w.Write([]byte(`<response>failure</response>`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"crushftp"})
	if len(selected) != 1 || selected[0].ID != "crushftp" {
		t.Fatalf("crushftp match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "crushadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "crushadmin" || postedCommand != "login" {
		t.Fatalf("posted user=%q command=%q", postedUser, postedCommand)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "crushadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunGoAnywhere(t *testing.T) {
	var postedUser, postedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postedPath = r.URL.Path
		if r.URL.Path != "/goanywhere/auth/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "mftadmin" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/goanywhere/home")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/goanywhere/auth/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"goanywhere"})
	if len(selected) != 1 || selected[0].ID != "goanywhere" || selected[0].Path != "/goanywhere/auth/login" {
		t.Fatalf("goanywhere match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "mftadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedPath != "/goanywhere/auth/login" || postedUser != "mftadmin" {
		t.Fatalf("posted path=%q user=%q", postedPath, postedUser)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "mftadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunMOVEit(t *testing.T) {
	var postedUser, postedTx, postedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postedPath = r.URL.Path
		if r.URL.Path != "/human.aspx" || r.Method != http.MethodPost || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("arg01")
		postedTx = r.Form.Get("transaction")
		if postedUser == "moveituser" && r.Form.Get("arg02") == "secret" && postedTx == "signon" && r.Form.Get("arg12") == "signon" {
			w.Header().Set("Location", "/human.aspx?arg12=home")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<input name="arg02">Invalid username/password`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"moveit"})
	if len(selected) != 1 || selected[0].ID != "moveit" || selected[0].Path != "/human.aspx" {
		t.Fatalf("moveit match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "moveituser", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedPath != "/human.aspx" || postedUser != "moveituser" || postedTx != "signon" {
		t.Fatalf("posted path=%q user=%q transaction=%q", postedPath, postedUser, postedTx)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "moveituser", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunQuestKACE(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("userName")
		if postedUser == "kaceadmin" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/adminui/summary")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<form action="/admin">Login failed</form>`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"quest-kace-sma"})
	if len(selected) != 1 || selected[0].ID != "quest-kace" {
		t.Fatalf("quest-kace match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "kaceadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "kaceadmin" {
		t.Fatalf("posted user=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "kaceadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunExchange(t *testing.T) {
	var postedUser, postedDest string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/owa/auth.owa" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedDest = r.Form.Get("destination")
		if postedUser == "user@contoso.com" && r.Form.Get("password") == "secret" && postedDest == "/owa/" {
			w.Header().Set("Location", "/owa/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/owa/auth/logon.aspx?reason=2")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"exchange_server"})
	if len(selected) != 1 || selected[0].ID != "exchange" {
		t.Fatalf("exchange match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@contoso.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "user@contoso.com" || postedDest != "/owa/" {
		t.Fatalf("posted user=%q destination=%q", postedUser, postedDest)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@contoso.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunSharePoint(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_layouts/15/Authenticate.aspx" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "spadmin" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/_layouts/15/start.aspx")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/_layouts/15/Authenticate.aspx?Source=/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"sharepoint"})
	if len(selected) != 1 || selected[0].ID != "sharepoint" {
		t.Fatalf("sharepoint match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "spadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "spadmin" {
		t.Fatalf("posted user=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "spadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunADFS(t *testing.T) {
	var postedUser, postedMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adfs/ls/" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("UserName")
		postedMethod = r.Form.Get("AuthMethod")
		if postedUser == "user@contoso.com" && r.Form.Get("Password") == "secret" && postedMethod == "FormsAuthentication" {
			w.Header().Set("Set-Cookie", "MSISAuth=abc; Path=/adfs; Secure")
			w.Header().Set("Location", "/adfs/ls/?wa=wsignin1.0")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<span id="errorText">Incorrect user ID or password</span>`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"adfs"})
	if len(selected) != 1 || selected[0].ID != "adfs" {
		t.Fatalf("adfs match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@contoso.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "user@contoso.com" || postedMethod != "FormsAuthentication" {
		t.Fatalf("posted user=%q method=%q", postedUser, postedMethod)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@contoso.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunZimbra(t *testing.T) {
	var postedUser, postedOp string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zimbra/" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedOp = r.Form.Get("loginOp")
		if postedUser == "user@example.com" && r.Form.Get("password") == "secret" && postedOp == "login" {
			w.Header().Set("Set-Cookie", "ZM_AUTH_TOKEN=abc; Path=/; Secure")
			w.Header().Set("Location", "/zimbra/mail")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid username or password"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"zimbra"})
	if len(selected) != 1 || selected[0].ID != "zimbra" {
		t.Fatalf("zimbra match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@example.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "user@example.com" || postedOp != "login" {
		t.Fatalf("posted user=%q loginOp=%q", postedUser, postedOp)
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

func TestRunSolarWindsWHD(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/helpdesk/WebObjects/Helpdesk.woa" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "admin" && r.Form.Get("password") == "admin" {
			w.Header().Set("Location", "/helpdesk/WebObjects/Helpdesk.woa/wo/1.0")
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
	selected := Match(tpls, []string{"solarwinds-whd"})
	if len(selected) != 1 || selected[0].ID != "solarwinds-whd" {
		t.Fatalf("solarwinds-whd match = %+v", selected)
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

func TestRunManageEngine(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/j_security_check" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("j_username")
		if postedUser == "admin" && r.Form.Get("j_password") == "admin" {
			w.Header().Set("Location", "/HomePage.do")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/showlogin.cc?error=invalid")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"manageengine"})
	if len(selected) != 1 || selected[0].ID != "manageengine" {
		t.Fatalf("manageengine match = %+v", selected)
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

func TestRunBeyondTrust(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "admin" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/console")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login/login?failed=1")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"beyondtrust-pra"})
	if len(selected) != 1 || selected[0].ID != "beyondtrust-pra" {
		t.Fatalf("beyondtrust match = %+v", selected)
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

func TestRunADCS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certsrv/" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="certsrv"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "certadmin" && pass == "secret" {
			_, _ = w.Write([]byte("Microsoft Certificate Services"))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"adcs-web-enrollment"})
	if len(selected) != 1 || selected[0].ID != "adcs" {
		t.Fatalf("adcs match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "certadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestRunTelerik(t *testing.T) {
	var postedUser, postedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Account/Login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="__RequestVerificationToken" value="telerik-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("UserName")
		postedToken = r.Form.Get("__RequestVerificationToken")
		if postedUser == "reportadmin" && r.Form.Get("Password") == "secret" && postedToken == "telerik-token" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/Account/Login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"telerik-report-server"})
	if len(selected) != 1 || selected[0].ID != "telerik" {
		t.Fatalf("telerik match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "reportadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "reportadmin" || postedToken != "telerik-token" {
		t.Fatalf("posted user=%q token=%q", postedUser, postedToken)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestRunCommvault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webconsole/api/Login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"username":"cvadmin"`) && strings.Contains(raw, `"password":"secret"`) {
			_, _ = w.Write([]byte(`{"token":"abc"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"commvault"})
	if len(selected) != 1 || selected[0].ID != "commvault" {
		t.Fatalf("commvault match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "cvadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestRunVMwareHorizon(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/portal/webclient/index.html" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		if postedUser == "horizon" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/portal/webclient/desktop")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/portal/webclient/index.html")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"vmware-horizon"})
	if len(selected) != 1 || selected[0].ID != "vmware-horizon" {
		t.Fatalf("horizon match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "horizon", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "horizon" {
		t.Fatalf("posted user=%q", postedUser)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestRunMetabase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/session" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"username":"analyst@example.com"`) && strings.Contains(raw, `"password":"secret"`) {
			_, _ = w.Write([]byte(`{"id":"session-id"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":{"password":"did not match stored password"}}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"metabase"})
	if len(selected) != 1 || selected[0].ID != "metabase" {
		t.Fatalf("metabase match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "analyst@example.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "analyst@example.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunSuperset(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="username"><input name="password"><input name="csrf_token" value="superset-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedCSRF = r.Form.Get("csrf_token")
		if postedUser == "admin" && r.Form.Get("password") == "secret" && postedCSRF == "superset-token" {
			w.Header().Set("Location", "/superset/welcome/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"superset"})
	if len(selected) != 1 || selected[0].ID != "superset" {
		t.Fatalf("superset match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedCSRF != "superset-token" {
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

func TestRunRedash(t *testing.T) {
	var postedEmail, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="email"><input name="password"><input name="csrf_token" value="redash-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedEmail = r.Form.Get("email")
		postedCSRF = r.Form.Get("csrf_token")
		if postedEmail == "analyst@example.com" && r.Form.Get("password") == "secret" && postedCSRF == "redash-token" {
			w.Header().Set("Location", "/queries")
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
	selected := Match(tpls, []string{"redash"})
	if len(selected) != 1 || selected[0].ID != "redash" {
		t.Fatalf("redash match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "analyst@example.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedEmail != "analyst@example.com" || postedCSRF != "redash-token" {
		t.Fatalf("posted email=%q csrf=%q", postedEmail, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "analyst@example.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunAirflow(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="username"><input name="password"><input name="csrf_token" value="airflow-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedCSRF = r.Form.Get("csrf_token")
		if postedUser == "airflow" && r.Form.Get("password") == "secret" && postedCSRF == "airflow-token" {
			w.Header().Set("Location", "/home")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"airflow"})
	if len(selected) != 1 || selected[0].ID != "airflow" {
		t.Fatalf("airflow match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "airflow", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "airflow" || postedCSRF != "airflow-token" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "airflow", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunDoccano(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth-token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"username":"annotator"`) && strings.Contains(raw, `"password":"secret"`) {
			_, _ = w.Write([]byte(`{"token":"abc"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"non_field_errors":["Unable to log in with provided credentials."]}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"doccano"})
	if len(selected) != 1 || selected[0].ID != "doccano" {
		t.Fatalf("doccano match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "annotator", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "annotator", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunMLflow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/2.0/mlflow/experiments/search" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="mlflow"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "mlflow" && pass == "secret" {
			_, _ = w.Write([]byte(`{"experiments":[]}`))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"mlflow"})
	if len(selected) != 1 || selected[0].ID != "mlflow" {
		t.Fatalf("mlflow match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "mlflow", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"experiments":[]}`))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "mlflow", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open MLflow search reported a credential hit: %+v", hits)
	}
}

func TestRunJupyterHub(t *testing.T) {
	var postedUser, postedXSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hub/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="username"><input name="password"><input name="_xsrf" value="hub-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedXSRF = r.Form.Get("_xsrf")
		if postedUser == "jupyter" && r.Form.Get("password") == "secret" && postedXSRF == "hub-token" {
			w.Header().Set("Location", "/hub/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/hub/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"jupyterhub"})
	if len(selected) != 1 || selected[0].ID != "jupyterhub" {
		t.Fatalf("jupyterhub match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "jupyter", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "jupyter" || postedXSRF != "hub-token" {
		t.Fatalf("posted user=%q xsrf=%q", postedUser, postedXSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "jupyter", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunOpenWebUI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auths/signin" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"email":"user@example.com"`) && strings.Contains(raw, `"password":"secret"`) {
			_, _ = w.Write([]byte(`{"token":"abc","email":"user@example.com"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"Invalid credentials"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"open_webui"})
	if len(selected) != 1 || selected[0].ID != "open-webui" {
		t.Fatalf("open-webui match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "user@example.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
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

func TestRunDify(t *testing.T) {
	var postedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postedPath = r.URL.Path
		if r.URL.Path != "/console/api/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"email":"admin@example.com"`) && strings.Contains(raw, `"password":"secret"`) {
			_, _ = w.Write([]byte(`{"result":"success","data":{"access_token":"abc"}}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid email or password"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"dify"})
	if len(selected) != 1 || selected[0].ID != "dify" || selected[0].Path != "/console/api/login" {
		t.Fatalf("dify match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin@example.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedPath != "/console/api/login" {
		t.Fatalf("posted path=%q", postedPath)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
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

func TestRunFortiGate(t *testing.T) {
	var postedUser, postedAjax string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/remote/logincheck" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedAjax = r.Form.Get("ajax")
		if postedUser == "admin" && r.Form.Get("credential") == "admin" && postedAjax == "1" {
			_, _ = w.Write([]byte("ret=1,redir=/remote/hostcheck"))
			return
		}
		_, _ = w.Write([]byte("ret=0"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"fortinet-fortigate"})
	if len(selected) != 1 || selected[0].ID != "fortigate" || selected[0].Path != "/remote/logincheck" {
		t.Fatalf("fortigate match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedAjax != "1" {
		t.Fatalf("posted user=%q ajax=%q", postedUser, postedAjax)
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

func TestRunGlobalProtect(t *testing.T) {
	var postedUser, postedOS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/global-protect/getconfig.esp" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("user")
		postedOS = r.Form.Get("clientos")
		if postedUser == "gpuser" && r.Form.Get("passwd") == "secret" && postedOS == "Windows" {
			_, _ = w.Write([]byte(`<response><status>Success</status><portal-userauthcookie>abc</portal-userauthcookie></response>`))
			return
		}
		_, _ = w.Write([]byte(`<response status="error"><portal-prelogin><status>Error</status><msg>auth-failed</msg></portal-prelogin></response>`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"palo-alto-globalprotect"})
	if len(selected) != 1 || selected[0].ID != "globalprotect" {
		t.Fatalf("globalprotect match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "gpuser", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "gpuser" || postedOS != "Windows" {
		t.Fatalf("posted user=%q clientos=%q", postedUser, postedOS)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "gpuser", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
