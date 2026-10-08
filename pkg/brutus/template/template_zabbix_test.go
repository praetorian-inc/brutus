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

// TestRunZabbix models the appliance login. To troubleshoot against the real app:
//
//	docker run -d --name zabbix --platform linux/amd64 -p 80:80 zabbix/zabbix-appliance
//
// Wait until http://127.0.0.1/index.php shows the sign-in form. Admin:zabbix
// redirects to zabbix.php?action=dashboard.view. The username is case-sensitive.
func TestRunZabbix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.php" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			_, _ = w.Write([]byte(`<title>Zabbix: Zabbix</title><form action="index.php"><input name="name"><input name="password"></form>`))
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if r.Form.Get("name") == "Admin" && r.Form.Get("password") == "zabbix" {
			http.Redirect(w, r, "zabbix.php?action=dashboard.view", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<title>Zabbix: Zabbix</title>Incorrect user name or password`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"zabbix"})
	if len(selected) != 1 || selected[0].ID != "zabbix" {
		t.Fatalf("zabbix match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "Admin" || hits[0].Password != "zabbix" {
		t.Fatalf("hits = %+v", hits)
	}
}
