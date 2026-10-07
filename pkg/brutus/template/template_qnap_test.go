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

func TestEmbeddedQnap(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "qnap" {
			if tpl.Path != "/cgi-bin/authLogin.cgi" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template qnap")
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
