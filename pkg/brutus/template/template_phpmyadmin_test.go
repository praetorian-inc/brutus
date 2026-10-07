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

func TestEmbeddedPhpmyadmin(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "phpmyadmin" {
			if tpl.Path != "/phpmyadmin/index.php" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template phpmyadmin")
}

func TestRunFormUsesPrefetchAndRejectsWeakMatcher(t *testing.T) {
	var postedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/phpmyadmin/index.php" {
			http.NotFound(w, r)
			return
		}
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
