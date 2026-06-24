// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

func TestDDGSearch(t *testing.T) {
	t.Parallel()
	body := `<html><body>
		<p>alice@acme.com</p>
		<p>charlie@mail.acme.com</p>
		<p>unrelated@evil.com</p>
	</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d := newDDGWithEndpoint(enum.NewEnumHTTPClient(5*time.Second), srv.URL)
	emails, err := d.Search(context.Background(), "acme.com")
	require.NoError(t, err)

	assert.Contains(t, emails, "alice@acme.com")
	assert.Contains(t, emails, "charlie@mail.acme.com")
	assert.NotContains(t, emails, "unrelated@evil.com")

	for _, e := range emails {
		assert.Contains(t, e, "@", "every result must be an email, not a host")
	}
}

func TestDDGSearchNonOKStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	d := newDDGWithEndpoint(enum.NewEnumHTTPClient(5*time.Second), srv.URL)
	_, err := d.Search(context.Background(), "acme.com")
	require.Error(t, err)
}
