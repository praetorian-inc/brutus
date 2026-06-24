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

func TestBraveSearch(t *testing.T) {
	t.Parallel()
	body := `<html><body>
		<p>dana@acme.com</p>
		<p>infosec@acme.com</p>
		<p>spam@spam.net</p>
	</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	b := newBraveWithEndpoint(enum.NewEnumHTTPClient(5*time.Second), srv.URL)
	emails, err := b.Search(context.Background(), "acme.com")
	require.NoError(t, err)

	assert.Contains(t, emails, "dana@acme.com")
	assert.Contains(t, emails, "infosec@acme.com")
	assert.NotContains(t, emails, "spam@spam.net")

	for _, e := range emails {
		assert.Contains(t, e, "@", "every result must be an email, not a host")
	}
}

func TestBraveSearchNonOKStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()

	b := newBraveWithEndpoint(enum.NewEnumHTTPClient(5*time.Second), srv.URL)
	_, err := b.Search(context.Background(), "acme.com")
	require.Error(t, err)
}
