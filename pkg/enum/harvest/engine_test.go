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

package harvest

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubSource struct {
	name   string
	emails []string
	err    error
}

func (s *stubSource) Name() string { return s.name }
func (s *stubSource) Search(_ context.Context, _ string) ([]string, error) {
	return s.emails, s.err
}

// init registers the stubs that engine tests rely on. Each source name must be
// globally unique because the registry panics on duplicates and test packages
// are loaded once per binary.
func init() {
	Register("eng-a", func(_ *http.Client) Source {
		return &stubSource{name: "eng-a", emails: []string{"jane.doe@acme.com", "it@acme.com"}}
	})
	Register("eng-b", func(_ *http.Client) Source {
		return &stubSource{name: "eng-b", emails: []string{"JANE.DOE@acme.com"}}
	})
	Register("eng-ok", func(_ *http.Client) Source {
		return &stubSource{name: "eng-ok", emails: []string{"a@acme.com"}}
	})
	Register("eng-bad", func(_ *http.Client) Source {
		return &stubSource{name: "eng-bad", err: errors.New("boom")}
	})
}

func TestHarvestAggregatesAndScores(t *testing.T) {
	t.Parallel()
	rep, err := Harvest(context.Background(), Options{
		Domain:  "acme.com",
		Sources: []string{"eng-a", "eng-b"},
		Threads: 2,
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	require.Len(t, rep.Hits, 2)
	// Sorted Count desc: jane.doe (2) before it@ (1).
	assert.Equal(t, "jane.doe@acme.com", rep.Hits[0].Email)
	assert.Equal(t, 2, rep.Hits[0].Count)
	assert.Equal(t, []string{"eng-a", "eng-b"}, rep.Hits[0].Sources)
	assert.Equal(t, 1, rep.Hits[1].Count)
}

func TestHarvestSourceErrorIsIsolated(t *testing.T) {
	t.Parallel()
	rep, err := Harvest(context.Background(), Options{
		Domain:  "acme.com",
		Sources: []string{"eng-ok", "eng-bad"},
		Threads: 2,
		Timeout: time.Second,
	})
	require.NoError(t, err, "a single source error must not fail the run")
	require.Len(t, rep.Hits, 1)
	assert.Equal(t, "a@acme.com", rep.Hits[0].Email)
}

func TestHarvestUnknownSource(t *testing.T) {
	t.Parallel()
	_, err := Harvest(context.Background(), Options{
		Domain:  "acme.com",
		Sources: []string{"does-not-exist"},
		Threads: 1,
	})
	require.Error(t, err)
}

func TestHarvestEmptyDomain(t *testing.T) {
	t.Parallel()
	_, err := Harvest(context.Background(), Options{Domain: "", Threads: 1})
	require.Error(t, err)
}
