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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct{ name string }

func (f *fakeSource) Name() string                                          { return f.name }
func (f *fakeSource) Search(_ context.Context, _ string) ([]string, error) { return nil, nil }

func TestRegisterAndGetSource(t *testing.T) {
	t.Parallel()
	Register("regtest", func(_ *http.Client) Source { return &fakeSource{name: "regtest"} })
	s, err := GetSource("regtest", nil)
	require.NoError(t, err)
	assert.Equal(t, "regtest", s.Name())
}

func TestGetSourceUnknown(t *testing.T) {
	t.Parallel()
	_, err := GetSource("nope-not-registered", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown source")
}

func TestListSourcesSorted(t *testing.T) {
	t.Parallel()
	names := ListSources()
	for i := 1; i < len(names); i++ {
		assert.LessOrEqual(t, names[i-1], names[i], "ListSources must be sorted")
	}
}
