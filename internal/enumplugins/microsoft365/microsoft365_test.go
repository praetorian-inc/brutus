package microsoft365

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "microsoft365", p.Name())
}

func TestPlugin_Check_Exists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"IfExistsResult":0,"ThrottleStatus":0}`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "valid@company.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, "microsoft365", result.Service)
	assert.Equal(t, "valid@company.com", result.Email)
}

func TestPlugin_Check_NotExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"IfExistsResult":1,"ThrottleStatus":0}`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "invalid@company.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.False(t, result.Exists)
}

func TestPlugin_Check_Throttled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"IfExistsResult":0,"ThrottleStatus":1}`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "user@company.com", 5*time.Second)

	assert.NotNil(t, result.Error)
}

func TestPlugin_Check_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "user@company.com", 5*time.Second)

	assert.NotNil(t, result.Error)
	assert.False(t, result.Exists)
}
