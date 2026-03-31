package github

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
	assert.Equal(t, "github", p.Name())
}

func TestPlugin_Check_Exists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"testuser","id":12345}`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "testuser@example.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, "github", result.Service)
	assert.Equal(t, "testuser@example.com", result.Email)
}

func TestPlugin_Check_NotExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "nonexistent@example.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.False(t, result.Exists)
}

func TestPlugin_Check_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "user@example.com", 5*time.Second)

	assert.NotNil(t, result.Error)
	assert.False(t, result.Exists)
}

func TestPlugin_Check_InvalidEmail(t *testing.T) {
	p := &Plugin{baseURL: "http://unused"}
	result := p.Check(context.Background(), "noemailformat", 5*time.Second)

	assert.NotNil(t, result.Error)
	assert.False(t, result.Exists)
}
