package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAddHeadersOnlyAllowsConfiguredOrigins(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	tests := []struct {
		name              string
		origin            string
		allowedOrigins    []string
		wantOrigin        string
		wantCredentials   string
		wantVary          string
	}{
		{
			name:            "configured origin",
			origin:          "https://app.example",
			allowedOrigins:  []string{"https://app.example"},
			wantOrigin:      "https://app.example",
			wantCredentials: "true",
			wantVary:        "Origin",
		},
		{
			name:            "unconfigured origin",
			origin:          "https://evil.example",
			allowedOrigins:  []string{"https://app.example"},
		},
		{
			name:            "wildcard configuration",
			origin:          "https://evil.example",
			allowedOrigins:  []string{"*"},
		},
		{
			name:            "origin with a path",
			origin:          "https://app.example/path",
			allowedOrigins:  []string{"https://app.example"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v0/get-global-feed", nil)
			req.Header.Set("Origin", test.origin)
			res := httptest.NewRecorder()

			AddHeaders(next, test.allowedOrigins).ServeHTTP(res, req)

			if res.Header().Get("Access-Control-Allow-Origin") != test.wantOrigin {
				t.Fatalf("unexpected allow-origin header: got %q, want %q", res.Header().Get("Access-Control-Allow-Origin"), test.wantOrigin)
			}
			if res.Header().Get("Access-Control-Allow-Credentials") != test.wantCredentials {
				t.Fatalf("unexpected credentials header: got %q, want %q", res.Header().Get("Access-Control-Allow-Credentials"), test.wantCredentials)
			}
			if res.Header().Get("Vary") != test.wantVary {
				t.Fatalf("unexpected vary header: got %q, want %q", res.Header().Get("Vary"), test.wantVary)
			}
		})
	}
}

func TestAddHeadersUsesAnExactOriginForVideoUploads(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, RoutePathUploadVideo, nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	AddHeaders(next, []string{"https://app.example"}).ServeHTTP(res, req)

	if got := res.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("unexpected allow-origin header: got %q", got)
	}
	if got := res.Header().Get("Access-Control-Allow-Headers"); got == "*" {
		t.Fatal("video uploads must not emit a wildcard allow-headers value")
	}
}
