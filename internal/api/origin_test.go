package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/config"
)

func TestOriginGuard(t *testing.T) {
	s := &Server{Cfg: config.Config{PublicURL: "https://console.example.com"}}
	h := s.originGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	do := func(method, origin, fetchSite string) int {
		r := httptest.NewRequest(method, "/api/tenants/x/deploy", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if c := do("POST", "https://evil.test", ""); c != 403 {
		t.Fatalf("foreign origin: %d", c)
	}
	if c := do("POST", "", "cross-site"); c != 403 {
		t.Fatalf("cross-site fetch: %d", c)
	}
	if c := do("POST", "https://console.example.com", ""); c != 200 {
		t.Fatalf("own origin: %d", c)
	}
	if c := do("POST", "", ""); c != 200 {
		t.Fatalf("no origin (script): %d", c)
	}
	if c := do("GET", "https://evil.test", ""); c != 200 {
		t.Fatalf("GET should pass: %d", c)
	}
}
