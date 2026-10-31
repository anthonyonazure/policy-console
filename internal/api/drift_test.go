package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/config"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func TestParseExpiry(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	if v, err := parseExpiry("", now); v != "" || err != nil {
		t.Fatal("empty means no expiry")
	}
	v, err := parseExpiry("2026-12-31", now)
	if err != nil || v != "2026-12-31T23:59:59Z" {
		t.Fatalf("a bare date covers the whole day: %q %v", v, err)
	}
	if _, err := parseExpiry("2026-10-01", now); err == nil {
		t.Fatal("past dates must be refused")
	}
	if _, err := parseExpiry("next week", now); err == nil {
		t.Fatal("garbage must be refused")
	}
}

func timeNow() time.Time { return time.Now() }

func TestAssessmentBaselinesListTheStandardAndEveryLibrary(t *testing.T) {
	cat, err := catalog.Load("")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "oib-windows"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "oib-windows", "p.json"), []byte(`{"name":"W","platforms":"windows10","settings":[{"id":"0"}]}`), 0o644)
	if _, err := cat.AddDir(dir); err != nil {
		t.Fatal(err)
	}
	s := &Server{Cat: cat}
	got := s.baselineChoices()
	if got[0].ID != "" || got[0].Label != "House standard" || got[0].Count == 0 {
		t.Fatalf("the standard comes first: %+v", got)
	}
	if len(got) != 3 || got[1].ID != "oib-windows" || got[1].Count != 1 {
		t.Fatalf("libraries follow: %+v", got)
	}
	if got[2].ID != "pack-compliance" || got[2].Label != "House pack: compliance" || got[2].Count != 4 {
		t.Fatalf("House's own optional pack is listed after the imported libraries: %+v", got[2])
	}
	if !s.knownBaseline("oib-windows") || s.knownBaseline("microsoft") || s.knownBaseline("nonsense") {
		t.Fatal("only the standard and libraries can be assessed against")
	}
}

func TestFindingLifecycleOverTheAPI(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.ApplyFindings("t", []store.Finding{{TemplateID: "a", Class: "missing", Severity: "critical", Name: "A"}}, nil, time.Now())
	o, _ := db.OpenFindings("t")
	s := &Server{Cfg: config.Config{}, Store: db}
	h := s.Handler()
	post := func(path, body string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	id := strconv.FormatInt(o[0].ID, 10)
	if c := post("/api/findings/"+id+"/acknowledge", `{"note":"ok"}`); c != 200 {
		t.Fatalf("ack %d", c)
	}
	if c := post("/api/findings/"+id+"/snooze", `{"until":"2000-01-01"}`); c != 400 {
		t.Fatalf("a past snooze: %d", c)
	}
	if c := post("/api/findings/"+id+"/snooze", `{"until":"2999-01-01"}`); c != 200 {
		t.Fatalf("snooze %d", c)
	}
	if c := post("/api/findings/"+id+"/reopen", `{}`); c != 200 {
		t.Fatalf("reopen %d", c)
	}
	if c := post("/api/findings/99999/acknowledge", `{}`); c != 404 {
		t.Fatalf("unknown finding %d", c)
	}
}
