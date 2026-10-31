package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/config"
	"github.com/anthonyonazure/policy-console/internal/impact"
	"github.com/anthonyonazure/policy-console/internal/store"
)

type fakeDevices []impact.Device

func (f fakeDevices) Devices(context.Context, string) ([]impact.Device, error) { return f, nil }

func impactServer(t *testing.T, devices []impact.Device) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "pack-compliance"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "pack-compliance", "w.json"), []byte(`{"@odata.type":"#microsoft.graph.windows10CompliancePolicy","displayName":"Win","secureBootEnabled":false,"bitLockerEnabled":true}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "pack-compliance", "cfg.json"), []byte(`{"name":"Settings","platforms":"windows10","settings":[{"id":"0"}]}`), 0o644)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_ = db.UpsertTenant(store.Tenant{ID: "t1", Name: "Acme", Status: "connected"})
	var id string
	for _, tpl := range cat.All() {
		if tpl.Kind == catalog.KindCompliance {
			id = tpl.ID
		}
	}
	return &Server{Cfg: config.Config{}, Store: db, Cat: cat, Impact: fakeDevices(devices)}, id
}

func TestImpactPreviewOverTheAPI(t *testing.T) {
	now := time.Now()
	devs := []impact.Device{
		{ID: "1", Name: "ok", Platform: "Windows", OSVersion: "10.0.26100", Encrypted: boolp(true), LastSync: now},
		{ID: "2", Name: "bad", Platform: "Windows", OSVersion: "10.0.19045", Encrypted: boolp(false), LastSync: now},
	}
	s, id := impactServer(t, devs)
	h := s.Handler()
	call := func(body string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/api/tenants/t1/impact", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := call(`{"templateId":"` + id + `"}`)
	res := out["result"].(map[string]any)
	counts := res["counts"].(map[string]any)
	if code != 200 || counts["compliant"] != float64(1) || counts["fail"] != float64(1) {
		t.Fatalf("%d %v", code, out)
	}
	// What if encryption were not required: the failing device now passes.
	_, out = call(`{"templateId":"` + id + `","overrides":{"bitLockerEnabled":null}}`)
	counts = out["result"].(map[string]any)["counts"].(map[string]any)
	if counts["compliant"] != float64(2) {
		t.Fatalf("what-if: %v", counts)
	}
	// Only compliance policies, and a clear refusal otherwise.
	var cfgID string
	for _, tpl := range s.Cat.All() {
		if tpl.Kind != catalog.KindCompliance {
			cfgID = tpl.ID
		}
	}
	if code, _ := call(`{"templateId":"` + cfgID + `"}`); code != 400 {
		t.Fatalf("non compliance template: %d", code)
	}
	if code, _ := call(`{"templateId":"nope"}`); code != 404 {
		t.Fatalf("unknown template: %d", code)
	}
}

func boolp(v bool) *bool { return &v }
