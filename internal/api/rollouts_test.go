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
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/rollout"
	"github.com/anthonyonazure/policy-console/internal/store"
)

type memAssigner struct{ cur rollout.Assignment }

func (m *memAssigner) Current(context.Context, string, string, string) (rollout.Assignment, error) {
	return m.cur, nil
}
func (m *memAssigner) Set(_ context.Context, _, _, _ string, a rollout.Assignment) error {
	m.cur = a
	return nil
}

func rolloutServer(t *testing.T, approvers ...string) (*Server, *memAssigner) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_ = db.UpsertTenant(store.Tenant{ID: "t1", Name: "Acme", Status: "connected"})
	ma := &memAssigner{}
	return &Server{Cfg: config.Config{Approvers: approvers}, Store: db, Rollouts: &rollout.Runner{Store: db, Assign: ma, Now: time.Now}}, ma
}

func call(t *testing.T, s *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

const rollBody = `{"planId":"three-ring","kind":"compliance-policies","objectId":"p1","objectName":"Win","ringGroups":[["11111111-1111-1111-1111-111111111111"],["22222222-2222-2222-2222-222222222222"]],"everyone":"all-devices"%s}`

func TestRolloutPreviewThenConfirmThenControl(t *testing.T) {
	s, ma := rolloutServer(t)
	if c, out := call(t, s, "GET", "/api/rollout-plans", ""); c != 200 || out != nil {
		// the list is an array, so decoding into a map yields nil: only the status matters here
		_ = out
	}
	code, sch := call(t, s, "POST", "/api/tenants/t1/rollouts/preview", strings.Replace(rollBody, "%s", "", 1))
	if code != 200 || len(sch["steps"].([]any)) != 3 {
		t.Fatalf("preview: %d %v", code, sch)
	}
	if len(ma.cur.Groups) != 0 {
		t.Fatal("a preview writes nothing")
	}
	hash := sch["hash"].(string)
	if c, _ := call(t, s, "POST", "/api/tenants/t1/rollouts", strings.Replace(rollBody, "%s", `,"hash":"wrong"`, 1)); c != 409 {
		t.Fatalf("a wrong confirmation: %d", c)
	}
	code, ro := call(t, s, "POST", "/api/tenants/t1/rollouts", strings.Replace(rollBody, "%s", `,"hash":"`+hash+`"`, 1))
	if code != 201 || ro["state"] != "running" {
		t.Fatalf("create: %d %v", code, ro)
	}
	if c, _ := call(t, s, "POST", "/api/tenants/t1/rollouts", strings.Replace(rollBody, "%s", `,"hash":"`+hash+`"`, 1)); c != 409 {
		t.Fatalf("the same policy twice: %d", c)
	}
	id := "1"
	if c, _ := call(t, s, "POST", "/api/rollouts/"+id+"/approve", `{"ring":0}`); c != 200 {
		t.Fatalf("approve: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/rollouts/"+id+"/pause", `{}`); c != 200 {
		t.Fatalf("pause: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/rollouts/"+id+"/resume", `{}`); c != 200 {
		t.Fatalf("resume: %d", c)
	}
	if c, got := call(t, s, "GET", "/api/rollouts/"+id, ""); c != 200 || len(got["rings"].([]any)) != 3 {
		t.Fatalf("detail: %d %v", c, got)
	}
	if c, _ := call(t, s, "POST", "/api/rollouts/"+id+"/cancel", `{"revert":true}`); c != 200 {
		t.Fatalf("cancel: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/rollouts/"+id+"/pause", `{}`); c != 400 {
		t.Fatalf("a canceled rollout cannot be paused: %d", c)
	}
}

func TestOnlyApproversCanApproveWhenTheyAreConfigured(t *testing.T) {
	s, _ := rolloutServer(t, "someone.else@example.com")
	_, sch := call(t, s, "POST", "/api/tenants/t1/rollouts/preview", strings.Replace(rollBody, "%s", "", 1))
	call(t, s, "POST", "/api/tenants/t1/rollouts", strings.Replace(rollBody, "%s", `,"hash":"`+sch["hash"].(string)+`"`, 1))
	if c, _ := call(t, s, "POST", "/api/rollouts/1/approve", `{"ring":0}`); c != 403 {
		t.Fatalf("a non approver must be refused: %d", c)
	}
}

func TestBadRolloutRequestsAreRefusedClearly(t *testing.T) {
	s, _ := rolloutServer(t)
	for name, body := range map[string]string{
		"no policy":    `{"planId":"three-ring"}`,
		"unknown plan": `{"planId":"nope","kind":"compliance-policies","objectId":"p"}`,
		"bad time":     strings.Replace(rollBody, "%s", `,"startAt":"tomorrow"`, 1),
	} {
		if c, out := call(t, s, "POST", "/api/tenants/t1/rollouts/preview", body); c != 400 {
			t.Errorf("%s: %d %v", name, c, out)
		}
	}
	if c, _ := call(t, s, "POST", "/api/tenants/nope/rollouts", strings.Replace(rollBody, "%s", `,"hash":"x"`, 1)); c != 404 {
		t.Fatalf("unknown tenant: %d", c)
	}
}

func TestProfileOverlaysAndTheTailoringTable(t *testing.T) {
	s, _ := rolloutServer(t)
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "defender"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "intune"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "defender", "av.json"), []byte(`{"name":"AV","platforms":"windows10","settings":[{"id":"0"}]}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "intune", "win.json"), []byte(`{"name":"Win","platforms":"windows10","settings":[{"id":"0"}]}`), 0o644)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Cat = cat
	s.Engine = &engine.Engine{Store: s.Store, Catalog: cat}

	if c, out := call(t, s, "PUT", "/api/tenants/t1/profile", `{"namePrefix":"ACME | ","thirdPartyEDR":true,"platforms":["Windows"]}`); c != 200 || out["namePrefix"] != "ACME | " {
		t.Fatalf("profile: %d %v", c, out)
	}
	if c, _ := call(t, s, "PUT", "/api/tenants/nope/profile", `{}`); c != 404 {
		t.Fatalf("unknown tenant: %d", c)
	}
	var winID string
	for _, tpl := range cat.All() {
		if tpl.Category == "intune" {
			winID = tpl.ID
		}
	}
	if c, _ := call(t, s, "POST", "/api/tenants/t1/overlays", `{"templateId":"`+winID+`","op":"modify","patch":"not json","reason":"x"}`); c != 400 {
		t.Fatalf("a patch that is not JSON: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/tenants/t1/overlays", `{"templateId":"`+winID+`","op":"exclude"}`); c != 400 {
		t.Fatalf("an overlay without a reason: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/tenants/t1/overlays", `{"templateId":"nope","op":"exclude","reason":"x"}`); c != 404 {
		t.Fatalf("unknown template: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/tenants/t1/overlays", `{"templateId":"`+winID+`","op":"modify","patch":"{\"description\":\"changed\"}","reason":"legacy"}`); c != 201 {
		t.Fatalf("add: %d", c)
	}
	_, tab := call(t, s, "GET", "/api/tenants/t1/tailoring", "")
	counts := tab["counts"].(map[string]any)
	if counts["excluded"] != float64(1) || counts["modified"] != float64(1) {
		t.Fatalf("the table shows the defender policy excluded by the EDR flag and the Windows one modified: %v", counts)
	}
	rows := tab["rows"].([]any)
	first := rows[0].(map[string]any)
	if first["state"] != "excluded" || !strings.Contains(first["reason"].(string), "endpoint protection") {
		t.Fatalf("excluded rows come first with the reason: %v", first)
	}
}
