package api

import (
	"net/http"
	"strings"
	"testing"
)

func libServer(t *testing.T, approvers ...string) *Server {
	s, _ := fleetServer(t, healthyGraph, approvers...)
	if _, err := s.InitLibrary(); err != nil {
		t.Fatal(err)
	}
	return s
}

func lib(t *testing.T, s *Server, method, path, body string) (int, map[string]any) {
	return call(t, s, method, path, body)
}

const goodCfg = `{"name":"Custom firewall","platforms":"windows10","settings":[{"id":"0"}]}`

func TestADraftIsInvisibleUntilAnApproverPublishesIt(t *testing.T) {
	s := libServer(t)
	if c, o := lib(t, s, "POST", "/api/library/templates", `{"id":"pack-custom-fw","category":"pack-custom","body":`+jsonString(goodCfg)+`}`); c != 201 {
		t.Fatalf("%d %v", c, o)
	}
	if s.Cat.Get("pack-custom-fw") != nil {
		t.Fatal("a draft must not be in the catalog, or it could be deployed before anyone approved it")
	}
	if c, _ := lib(t, s, "POST", "/api/library/templates/pack-custom-fw/publish", `{}`); c != 400 {
		t.Fatalf("publishing needs a reason: %d", c)
	}
	if c, o := lib(t, s, "POST", "/api/library/templates/pack-custom-fw/publish", `{"reason":"first version"}`); c != 200 || o["publishedVersion"] != float64(1) {
		t.Fatalf("%d %v", c, o)
	}
	if s.Cat.Get("pack-custom-fw") == nil {
		t.Fatal("published means in the catalog")
	}
	// Edit, publish again, and the history keeps both with who and why.
	edited := strings.Replace(goodCfg, "Custom firewall", "Custom firewall v2", 1)
	if c, _ := lib(t, s, "PUT", "/api/library/templates/pack-custom-fw/draft", `{"body":`+jsonString(edited)+`}`); c != 200 {
		t.Fatalf("%d", c)
	}
	if got := s.Cat.Get("pack-custom-fw"); got.Name != "Custom firewall" {
		t.Fatalf("editing a draft does not change what is deployed: %q", got.Name)
	}
	_, _ = lib(t, s, "POST", "/api/library/templates/pack-custom-fw/publish", `{"reason":"renamed"}`)
	if got := s.Cat.Get("pack-custom-fw"); got.Name != "Custom firewall v2" {
		t.Fatalf("%q", got.Name)
	}
	_, vs := call(t, s, "GET", "/api/library/templates/pack-custom-fw/versions", "")
	_ = vs
	code, d := lib(t, s, "GET", "/api/library/templates/pack-custom-fw/diff?from=1&to=2", "")
	if code != 200 || len(d["changes"].([]any)) == 0 {
		t.Fatalf("a readable diff between versions: %d %v", code, d)
	}
	// Revert is itself a new version.
	code, rv := lib(t, s, "POST", "/api/library/templates/pack-custom-fw/revert", `{"version":1}`)
	if code != 200 || rv["publishedVersion"] != float64(3) || s.Cat.Get("pack-custom-fw").Name != "Custom firewall" {
		t.Fatalf("%d %v", code, rv)
	}
}

func TestOnlyApproversPublish(t *testing.T) {
	s := libServer(t, "someone.else@example.com")
	_, _ = lib(t, s, "POST", "/api/library/templates", `{"id":"pack-x1","category":"pack-custom","body":`+jsonString(goodCfg)+`}`)
	if c, _ := lib(t, s, "POST", "/api/library/templates/pack-x1/publish", `{"reason":"x"}`); c != 403 {
		t.Fatalf("%d", c)
	}
	if s.Cat.Get("pack-x1") != nil {
		t.Fatal("a refused publish must not change the catalog")
	}
}

func TestUnsafeTemplatesCannotBePublished(t *testing.T) {
	s := libServer(t)
	blocksAll := `{"displayName":"Block all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["block"]}}`
	_, _ = lib(t, s, "POST", "/api/library/templates", `{"id":"ca-block-all","category":"conditional-access","body":`+jsonString(blocksAll)+`}`)
	if c, o := lib(t, s, "POST", "/api/library/templates/ca-block-all/publish", `{"reason":"x"}`); c != 400 || !strings.Contains(o["error"].(string), "block every user") {
		t.Fatalf("the lockout guard applies to the library too: %d %v", c, o)
	}
	if s.Cat.Get("ca-block-all") != nil {
		t.Fatal("a refused template must not reach the catalog")
	}
	withSecret := `{"name":"Wifi","platforms":"windows10","preSharedKey":"hunter2","settings":[{"id":"0"}]}`
	_, _ = lib(t, s, "POST", "/api/library/templates", `{"id":"pack-wifi","category":"pack-custom","body":`+jsonString(withSecret)+`}`)
	c, o := lib(t, s, "POST", "/api/library/templates/pack-wifi/publish", `{"reason":"x"}`)
	if c != 400 || !strings.Contains(o["error"].(string), "secret") {
		t.Fatalf("a literal secret must not enter a shared template: %d %v", c, o)
	}
	placeholder := `{"name":"Wifi","platforms":"windows10","preSharedKey":"${WIFI_KEY}","settings":[{"id":"0"}]}`
	_, _ = lib(t, s, "PUT", "/api/library/templates/pack-wifi/draft", `{"body":`+jsonString(placeholder)+`}`)
	if c, o := lib(t, s, "POST", "/api/library/templates/pack-wifi/publish", `{"reason":"placeholder"}`); c != 200 {
		t.Fatalf("a placeholder holds no secret and is fine: %d %v", c, o)
	}
	_, _ = lib(t, s, "POST", "/api/library/templates", `{"id":"pack-redacted","category":"pack-custom","body":`+jsonString(`{"name":"R","platforms":"windows10","description":"[redacted:abcd1234]","settings":[{"id":"0"}]}`)+`}`)
	if c, _ := lib(t, s, "POST", "/api/library/templates/pack-redacted/publish", `{"reason":"x"}`); c != 400 {
		t.Fatalf("a redacted copy cannot be a template: %d", c)
	}
}

func TestEditingABuiltInTemplateReplacesItAtRuntime(t *testing.T) {
	s := libServer(t)
	builtin := s.Cat.All()[0].ID
	if c, _ := lib(t, s, "POST", "/api/library/templates", `{"id":"`+builtin+`","cloneFrom":"`+builtin+`"}`); c != 201 {
		t.Fatalf("a built in template can be edited by reusing its id: %d", c)
	}
	edited := strings.Replace(string(s.Cat.Get(builtin).Body), "Win cfg", "Win cfg tuned", 1)
	_, _ = lib(t, s, "PUT", "/api/library/templates/"+builtin+"/draft", `{"body":`+jsonString(edited)+`}`)
	_, _ = lib(t, s, "POST", "/api/library/templates/"+builtin+"/publish", `{"reason":"tuned"}`)
	if got := s.Cat.Get(builtin); got.Name != "Win cfg tuned" {
		t.Fatalf("%q", got.Name)
	}
	_, list := call(t, s, "GET", "/api/library", "")
	_ = list
	// A restart loads the published edit again on top of the built in.
	s2, _ := fleetServer(t, healthyGraph)
	s2.Store = s.Store
	if n, err := s2.InitLibrary(); err != nil || n != 1 || s2.Cat.Get(builtin).Name != "Win cfg tuned" {
		t.Fatalf("%d %v", n, err)
	}
}

func TestBadIdsAndDuplicatesAreRefused(t *testing.T) {
	s := libServer(t)
	for body, want := range map[string]int{
		`{"id":"Bad Id!","category":"pack-x","body":"{}"}`:     400,
		`{"id":"ok-id","category":"pack-x","body":"not json"}`: 400,
		`{"id":"ok-id2","cloneFrom":"nope"}`:                   404,
	} {
		if c, _ := lib(t, s, "POST", "/api/library/templates", body); c != want {
			t.Errorf("%s: %d", body, c)
		}
	}
	_, _ = lib(t, s, "POST", "/api/library/templates", `{"id":"dup-one","category":"pack-x","body":`+jsonString(goodCfg)+`}`)
	_, _ = lib(t, s, "POST", "/api/library/templates/dup-one/publish", `{"reason":"x"}`)
	if c, _ := lib(t, s, "POST", "/api/library/templates", `{"id":"dup-one","category":"pack-x","body":`+jsonString(goodCfg)+`}`); c != 409 {
		t.Fatalf("a second template with the same id: %d", c)
	}
	_ = http.StatusOK
}

func jsonString(s string) string {
	b, _ := jsonMarshal(s)
	return string(b)
}
