package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEmbedded(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() < 30 {
		t.Fatalf("expected the full baseline, got %d templates", c.Len())
	}
	for _, tpl := range c.All() {
		if tpl.ID == "" || tpl.Name == "" {
			t.Fatalf("template %q has no id or name", tpl.File)
		}
		if _, ok := Collections[tpl.Kind]; !ok {
			t.Fatalf("template %q has unknown kind %q", tpl.File, tpl.Kind)
		}
	}
}

// A template must never deploy with a placeholder left in it: Graph would
// happily store the literal "${GROUP_ID}" and the policy would target nothing.
func TestRenderRefusesUnfilledPlaceholders(t *testing.T) {
	c, _ := Load("")
	var withPlaceholders *Template
	for i, tpl := range c.All() {
		if len(tpl.Placeholders) > 0 {
			withPlaceholders = &c.All()[i]
			break
		}
	}
	if withPlaceholders == nil {
		t.Skip("no templates use placeholders")
	}
	if _, err := withPlaceholders.Render(nil, ""); err == nil {
		t.Fatal("render succeeded with placeholders unfilled")
	}
}

func TestRenderAppliesStateOverride(t *testing.T) {
	c, _ := Load("")
	tokens := map[string]string{}
	for _, p := range c.Placeholders() {
		tokens[p] = "11111111-1111-1111-1111-111111111111"
	}
	for _, tpl := range c.All() {
		if tpl.Kind != KindConditionalAccess {
			continue
		}
		out, err := tpl.Render(tokens, "enabled")
		if err != nil {
			t.Fatalf("%s: %v", tpl.Name, err)
		}
		if !contains(out, `"state": "enabled"`) {
			t.Fatalf("%s: state override not applied", tpl.Name)
		}
		return
	}
}

func contains(b []byte, s string) bool {
	return len(b) > 0 && len(s) > 0 && (string(b) != "" && indexOf(string(b), s) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// Templates added at run time must carry their real display name, or the
// deploy screen and the tenant would show an id instead of a policy name.
func TestFromBodyUsesDisplayName(t *testing.T) {
	tpl := FromBody("microsoft", KindConditionalAccess, "microsoft/abc.json", []byte(`{"displayName":"Microsoft | Block legacy authentication","state":"enabledForReportingButNotEnforced"}`))
	if tpl.Name != "Microsoft | Block legacy authentication" || tpl.Kind != KindConditionalAccess {
		t.Fatalf("got name %q kind %q", tpl.Name, tpl.Kind)
	}
}

func TestLibraryCategoriesAreLoadedButNeverCoreAndCannotShadow(t *testing.T) {
	cat, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	core := cat.Len()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "oib-macos"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oib-macos", "P.json"),
		[]byte(`{"name":"MacOS - OIB - P","platforms":"macOS","settings":[{"id":"0"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := cat.AddDir(dir)
	if err != nil || n != 1 || cat.Len() != core+1 {
		t.Fatalf("added %d, err %v, len %d", n, err, cat.Len())
	}
	if !IsLibrary("oib-macos") || IsLibrary("defender") || IsLibrary("praxis") {
		t.Fatal("only oib-* categories are library")
	}
	// A library folder using a core category name would collide on id and must be refused.
	dir2 := t.TempDir()
	first := cat.All()[0]
	_ = os.MkdirAll(filepath.Dir(filepath.Join(dir2, first.File)), 0o755)
	if err := os.WriteFile(filepath.Join(dir2, first.File), first.Body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.AddDir(dir2); err == nil {
		t.Fatal("a library must not be able to shadow a core template")
	}
}
