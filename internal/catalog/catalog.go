// Package catalog reads the policy template set: the client-neutral JSON
// baselines, their placeholders, and which Graph collection each one belongs to.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed all:files
var embedded embed.FS

// Kind is a Graph collection a template can be created in.
type Kind string

const (
	KindConditionalAccess Kind = "policies"
	KindNamedLocation     Kind = "named-locations"
	KindAuthStrength      Kind = "authentication-strengths"
	KindConfigPolicy      Kind = "configuration-policies"

	KindCompliance           Kind = "compliance-policies"
	KindIOSAppProtection     Kind = "ios-app-protection"
	KindAndroidAppProtection Kind = "android-app-protection"

	// Read only kinds: the console reads, versions and watches them (for discovery,
	// history and drift) but has no templates for them and does not create them.
	KindDeviceConfig     Kind = "device-configurations"     // legacy profiles and Windows update rings
	KindEnrollmentConfig Kind = "enrollment-configurations" // enrollment restrictions and status pages
	KindAutopilotProfile Kind = "autopilot-profiles"
	KindAssignmentFilter Kind = "assignment-filters"
)

// ManagedKinds lists every kind the console reads, compares and snapshots, in
// the order they are processed.
func ManagedKinds() []Kind {
	return []Kind{KindConditionalAccess, KindNamedLocation, KindAuthStrength, KindConfigPolicy,
		KindCompliance, KindIOSAppProtection, KindAndroidAppProtection,
		KindDeviceConfig, KindEnrollmentConfig, KindAutopilotProfile, KindAssignmentFilter}
}

// Collection describes where a Kind lives in Graph and which field holds its name.
type Collection struct {
	URI          string
	NameProperty string
}

var Collections = map[Kind]Collection{
	KindConditionalAccess: {"/v1.0/identity/conditionalAccess/policies", "displayName"},
	KindNamedLocation:     {"/v1.0/identity/conditionalAccess/namedLocations", "displayName"},
	KindAuthStrength:      {"/v1.0/policies/authenticationStrengthPolicies", "displayName"},
	KindConfigPolicy:      {"/beta/deviceManagement/configurationPolicies", "name"},

	KindCompliance:           {"/beta/deviceManagement/deviceCompliancePolicies", "displayName"},
	KindIOSAppProtection:     {"/beta/deviceAppManagement/iosManagedAppProtections", "displayName"},
	KindAndroidAppProtection: {"/beta/deviceAppManagement/androidManagedAppProtections", "displayName"},

	KindDeviceConfig:     {"/beta/deviceManagement/deviceConfigurations", "displayName"},
	KindEnrollmentConfig: {"/beta/deviceManagement/deviceEnrollmentConfigurations", "displayName"},
	KindAutopilotProfile: {"/beta/deviceManagement/windowsAutopilotDeploymentProfiles", "displayName"},
	KindAssignmentFilter: {"/beta/deviceManagement/assignmentFilters", "displayName"},
}

// kindFromODataType names the kind of a template whose body carries an
// @odata.type, which is how compliance and app protection policies say what
// they are. An empty result means the body does not say.
func kindFromODataType(t string) Kind {
	t = strings.ToLower(t)
	switch {
	case strings.HasSuffix(t, "managedappprotection") && strings.Contains(t, "ios"):
		return KindIOSAppProtection
	case strings.HasSuffix(t, "managedappprotection") && strings.Contains(t, "android"):
		return KindAndroidAppProtection
	case strings.HasSuffix(t, "compliancepolicy"):
		return KindCompliance
	}
	return ""
}

type Template struct {
	ID           string   `json:"id"`       // stable slug, used in URLs
	Code         string   `json:"code"`     // C001 etc, empty for non-CA policies
	Name         string   `json:"name"`     // display name as it lands in the tenant
	Category     string   `json:"category"` // conditional-access | defender | intune
	Kind         Kind     `json:"kind"`
	File         string   `json:"file"`
	Placeholders []string `json:"placeholders"`
	Body         []byte   `json:"-"`
}

var (
	placeholderRE = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)
	codeRE        = regexp.MustCompile(`(^|\s)(C\d{3}[a-z]?)(\s|$)`)
	slugRE        = regexp.MustCompile(`[^a-z0-9]+`)
)

type Catalog struct {
	mu        sync.RWMutex
	templates []Template
	byID      map[string]*Template
}

// Load reads the embedded template set, or a folder on disk when dir is set.
func Load(dir string) (*Catalog, error) {
	var fsys fs.FS
	var root string
	if dir != "" {
		fsys, root = os.DirFS(dir), "."
	} else {
		fsys, root = embedded, "files"
	}

	c := &Catalog{byID: map[string]*Template{}}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(p), ".json") {
			return err
		}
		body, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		t, err := parse(strings.TrimPrefix(strings.TrimPrefix(p, root), "/"), body)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		c.templates = append(c.templates, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(c.templates, func(i, j int) bool {
		if c.templates[i].Category != c.templates[j].Category {
			return c.templates[i].Category < c.templates[j].Category
		}
		return c.templates[i].Name < c.templates[j].Name
	})
	for i := range c.templates {
		c.byID[c.templates[i].ID] = &c.templates[i]
	}
	return c, nil
}

// parse derives category, kind and display name from the file's path and contents.
func parse(rel string, body []byte) (Template, error) {
	parts := strings.Split(rel, "/")
	if len(parts) < 2 {
		return Template{}, fmt.Errorf("unexpected layout %q", rel)
	}
	category := parts[0]

	kind := KindConfigPolicy
	if category == "praxis" && parts[1] == "conditional-access" {
		kind = KindConditionalAccess
	}
	if category == "conditional-access" {
		switch parts[1] {
		case "policies":
			kind = KindConditionalAccess
		case "named-locations":
			kind = KindNamedLocation
		case "authentication-strengths":
			kind = KindAuthStrength
		}
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return Template{}, err
	}
	if ot, _ := doc["@odata.type"].(string); ot != "" && kind == KindConfigPolicy {
		if k := kindFromODataType(ot); k != "" {
			kind = k
		}
	}
	name, _ := doc[Collections[kind].NameProperty].(string)
	base := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
	if name == "" {
		name = base
	}

	code := ""
	if m := codeRE.FindStringSubmatch(base); m != nil {
		code = m[2]
	}

	seen := map[string]bool{}
	var ph []string
	for _, m := range placeholderRE.FindAllStringSubmatch(string(body), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			ph = append(ph, m[1])
		}
	}
	sort.Strings(ph)

	return Template{
		ID:           slug(category + "-" + base),
		Code:         code,
		Name:         name,
		Category:     category,
		Kind:         kind,
		File:         rel,
		Placeholders: ph,
		Body:         body,
	}, nil
}

func slug(s string) string {
	return strings.Trim(slugRE.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func (c *Catalog) All() []Template {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Template(nil), c.templates...)
}

func (c *Catalog) Get(id string) *Template {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if t, ok := c.byID[id]; ok {
		cp := *t
		return &cp
	}
	return nil
}

func (c *Catalog) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.templates)
}

// Replace swaps in every template of one category, used for sources fetched at
// run time such as Microsoft's own Conditional Access templates.
func (c *Catalog) Replace(category string, ts []Template) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.templates[:0:0]
	for _, t := range c.templates {
		if t.Category != category {
			kept = append(kept, t)
		}
	}
	c.templates = append(kept, ts...)
	sort.Slice(c.templates, func(i, j int) bool {
		if c.templates[i].Category != c.templates[j].Category {
			return c.templates[i].Category < c.templates[j].Category
		}
		return c.templates[i].Name < c.templates[j].Name
	})
	c.byID = map[string]*Template{}
	for i := range c.templates {
		c.byID[c.templates[i].ID] = &c.templates[i]
	}
}

// FromBody builds a template from a policy document held in memory.
func FromBody(category string, kind Kind, file string, body []byte) Template {
	t, err := parse(category+"/policies/"+strings.TrimPrefix(file, category+"/"), body)
	if err != nil {
		return Template{Category: category, Kind: kind, File: file, Body: body, Name: file, ID: slug(file)}
	}
	// parse guessed the kind from the path; read the name again with the field
	// the real kind uses (displayName for Conditional Access, name for Intune).
	if t.Kind != kind {
		t.Kind = kind
		var doc map[string]any
		if json.Unmarshal(body, &doc) == nil {
			if n, ok := doc[Collections[kind].NameProperty].(string); ok && n != "" {
				t.Name = n
			}
		}
	}
	return t
}

// Placeholders returns every placeholder used anywhere in the set.
func (c *Catalog) Placeholders() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range c.All() {
		for _, p := range t.Placeholders {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Render fills placeholders and applies a Conditional Access state override.
// It refuses to return a body that still contains an unfilled placeholder,
// because Graph would otherwise accept a literal "${...}" as a real value.
func (t *Template) Render(tokens map[string]string, state string) ([]byte, error) {
	text := string(t.Body)
	for k, v := range tokens {
		if strings.TrimSpace(v) == "" {
			continue
		}
		text = strings.ReplaceAll(text, "${"+k+"}", v)
	}
	if m := placeholderRE.FindAllStringSubmatch(text, -1); m != nil {
		seen := map[string]bool{}
		var missing []string
		for _, x := range m {
			if !seen[x[1]] {
				seen[x[1]] = true
				missing = append(missing, x[1])
			}
		}
		return nil, fmt.Errorf("still needs values for: %s", strings.Join(missing, ", "))
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	if state != "" {
		if _, ok := doc["state"]; ok {
			doc["state"] = state
		}
	}
	return json.MarshalIndent(doc, "", "  ")
}

// IsLibrary reports whether a category is an optional library or pack rather than
// part of the standard (imported Open Intune Baseline folders start with "oib-",
// House's own optional packs with "pack-"). Library templates can be browsed and deployed on request but
// are never expected in a tenant, so they take no part in "missing", the score,
// or the overlap and baseline audits of the House set.
func IsLibrary(category string) bool {
	return strings.HasPrefix(category, "oib-") || strings.HasPrefix(category, "pack-")
}

// AddDir adds the templates found under dir, which holds one folder per
// category. It is how an imported library is loaded without being compiled in.
// A template whose id already exists is refused, so a library can never shadow
// a core template.
func (c *Catalog) AddDir(dir string) (int, error) {
	extra, err := Load(dir)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	added := 0
	for _, t := range extra.All() {
		if _, dup := c.byID[t.ID]; dup {
			return added, fmt.Errorf("template %q in %s collides with an existing template", t.ID, dir)
		}
		c.templates = append(c.templates, t)
		added++
	}
	sort.Slice(c.templates, func(i, j int) bool {
		if c.templates[i].Category != c.templates[j].Category {
			return c.templates[i].Category < c.templates[j].Category
		}
		return c.templates[i].Name < c.templates[j].Name
	})
	c.byID = map[string]*Template{}
	for i := range c.templates {
		c.byID[c.templates[i].ID] = &c.templates[i]
	}
	return added, nil
}

// Build makes a template from a body under a chosen id and category, using the
// same rules as templates read from files. It is how operator edited templates
// join the catalog.
func Build(id, category string, body []byte) (Template, error) {
	rel := category + "/" + id + ".json"
	if category == "conditional-access" {
		rel = category + "/policies/" + id + ".json" // the folder is what makes it a Conditional Access policy
	}
	t, err := parse(rel, body)
	if err != nil {
		return Template{}, err
	}
	t.ID = id
	return t, nil
}

// Upsert adds a template or replaces the one with the same id.
func (c *Catalog) Upsert(t Template) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.templates {
		if c.templates[i].ID == t.ID {
			c.templates[i] = t
			c.reindex()
			return
		}
	}
	c.templates = append(c.templates, t)
	c.reindex()
}

// Remove takes a template out of the catalog.
func (c *Catalog) Remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.templates[:0:0]
	for _, t := range c.templates {
		if t.ID != id {
			kept = append(kept, t)
		}
	}
	c.templates = kept
	c.reindex()
}

func (c *Catalog) reindex() {
	sort.Slice(c.templates, func(i, j int) bool {
		if c.templates[i].Category != c.templates[j].Category {
			return c.templates[i].Category < c.templates[j].Category
		}
		return c.templates[i].Name < c.templates[j].Name
	})
	c.byID = map[string]*Template{}
	for i := range c.templates {
		c.byID[c.templates[i].ID] = &c.templates[i]
	}
}
