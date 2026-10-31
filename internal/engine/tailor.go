package engine

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/store"
)

// Tailoring is what makes the standard fit one client without copying it: their
// name prefix, the templates that do not apply to them, and small patches.
type Tailoring struct {
	Profile  store.Profile
	Overlays map[string]store.Overlay // by template id, active ones only
	Now      time.Time
}

// LoadTailoring reads a client's profile and the overlays that apply today.
func (e *Engine) LoadTailoring(tenantID string) (*Tailoring, error) {
	p, err := e.Store.GetProfile(tenantID)
	if err != nil {
		return nil, err
	}
	os, err := e.Store.Overlays(tenantID)
	if err != nil {
		return nil, err
	}
	t := &Tailoring{Profile: p, Overlays: map[string]store.Overlay{}, Now: time.Now()}
	for _, o := range os {
		if o.Active(t.Now) {
			t.Overlays[o.TemplateID] = o
		}
	}
	return t, nil
}

// Status is how a template stands for a client, for the Included, Modified,
// Excluded table.
type Status struct {
	State  string // included | modified | excluded
	Reason string
	Owner  string
}

// Apply returns the template as this client should have it. When the client is
// not expected to have it at all, excluded is true and the reason says why.
func (t *Tailoring) Apply(tpl catalog.Template) (out catalog.Template, st Status) {
	st = Status{State: "included"}
	if t == nil {
		return tpl, st
	}
	// A client profile flag removes whole groups of templates that make no sense for them.
	if t.Profile.ThirdPartyEDR && tpl.Category == "defender" {
		return tpl, Status{State: "excluded", Reason: "another product already does endpoint protection for this client", Owner: "client profile"}
	}
	out = tpl
	if o, ok := t.Overlays[tpl.ID]; ok {
		if o.Op == "exclude" {
			return tpl, Status{State: "excluded", Reason: o.Reason, Owner: o.Owner}
		}
		if patched, err := MergePatch(tpl.Body, []byte(o.Patch)); err == nil {
			out.Body = patched
			st = Status{State: "modified", Reason: o.Reason, Owner: o.Owner}
		}
	}
	if p := t.Profile.NamePrefix; p != "" {
		out.Body, out.Name = withName(out, p)
	}
	return out, st
}

// withName puts the client's prefix in front of the policy's name, both in the
// body that is deployed and in the name used to find it again.
func withName(t catalog.Template, prefix string) ([]byte, string) {
	var doc map[string]any
	if json.Unmarshal(t.Body, &doc) != nil {
		return t.Body, t.Name
	}
	prop := catalog.Collections[t.Kind].NameProperty
	name, _ := doc[prop].(string)
	if name == "" {
		name = t.Name
	}
	if strings.HasPrefix(name, prefix) {
		return t.Body, name
	}
	full := prefix + name
	doc[prop] = full
	b, err := json.Marshal(doc)
	if err != nil {
		return t.Body, t.Name
	}
	return b, full
}

// MergePatch applies an RFC 7386 JSON merge patch: objects merge, null removes a
// setting, anything else replaces. It is how a client overlay changes a few
// settings and leaves the rest of the template alone.
func MergePatch(target, patch []byte) ([]byte, error) {
	var t, p any
	if err := json.Unmarshal(target, &t); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(patch, &p); err != nil {
		return nil, err
	}
	return json.Marshal(merge(t, p))
}

func merge(target, patch any) any {
	pm, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	tm, ok := target.(map[string]any)
	if !ok {
		tm = map[string]any{}
	}
	for k, v := range pm {
		if v == nil {
			delete(tm, k)
		} else {
			tm[k] = merge(tm[k], v)
		}
	}
	return tm
}

// ---- stable identity ----

// idMarker is written into a deployed policy's description so the console can
// recognise it later even if someone renames it or a name prefix changes. Kinds
// without a description (Conditional Access) are found by name alone.
const idMarker = "PCID:"

func hasDescription(k catalog.Kind) bool {
	return k == catalog.KindConfigPolicy || k == catalog.KindCompliance || isAppProtection(k)
}

// withMarker adds the template id to a body's description.
func withMarker(kind catalog.Kind, body []byte, templateID string) []byte {
	if !hasDescription(kind) {
		return body
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return body
	}
	d, _ := doc["description"].(string)
	if strings.Contains(d, idMarker) {
		return body
	}
	if d != "" {
		d += "\n"
	}
	doc["description"] = d + idMarker + templateID
	b, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return b
}

// markerOf reads the template id out of a live object's description.
func markerOf(obj map[string]any) string {
	d, _ := obj["description"].(string)
	i := strings.Index(d, idMarker)
	if i < 0 {
		return ""
	}
	rest := d[i+len(idMarker):]
	if j := strings.IndexAny(rest, " \n\r\t"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// withoutMarker returns a live object with the console's own id marker taken out
// of its description, so the marker is never reported as drift. A description
// that was only the marker is removed.
func withoutMarker(obj map[string]any) map[string]any {
	d, ok := obj["description"].(string)
	if !ok || !strings.Contains(d, idMarker) {
		return obj
	}
	i := strings.Index(d, idMarker)
	rest := d[i+len(idMarker):]
	end := len(rest)
	if j := strings.IndexAny(rest, " \n\r\t"); j >= 0 {
		end = j
	}
	clean := strings.TrimSpace(d[:i] + rest[end:])
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		out[k] = v
	}
	if clean == "" {
		delete(out, "description")
	} else {
		out["description"] = clean
	}
	return out
}
