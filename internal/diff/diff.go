// Package diff compares two policy documents and reports the differences as a
// flat list of paths. It ignores fields the tenant owns rather than the author:
// identifiers, timestamps, and read-only echo fields Graph adds on export.
package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Ignored fields never count as drift. An id or a modified date changing is not
// a policy change, and counting it would make every comparison look dirty.
var Ignored = map[string]bool{
	"id":                               true,
	"createdDateTime":                  true,
	"modifiedDateTime":                 true,
	"lastModifiedDateTime":             true,
	"createdDateTime@odata":            true,
	"templateReference":                true,
	"settingInstanceTemplateReference": true,
	"settingValueTemplateReference":    true,
	"@odata.context":                   true,
	"version":                          true,
	"isAssigned":                       true,
	"settingCount":                     true,
	"creationSource":                   true,
	"priorityMetaData":                 true,
	"deployedAppCount":                 true, // app protection: computed by the service
	"assignments":                      true, // where a policy applies is a per-client decision, not part of what it says
}

type Kind string

const (
	Added   Kind = "added"   // present live, absent in the baseline
	Removed Kind = "removed" // present in the baseline, absent live
	Changed Kind = "changed"
)

type Change struct {
	Path string `json:"path"`
	Kind Kind   `json:"kind"`
	Base any    `json:"base,omitempty"`
	Live any    `json:"live,omitempty"`
}

// Compare walks two JSON documents and returns every meaningful difference.
// "base" is what you expected (a template, or an older version); "live" is what
// is there now.
func Compare(base, live []byte) ([]Change, error) {
	var b, l any
	if len(base) > 0 {
		if err := json.Unmarshal(base, &b); err != nil {
			return nil, fmt.Errorf("base: %w", err)
		}
	}
	if len(live) > 0 {
		if err := json.Unmarshal(live, &l); err != nil {
			return nil, fmt.Errorf("live: %w", err)
		}
	}
	var out []Change
	walk("", b, l, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func walk(path string, b, l any, out *[]Change) {
	switch bv := b.(type) {
	case map[string]any:
		lv, ok := l.(map[string]any)
		if !ok {
			*out = append(*out, Change{Path: path, Kind: Changed, Base: b, Live: l})
			return
		}
		keys := map[string]bool{}
		for k := range bv {
			keys[k] = true
		}
		for k := range lv {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if Ignored[k] || strings.Contains(k, "@odata") {
				continue
			}
			bChild, bOK := bv[k]
			lChild, lOK := lv[k]
			child := join(path, k)
			switch {
			case bOK && !lOK:
				*out = append(*out, Change{Path: child, Kind: Removed, Base: bChild})
			case !bOK && lOK:
				*out = append(*out, Change{Path: child, Kind: Added, Live: lChild})
			default:
				walk(child, bChild, lChild, out)
			}
		}
	case []any:
		lv, ok := l.([]any)
		if !ok {
			*out = append(*out, Change{Path: path, Kind: Changed, Base: b, Live: l})
			return
		}
		// Lists of scalars are compared as unordered sets, because Graph returns
		// role and country lists in an arbitrary order.
		if scalarList(bv) && scalarList(lv) {
			bs, ls := toSet(bv), toSet(lv)
			for _, k := range sortedKeys(bs) {
				if !ls[k] {
					*out = append(*out, Change{Path: path, Kind: Removed, Base: k})
				}
			}
			for _, k := range sortedKeys(ls) {
				if !bs[k] {
					*out = append(*out, Change{Path: path, Kind: Added, Live: k})
				}
			}
			return
		}
		n := len(bv)
		if len(lv) > n {
			n = len(lv)
		}
		for i := 0; i < n; i++ {
			child := fmt.Sprintf("%s[%d]", path, i)
			switch {
			case i >= len(lv):
				*out = append(*out, Change{Path: child, Kind: Removed, Base: bv[i]})
			case i >= len(bv):
				*out = append(*out, Change{Path: child, Kind: Added, Live: lv[i]})
			default:
				walk(child, bv[i], lv[i], out)
			}
		}
	default:
		if !equal(b, l) {
			*out = append(*out, Change{Path: path, Kind: Changed, Base: b, Live: l})
		}
	}
}

func equal(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func scalarList(v []any) bool {
	for _, x := range v {
		switch x.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func toSet(v []any) map[string]bool {
	s := map[string]bool{}
	for _, x := range v {
		s[fmt.Sprintf("%v", x)] = true
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
