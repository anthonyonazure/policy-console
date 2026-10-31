package benchmark

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Grapher is the part of the Graph client this package needs. Keeping it to an
// interface means the benchmark code can be tested without a tenant.
type Grapher interface {
	List(ctx context.Context, uri string) ([]map[string]any, error)
	// FirstPage must not follow pagination: the secure score collection is a
	// dated history, so following it would read every day ever recorded.
	FirstPage(ctx context.Context, uri string) ([]map[string]any, error)
}

// SecureScore is Microsoft's own assessment of a tenant, read live. It needs no
// mapping from us, which makes it the one framework score that cannot be wrong
// because someone mistyped a control number.
type SecureScore struct {
	CapturedAt  string             `json:"capturedAt"`
	Current     float64            `json:"current"`
	Max         float64            `json:"max"`
	Percent     int                `json:"percent"`
	Comparative map[string]float64 `json:"comparative,omitempty"` // how similar tenants score
	Controls    []SecureControl    `json:"controls"`
}

type SecureControl struct {
	Name        string  `json:"name"`
	Title       string  `json:"title"`
	State       string  `json:"state"` // Default | Ignored | ThirdParty | Reviewed
	Score       float64 `json:"score"`
	Max         float64 `json:"max"`
	Category    string  `json:"category"`
	ActionType  string  `json:"actionType"`
	Remediation string  `json:"remediation,omitempty"`
}

// ProfileCache stores the Secure Score control profiles between runs. There are
// several hundred of them and they change rarely, so paging the whole list on
// every score is what made scoring slow enough to feel broken.
type ProfileCache interface {
	Get() ([]map[string]any, bool)
	Put([]map[string]any)
}

// FetchSecureScore reads the most recent score and joins it to the control
// profiles, which is where the human-readable titles live.
func FetchSecureScore(ctx context.Context, g Grapher) (*SecureScore, error) {
	return FetchSecureScoreCached(ctx, g, nil)
}

// FetchSecureScoreCached is FetchSecureScore with a profile cache.
func FetchSecureScoreCached(ctx context.Context, g Grapher, cache ProfileCache) (*SecureScore, error) {
	scores, err := g.FirstPage(ctx, "/v1.0/security/secureScores?$top=1")
	if err != nil {
		return nil, err
	}
	if len(scores) == 0 {
		return nil, fmt.Errorf("tenant returned no secure score yet")
	}
	latest := scores[0]

	out := &SecureScore{
		CapturedAt: str(latest["createdDateTime"]),
		Current:    num(latest["currentScore"]),
		Max:        num(latest["maxScore"]),
	}
	if out.Max > 0 {
		out.Percent = int(out.Current / out.Max * 100)
	}
	if avgs, ok := latest["averageComparativeScores"].([]any); ok {
		out.Comparative = map[string]float64{}
		for _, a := range avgs {
			if m, ok := a.(map[string]any); ok {
				out.Comparative[str(m["basis"])] = num(m["averageScore"])
			}
		}
	}

	var profiles []map[string]any
	if cache != nil {
		if cached, ok := cache.Get(); ok {
			profiles = cached
		}
	}
	if profiles == nil {
		fetched, err := g.List(ctx, "/v1.0/security/secureScoreControlProfiles")
		if err != nil {
			// A score without titles is still worth returning; the numbers are the point.
			return out, nil
		}
		profiles = fetched
		if cache != nil {
			cache.Put(profiles)
		}
	}
	titles := map[string]map[string]any{}
	for _, p := range profiles {
		titles[strings.ToLower(str(p["id"]))] = p
	}

	if controls, ok := latest["controlScores"].([]any); ok {
		for _, c := range controls {
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			name := str(m["controlName"])
			sc := SecureControl{
				Name:     name,
				Title:    str(m["description"]),
				State:    str(m["controlState"]),
				Score:    num(m["score"]),
				Category: str(m["controlCategory"]),
			}
			if p := titles[strings.ToLower(name)]; p != nil {
				sc.Max = num(p["maxScore"])
				sc.ActionType = str(p["actionType"])
				if sc.Title == "" {
					sc.Title = str(p["title"])
				}
				if sc.Title == "" {
					sc.Title = str(p["actionUrl"])
				}
				sc.Remediation = str(p["remediation"])
			}
			out.Controls = append(out.Controls, sc)
		}
	}
	sort.Slice(out.Controls, func(i, j int) bool {
		if out.Controls[i].Max != out.Controls[j].Max {
			return out.Controls[i].Max > out.Controls[j].Max
		}
		return out.Controls[i].Name < out.Controls[j].Name
	})
	return out, nil
}

func str(v any) string { s, _ := v.(string); return s }

func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}
