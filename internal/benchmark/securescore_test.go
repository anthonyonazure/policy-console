package benchmark

import (
	"context"
	"strings"
	"testing"
)

type fakeGraph struct {
	firstPageCalls []string
	listCalls      []string
	t              *testing.T
}

func (f *fakeGraph) FirstPage(ctx context.Context, uri string) ([]map[string]any, error) {
	f.firstPageCalls = append(f.firstPageCalls, uri)
	return []map[string]any{{
		"createdDateTime": "2026-09-17T00:00:00Z",
		"currentScore":    float64(698),
		"maxScore":        float64(1193),
		"averageComparativeScores": []any{
			map[string]any{"basis": "AllTenants", "averageScore": float64(54)},
		},
		"controlScores": []any{
			map[string]any{"controlName": "aad_x", "description": "Do the thing", "controlState": "Default", "score": float64(1)},
		},
	}}, nil
}

func (f *fakeGraph) List(ctx context.Context, uri string) ([]map[string]any, error) {
	f.listCalls = append(f.listCalls, uri)
	// The score history must never be read through the paginating helper.
	if strings.Contains(uri, "secureScores") {
		f.t.Fatalf("secureScores was read with pagination, which walks the tenant's whole history: %s", uri)
	}
	return []map[string]any{{"id": "aad_x", "maxScore": float64(10), "title": "Do the thing", "actionType": "Config"}}, nil
}

func TestSecureScoreReadsOnlyTheLatest(t *testing.T) {
	g := &fakeGraph{t: t}
	ss, err := FetchSecureScore(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if ss.Percent != 58 {
		t.Fatalf("expected 58 percent, got %d", ss.Percent)
	}
	if len(g.firstPageCalls) != 1 || !strings.Contains(g.firstPageCalls[0], "secureScores") {
		t.Fatalf("score was not read as a single page: %v", g.firstPageCalls)
	}
	if len(ss.Controls) != 1 || ss.Controls[0].Max != 10 {
		t.Fatalf("control profile was not joined in: %+v", ss.Controls)
	}
}

type countingCache struct {
	stored []map[string]any
	gets   int
}

func (c *countingCache) Get() ([]map[string]any, bool) {
	c.gets++
	if c.stored == nil {
		return nil, false
	}
	return c.stored, true
}
func (c *countingCache) Put(p []map[string]any) { c.stored = p }

// Several hundred control profiles paged on every score is what made scoring
// feel broken, so a warm cache must stop the second fetch entirely.
func TestProfileCacheAvoidsRefetch(t *testing.T) {
	g := &fakeGraph{t: t}
	cache := &countingCache{}
	if _, err := FetchSecureScoreCached(context.Background(), g, cache); err != nil {
		t.Fatal(err)
	}
	if len(g.listCalls) != 1 {
		t.Fatalf("expected one profile fetch, got %d", len(g.listCalls))
	}
	if _, err := FetchSecureScoreCached(context.Background(), g, cache); err != nil {
		t.Fatal(err)
	}
	if len(g.listCalls) != 1 {
		t.Fatalf("profiles were fetched again despite a warm cache: %d calls", len(g.listCalls))
	}
}
