package report

import (
	"strings"
	"testing"
)

func TestEverythingFromOutsideIsEscaped(t *testing.T) {
	out := HTML(Data{Client: `Acme <script>alert(1)</script>`, Generated: "today", Baseline: "x",
		Protected: []Line{{Name: `<img src=x onerror=alert(1)>`, Detail: `"quoted" & more`}}})
	for _, bad := range []string{"<script>alert", "<img src=x"} {
		if strings.Contains(out, bad) {
			t.Fatalf("unescaped %q in the report", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;") || !strings.Contains(out, "&amp; more") {
		t.Fatal("escaped text must still be readable")
	}
}

func TestPercentAndDeltaSayWhatMoved(t *testing.T) {
	c := Counts{InPlace: 30, Differ: 5, Missing: 5}
	if c.Percent() != 75 || (Counts{}).Percent() != 0 {
		t.Fatalf("%d", c.Percent())
	}
	if !strings.Contains(Delta(c, nil), "first report") {
		t.Fatal("first")
	}
	d := Delta(Counts{InPlace: 35, Missing: 2}, &Counts{InPlace: 30, Missing: 5})
	if !strings.Contains(d, "+5 policies in place") || !strings.Contains(d, "-3 missing") {
		t.Fatal(d)
	}
	if Delta(c, &c) != "Nothing has changed since the last report." {
		t.Fatal("no change")
	}
}

func TestTheReportIsPlainEnglishWithNoDashes(t *testing.T) {
	out := HTML(Data{Client: "Acme", Generated: "27 October 2026", Baseline: "House standard", Counts: Counts{InPlace: 3, Missing: 1, Critical: 1},
		NextSteps: NextSteps(Counts{InPlace: 3, Missing: 1, Critical: 1})})
	body := out[strings.Index(out, "<body>"):]
	for _, d := range []string{"—", "–"} {
		if strings.Contains(body, d) {
			t.Fatal("the owner does not want em or en dashes in anything he reads")
		}
	}
	if !strings.Contains(body, "Fix the 1 urgent issue") || !strings.Contains(body, "75%") {
		t.Fatal(body)
	}
}

func TestNextStepsWhenAllIsWell(t *testing.T) {
	if s := NextSteps(Counts{InPlace: 10}); len(s) != 1 || !strings.Contains(s[0], "No action needed") {
		t.Fatalf("%v", s)
	}
}
