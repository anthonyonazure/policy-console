package engine

import (
	"testing"

	"github.com/anthonyonazure/policy-console/internal/graph"
)

func TestReadsUseTheReadRegistrationWhenOneIsConfigured(t *testing.T) {
	write, read := &graph.Client{}, &graph.Client{}
	e := &Engine{NewGraph: func(string) *graph.Client { return write }}
	if e.Reader("t") != write {
		t.Fatal("with no read registration, reads fall back to the only one there is")
	}
	e.NewReadGraph = func(string) *graph.Client { return read }
	if e.Reader("t") != read {
		t.Fatal("reads must use the read registration")
	}
	if e.NewGraph("t") != write {
		t.Fatal("writes must keep using the write registration")
	}
}
