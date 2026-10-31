package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
)

func TestTeamsPostsAnAdaptiveCard(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad request %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(202)
	}))
	defer srv.Close()
	s := New(Config{TeamsURL: srv.URL}, t.Logf)
	if err := s.Teams(context.Background(), "Title", []string{"line one"}); err != nil {
		t.Fatal(err)
	}
	att := got["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("payload: %v", got)
	}
}

func TestTeamsErrorNeverContainsTheSecretURL(t *testing.T) {
	s := New(Config{TeamsURL: "http://127.0.0.1:1/secret-token-abc"}, t.Logf)
	err := s.Teams(context.Background(), "t", nil)
	if err == nil || strings.Contains(err.Error(), "secret-token-abc") {
		t.Fatalf("error must exist and not leak the URL: %v", err)
	}
}

func TestTeamsNon2xxIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 400) }))
	defer srv.Close()
	if err := New(Config{TeamsURL: srv.URL}, t.Logf).Teams(context.Background(), "t", nil); err == nil {
		t.Fatal("a rejected post must not look like success, or the alert would be marked as told")
	}
}

func TestDisabledChannelsAreNoOps(t *testing.T) {
	s := New(Config{}, t.Logf)
	if a, b := s.Enabled(); a || b {
		t.Fatal("empty config enables nothing")
	}
	if s.Teams(context.Background(), "t", nil) != nil || s.Email(context.Background(), "s", "b") != nil {
		t.Fatal("disabled channels must not error")
	}
}

func TestDryRunSendsNothing(t *testing.T) {
	s := New(Config{TeamsURL: "http://127.0.0.1:1/x", SMTPAddr: "h:25", MailFrom: "a@b", MailTo: []string{"c@d"}, DryRun: true}, t.Logf)
	s.SendFn = func(string, smtp.Auth, string, []string, []byte) error { t.Fatal("sent mail in dry run"); return nil }
	if err := s.Teams(context.Background(), "t", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Email(context.Background(), "s", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestEmailHeaderInjectionIsBlocked(t *testing.T) {
	var msg string
	s := New(Config{SMTPAddr: "h:25", MailFrom: "a@b", MailTo: []string{"c@d"}}, t.Logf)
	s.SendFn = func(_ string, _ smtp.Auth, _ string, _ []string, m []byte) error { msg = string(m); return nil }
	if err := s.Email(context.Background(), "Policy\r\nBcc: evil@x", "body"); err != nil {
		t.Fatal(err)
	}
	head := strings.SplitN(msg, "\r\n\r\n", 2)[0]
	if strings.Contains(head, "\r\nBcc:") {
		t.Fatalf("injected header: %q", head)
	}
	s.SendFn = func(string, smtp.Auth, string, []string, []byte) error { return errors.New("smtp down") }
	if s.Email(context.Background(), "s", "b") == nil {
		t.Fatal("mail failure must surface")
	}
}
