// Package notify delivers alerts to people. Teams posts go to a Workflows
// "when a webhook request is received" trigger, because Microsoft retired the
// old Office 365 connector webhooks on 2026-04-30. Email goes out over SMTP.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// Config says where alerts go. A channel with no setting is simply off.
type Config struct {
	TeamsURL     string // Workflows trigger URL; treat as a secret
	SMTPAddr     string // host:port
	SMTPUser     string
	SMTPPassword string
	MailFrom     string
	MailTo       []string
	DryRun       bool // log what would be sent and send nothing
}

// Notifier sends alerts. Implementations must be safe to call from a scheduler.
type Notifier interface {
	// Teams posts a card. Title is a heading, lines are the body.
	Teams(ctx context.Context, title string, lines []string) error
	// Email sends a plain text message.
	Email(ctx context.Context, subject, body string) error
	// Enabled reports which channels are configured.
	Enabled() (teams, email bool)
}

// Sender is the real Notifier.
type Sender struct {
	Cfg    Config
	HTTP   *http.Client
	Logf   func(format string, args ...any)
	SendFn func(addr string, a smtp.Auth, from string, to []string, msg []byte) error // test seam
}

func New(cfg Config, logf func(string, ...any)) *Sender {
	return &Sender{Cfg: cfg, HTTP: &http.Client{Timeout: 15 * time.Second}, Logf: logf, SendFn: smtp.SendMail}
}

func (s *Sender) Enabled() (bool, bool) {
	return s.Cfg.TeamsURL != "", s.Cfg.SMTPAddr != "" && len(s.Cfg.MailTo) > 0 && s.Cfg.MailFrom != ""
}

func (s *Sender) Teams(ctx context.Context, title string, lines []string) error {
	if s.Cfg.TeamsURL == "" {
		return nil
	}
	if s.Cfg.DryRun {
		s.Logf("alert (dry run) teams: %s | %s", title, strings.Join(lines, " | "))
		return nil
	}
	body, err := json.Marshal(TeamsCard(title, lines))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Cfg.TeamsURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return redact(err, s.Cfg.TeamsURL)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("teams returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// TeamsCard builds the Adaptive Card message a Workflows webhook trigger expects.
func TeamsCard(title string, lines []string) map[string]any {
	blocks := []any{map[string]any{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true}}
	for _, l := range lines {
		blocks = append(blocks, map[string]any{"type": "TextBlock", "text": l, "wrap": true})
	}
	return map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body":    blocks,
			},
		}},
	}
}

func (s *Sender) Email(ctx context.Context, subject, body string) error {
	if _, on := s.Enabled(); !on {
		return nil
	}
	if s.Cfg.DryRun {
		s.Logf("alert (dry run) email to %s: %s", strings.Join(s.Cfg.MailTo, ","), subject)
		return nil
	}
	var auth smtp.Auth
	if s.Cfg.SMTPUser != "" {
		host := s.Cfg.SMTPAddr
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		auth = smtp.PlainAuth("", s.Cfg.SMTPUser, s.Cfg.SMTPPassword, host)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		s.Cfg.MailFrom, strings.Join(s.Cfg.MailTo, ", "), sanitizeHeader(subject), body)
	return s.SendFn(s.Cfg.SMTPAddr, auth, s.Cfg.MailFrom, s.Cfg.MailTo, []byte(msg))
}

// sanitizeHeader stops a policy name containing a newline from injecting mail headers.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

// redact keeps the secret webhook URL out of logs, since the URL is the credential.
func redact(err error, secret string) error {
	if secret == "" {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), secret, "[teams url]"))
}
