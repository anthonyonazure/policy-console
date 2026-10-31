// Package config loads console settings from environment variables with
// sensible defaults, so the same binary runs on a laptop or in a container.
package config

import (
	"encoding/base64"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr            string // listen address, e.g. 127.0.0.1:4930
	DatabaseURL     string // sqlite file path, or postgres:// URL
	TemplateDir     string // optional override for the embedded template set
	ExtraTemplates  string // optional folder of extra template categories (an imported library) added to the set
	CISDir          string // folder of CIS benchmark PDFs to import
	ClientID        string // multi-tenant app registration (application) ID
	ClientSecret    string // app secret; prefer a certificate in production
	ReadClientID    string // optional read-only registration; when set, inventory, drift and assessments use it instead of the write registration
	ReadSecret      string
	SnapshotCron    string // how often scheduled full snapshots run, e.g. "24h"
	ReadOnly        bool   // hard kill switch: refuses every write to Graph
	ReportOnlyHours int    // minimum hours a Conditional Access policy stays report-only before it can be enforced

	// Entra ID sign-in for the people using the console (not for reaching tenants).
	TenantID     string // the tenant staff sign in from
	WebClientID  string // the console's own app registration
	WebSecret    string
	PublicURL    string   // how a browser reaches the console, e.g. https://policy-console.example.com
	SessionKey   []byte   // signs session cookies; generated if unset, which logs everyone out on restart
	AllowedUsers []string // optional allow-list of user principal names
	AllowedGroup string   // optional group object id a signed-in user must be in
	AuthDisabled bool     // local development only

	// Easy Auth trust. The X-Ms-Client-Principal-Name header is honoured only when
	// the request also carries this shared secret in X-Pc-Easyauth-Secret, set by
	// the proxy in front of the app. Empty means the header is ignored entirely.
	EasyAuthSecret string

	// Who may change things. Everyone permitted in is a viewer (read-only) unless
	// listed here. If neither is set, every permitted user is a deployer.
	DeployerUsers []string // user principal names
	DeployerGroup string   // group object id

	BackupDir string // where `policyconsole backup` writes snapshots

	// Drift alerts. Each channel is off until configured. The Teams URL is a
	// Workflows "when a webhook request is received" trigger and is a secret.
	AlertTeamsURL string
	AlertSMTPAddr string // host:port
	AlertSMTPUser string
	AlertSMTPPass string
	AlertMailFrom string
	AlertMailTo   []string
	AlertDryRun   bool // log alerts instead of sending them

	// RetentionDays is how long old policy versions are kept (never below 30).
	// 0 turns pruning off.
	RetentionDays int

	// Approvers may approve rollout rings. Empty means every deployer may.
	Approvers []string

	// PlannerPlanID posts build outs into one existing Planner plan; otherwise
	// PlannerGroupID creates one plan per build out inside that Microsoft 365 group.
	PlannerPlanID  string
	PlannerGroupID string
	// The Planner app is its own registration in our tenant, holding only the Planner permission.
	PlannerClientID string
	PlannerSecret   string

	// DemoDevices makes the impact preview use invented devices, labelled as such.
	DemoDevices bool
}

// RedirectURL is where Entra ID sends the browser back to, and must match a
// redirect URI on the console's app registration exactly.
func (c Config) RedirectURL() string {
	return strings.TrimSuffix(c.PublicURL, "/") + "/auth/callback"
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func Load() Config {
	ro, _ := strconv.ParseBool(env("PC_READ_ONLY", "false"))
	noAuth, _ := strconv.ParseBool(env("PC_AUTH_DISABLED", "false"))

	var key []byte
	if raw := os.Getenv("PC_SESSION_KEY"); raw != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) >= 32 {
			key = decoded
		} else {
			key = []byte(raw)
		}
	}

	var allowed []string
	for _, u := range strings.Split(os.Getenv("PC_ALLOWED_USERS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			allowed = append(allowed, u)
		}
	}

	var deployers []string
	for _, u := range strings.Split(os.Getenv("PC_DEPLOYERS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			deployers = append(deployers, u)
		}
	}

	var mailTo []string
	for _, u := range strings.Split(os.Getenv("PC_ALERT_MAIL_TO"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			mailTo = append(mailTo, u)
		}
	}
	var approvers []string
	for _, u := range strings.Split(os.Getenv("PC_APPROVERS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			approvers = append(approvers, u)
		}
	}
	retention := 90
	if v := os.Getenv("PC_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			retention = n
		}
	}
	dry, _ := strconv.ParseBool(env("PC_ALERT_DRY_RUN", "false"))
	demo, _ := strconv.ParseBool(env("PC_DEMO_DEVICES", "false"))

	addr := env("PC_ADDR", "127.0.0.1:4930")
	return Config{
		AlertTeamsURL:   os.Getenv("PC_ALERT_TEAMS_URL"),
		AlertSMTPAddr:   os.Getenv("PC_ALERT_SMTP_ADDR"),
		AlertSMTPUser:   os.Getenv("PC_ALERT_SMTP_USER"),
		AlertSMTPPass:   os.Getenv("PC_ALERT_SMTP_PASSWORD"),
		AlertMailFrom:   os.Getenv("PC_ALERT_MAIL_FROM"),
		AlertMailTo:     mailTo,
		AlertDryRun:     dry,
		Approvers:       approvers,
		RetentionDays:   retention,
		DemoDevices:     demo,
		TenantID:        os.Getenv("PC_TENANT_ID"),
		WebClientID:     os.Getenv("PC_WEB_CLIENT_ID"),
		WebSecret:       os.Getenv("PC_WEB_CLIENT_SECRET"),
		PublicURL:       env("PC_PUBLIC_URL", "http://"+addr),
		SessionKey:      key,
		AllowedUsers:    allowed,
		AllowedGroup:    os.Getenv("PC_ALLOWED_GROUP"),
		AuthDisabled:    noAuth,
		EasyAuthSecret:  os.Getenv("PC_EASYAUTH_SECRET"),
		DeployerUsers:   deployers,
		DeployerGroup:   os.Getenv("PC_DEPLOYER_GROUP"),
		BackupDir:       env("PC_BACKUP_DIR", "backups"),
		Addr:            addr,
		DatabaseURL:     env("PC_DATABASE", "policy-console.db"),
		TemplateDir:     os.Getenv("PC_TEMPLATE_DIR"),
		ExtraTemplates:  os.Getenv("PC_EXTRA_TEMPLATES"),
		CISDir:          os.Getenv("PC_CIS_DIR"),
		ClientID:        os.Getenv("PC_CLIENT_ID"),
		ClientSecret:    os.Getenv("PC_CLIENT_SECRET"),
		PlannerPlanID:   os.Getenv("PC_PLANNER_PLAN_ID"),
		PlannerGroupID:  os.Getenv("PC_PLANNER_GROUP_ID"),
		PlannerClientID: os.Getenv("PC_PLANNER_CLIENT_ID"),
		PlannerSecret:   os.Getenv("PC_PLANNER_CLIENT_SECRET"),
		ReadClientID:    os.Getenv("PC_READ_CLIENT_ID"),
		ReadSecret:      os.Getenv("PC_READ_CLIENT_SECRET"),
		SnapshotCron:    env("PC_SNAPSHOT_INTERVAL", "24h"),
		ReadOnly:        ro,
		ReportOnlyHours: func() int {
			n, err := strconv.Atoi(env("PC_REPORT_ONLY_HOURS", "48"))
			if err != nil || n < 0 {
				return 48
			}
			return n
		}(),
	}
}
