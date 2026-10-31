// Command policyconsole runs the policy deployment and management console:
// one binary containing the API, the browser UI and the baseline templates.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/anthonyonazure/policy-console/internal/alerts"
	"github.com/anthonyonazure/policy-console/internal/api"
	"github.com/anthonyonazure/policy-console/internal/auth"
	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/config"
	"github.com/anthonyonazure/policy-console/internal/consent"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/graph"
	"github.com/anthonyonazure/policy-console/internal/impact"
	"github.com/anthonyonazure/policy-console/internal/notify"
	"github.com/anthonyonazure/policy-console/internal/oib"
	"github.com/anthonyonazure/policy-console/internal/rollout"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func main() {
	addr := flag.String("addr", "", "listen address, overrides PC_ADDR")
	flag.Parse()

	cfg := config.Load()
	if *addr != "" {
		cfg.Addr = *addr
	}

	// Maintenance commands: `policyconsole backup` and `policyconsole counts <db>`.
	if cmd := flag.Arg(0); cmd != "" {
		os.Exit(runCommand(cmd, flag.Args()[1:], cfg))
	}

	cat, err := catalog.Load(cfg.TemplateDir)
	if err != nil {
		log.Fatalf("templates: %v", err)
	}
	if cfg.ExtraTemplates != "" {
		n, err := cat.AddDir(cfg.ExtraTemplates)
		if err != nil {
			log.Fatalf("extra templates: %v", err)
		}
		log.Printf("loaded %d library templates from %s", n, cfg.ExtraTemplates)
	}
	db, err := store.Open(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	eng := &engine.Engine{
		Store:   db,
		Catalog: cat,
		NewGraph: func(tenantID string) *graph.Client {
			return graph.New(tenantID, cfg.ClientID, cfg.ClientSecret, cfg.ReadOnly)
		},
	}

	if cfg.ReadClientID != "" {
		eng.NewReadGraph = func(tenantID string) *graph.Client {
			return graph.New(tenantID, cfg.ReadClientID, cfg.ReadSecret, true)
		}
	}

	if len(cfg.SessionKey) == 0 {
		cfg.SessionKey = auth.NewSessionKey()
		log.Println("no PC_SESSION_KEY set: generated one, so a restart signs everyone out")
	}
	authn := auth.New(auth.Config{
		TenantID:       cfg.TenantID,
		ClientID:       cfg.WebClientID,
		ClientSecret:   cfg.WebSecret,
		RedirectURL:    cfg.RedirectURL(),
		SessionKey:     cfg.SessionKey,
		AllowedUsers:   cfg.AllowedUsers,
		AllowedGroup:   cfg.AllowedGroup,
		Disabled:       cfg.AuthDisabled,
		EasyAuthSecret: cfg.EasyAuthSecret,
		DeployerUsers:  cfg.DeployerUsers,
		DeployerGroup:  cfg.DeployerGroup,
		SecureCookie:   strings.HasPrefix(cfg.PublicURL, "https://"),
	})
	// Refusing to serve writes without sign-in is the whole point of putting it in
	// front. Listening publicly with no sign-in would expose tenant writes to the network.
	if err := writeGateError(cfg, authn.Enabled() || cfg.EasyAuthSecret != "", localOnly(cfg.Addr)); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	if !authn.Enabled() && cfg.EasyAuthSecret == "" && !cfg.ReadOnly && !localOnly(cfg.Addr) {
		log.Fatalf("refusing to listen on %s with writes enabled and no sign-in (%s). Configure sign-in, set PC_READ_ONLY=true, or bind to localhost.", cfg.Addr, authn.Reason())
	}

	alertSvc := &alerts.Service{
		Compare: eng,
		Gate:    &eng.Gate,
		Store:   db,
		Logf:    log.Printf,
		Notifier: notify.New(notify.Config{
			TeamsURL: cfg.AlertTeamsURL, SMTPAddr: cfg.AlertSMTPAddr, SMTPUser: cfg.AlertSMTPUser,
			SMTPPassword: cfg.AlertSMTPPass, MailFrom: cfg.AlertMailFrom, MailTo: cfg.AlertMailTo, DryRun: cfg.AlertDryRun,
		}, log.Printf),
	}

	var devices impact.Source = impact.GraphSource{New: func(id string) impact.Lister { return eng.Reader(id) }}
	if cfg.DemoDevices {
		devices = impact.SampleSource{}
		log.Printf("PC_DEMO_DEVICES is on: the impact preview uses invented devices")
	}

	apiServer := &api.Server{Cfg: cfg, PlannerAsync: true, Engine: eng, Store: db, Cat: cat, Auth: authn, Alerts: alertSvc,
		Impact:        devices,
		ConsentTokens: consent.AzCLI{},
		ConsentAPI:    func(token string) consent.API { return &consent.HTTPAPI{Token: token} },
	}
	if n, err := apiServer.InitLibrary(); err != nil {
		log.Fatalf("template library: %v", err)
	} else if n > 0 {
		log.Printf("loaded %d published template(s) from the library", n)
	}
	if n := apiServer.LoadMSTemplates(); n > 0 {
		log.Printf("loaded %d Microsoft Conditional Access templates from cache", n)
	}
	runner := &rollout.Runner{Store: db, Assign: engine.GraphAssigner{E: eng}, Check: apiServer.ImpactChecker(),
		ReadOnly: cfg.ReadOnly, Logf: log.Printf}
	apiServer.Rollouts = runner
	if (cfg.PlannerPlanID != "" || cfg.PlannerGroupID != "") && cfg.TenantID != "" && cfg.PlannerClientID != "" {
		// Planner lives in our own tenant and has its own app, separate from the client-facing apps.
		apiServer.Planner = graph.New(cfg.TenantID, cfg.PlannerClientID, cfg.PlannerSecret, cfg.ReadOnly)
		log.Printf("Planner is connected: build outs can be posted and kept up to date")
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if d, err := time.ParseDuration(cfg.SnapshotCron); err == nil && d > 0 {
		go scheduledSnapshots(ctx, eng, db, alertSvc, d)
	}

	go runRollouts(ctx, runner, alertSvc.Notifier)
	if cfg.RetentionDays > 0 {
		go pruneHistory(ctx, db, cfg.RetentionDays)
	}

	go func() {
		signIn := "OFF"
		if authn.Enabled() {
			signIn = "Entra ID, tenant " + cfg.TenantID
		}
		fmt.Printf("policy console on %s  (%d templates, read-only=%v, sign-in=%s)\n", cfg.PublicURL, cat.Len(), cfg.ReadOnly, signIn)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	fmt.Println("stopped")
}

// scheduledSnapshots captures every connected tenant on an interval. This is
// what makes history complete for changes nobody made through the console.
// Each cycle ends with the drift check and any alerts it raises.
func scheduledSnapshots(ctx context.Context, eng *engine.Engine, db *store.Store, alertSvc *alerts.Service, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tenants, err := db.Tenants()
			if err != nil {
				log.Printf("scheduled snapshot: %v", err)
				continue
			}
			for _, t := range tenants {
				if t.Status != "connected" {
					continue
				}
				res, err := eng.Snapshot(ctx, t.ID, "scheduled", "scheduler")
				if err != nil {
					log.Printf("scheduled snapshot %s: %v", t.Name, err)
					continue
				}
				log.Printf("scheduled snapshot %s: %d read, %d changed", t.Name, res.Captured, res.Changed)
			}
			// After the snapshots, so the drift check and the history agree on "now".
			alertSvc.CheckAll(ctx)
		}
	}
}

// runRollouts moves staged rollouts forward once a minute and tells people what
// needs them: a ring waiting for approval, a failure, a completion.
func runRollouts(ctx context.Context, r *rollout.Runner, n notify.Notifier) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var lines []string
			for _, e := range r.Tick(ctx) {
				if e.What == "activated" && e.Ring != "" {
					log.Printf("rollout %d (%s): ring %s activated", e.RolloutID, e.Name, e.Ring)
				}
				switch e.What {
				case "waiting", "error", "completed":
					lines = append(lines, fmt.Sprintf("%s, ring %s: %s %s", e.Name, e.Ring, e.What, e.Detail))
				}
			}
			if teams, _ := n.Enabled(); teams && len(lines) > 0 {
				if err := n.Teams(ctx, "Staged rollouts need attention", lines); err != nil {
					log.Printf("rollout alert: %v", err)
				}
			}
		}
	}
}

// pruneHistory removes old policy versions once a day, keeping the newest version
// of everything and any version a run still points at.
func pruneHistory(ctx context.Context, db *store.Store, days int) {
	if days < store.MinRetentionDays {
		log.Printf("retention: %d days is below the %d day floor, so history is not pruned", days, store.MinRetentionDays)
		return
	}
	run := func() {
		n, err := db.PruneVersions(days, time.Now())
		if err != nil {
			log.Printf("retention: %v", err)
			return
		}
		if n > 0 {
			log.Printf("retention: removed %d version(s) older than %d days", n, days)
		}
	}
	run()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// localOnly reports whether the console is reachable only from this machine,
// which is the one case where running without sign-in is reasonable.
func localOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// runCommand handles the non-server subcommands and returns an exit code.
func runCommand(cmd string, args []string, cfg config.Config) int {
	switch cmd {
	case "backup":
		db, err := store.Open(cfg.DatabaseURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, "database:", err)
			return 1
		}
		defer db.Close()
		path, err := db.Backup(cfg.BackupDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(path)
		return 0
	case "import-oib":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: policyconsole import-oib <Open Intune Baseline checkout> <library folder>")
			return 2
		}
		sum, err := oib.Import(args[0], args[1])
		if sum != nil {
			for lib, n := range sum.Imported {
				fmt.Printf("%-16s %d policies\n", lib, n)
			}
			for dir, n := range sum.Unsupported {
				fmt.Printf("not importable yet: %d in %s (the console cannot manage that kind of policy yet)\n", n, dir)
			}
			for _, w := range sum.Warnings {
				fmt.Println("warning:", w)
			}
			for _, sk := range sum.Skipped {
				fmt.Printf("skipped %s: %s\n", sk.File, sk.Reason)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("library written to", args[1], "; set PC_EXTRA_TEMPLATES to that folder to load it")
		return 0
	case "counts":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "usage: policyconsole counts <database file>")
			return 2
		}
		c, err := store.Counts(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Print(store.FormatCounts(c))
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %q (known: backup, counts, import-oib)\n", cmd)
	return 2
}
