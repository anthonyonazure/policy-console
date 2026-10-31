# Adversarial review: Policy Console, MSP Edition PRD

Reviewed: `docs/prd/prd.md` (status: ready-for-architecture, 2026-10-27)
Ground truth read: `internal/engine/engine.go`, `internal/engine/rollout.go`, `internal/store/store.go`, `internal/api/api.go`, `internal/auth/auth.go`, `internal/graph/graph.go`, `internal/diff/diff.go`, `internal/catalog/catalog.go`, `cmd/policyconsole/main.go`, `cmd/policyconsole/gate.go`, `internal/config/config.go`, `internal/api/web/app.js`, `scripts/run-readonly.sh`, `README.md`.
Method: every claim about "today" was checked against code. Findings cite file and function so each can be re-verified. Nothing in the PRD was edited.

## Verdict

**Not ready for architecture as labeled. Revise first.** The product direction is sound and the scope is honest about its size. The problems are in the seams: the delivery order starts with a feature (scheduled drift) whose data does not exist until a later step, two headline safety statements describe guards the code does not have, and several operator day-one needs (throttling, delete semantics, consent state, secret handling, concurrency) are either missing or contradicted by current behavior. None of this needs a redesign; most of it needs a sentence or two of requirement text and one reordered delivery step.

Severity key used below: **S1** blocks architecture or breaks a stated safety property; **S2** will bite during build or first rollout; **S3** clarity or hygiene.

---

## 1. Verification of the PRD's claims about the existing program

| PRD claim | Verdict | Evidence and nuance |
|---|---|---|
| Console writes only CA, named locations, authentication strengths, settings catalog policies | **True for object kinds, incomplete for write types** | `catalog.Kind` has exactly four constants and `Snapshot`, `Compare`, `Deploy` all iterate exactly those four. But the console also writes **assignments** on settings catalog policies (`assign()` POSTs to `.../assign`, which replaces the whole assignment list) and PATCHes CA `state` and targeting (`Enforce`, `Widen`). The PRD's F3 framing ("four kinds") hides that assignment is already a separate, un-versioned write surface (see 5.3). |
| No alerting | **True** | A search for alert, webhook, Teams, exception found nothing. `scheduledSnapshots` only logs a line per tenant. |
| No per-client overrides | **True, and worse than stated** | There is no server-side per-client data at all. Placeholder values live in the operator's browser `localStorage` under one key, `pc.tokens`, which is **not keyed by tenant** (`app.js` lines 8, 559 to 561). The pilot group id is likewise one global value (`pc.pilotGroup`). The server's `tenants` table has only id, name, status, notes. So "profile" (FR-11) is new storage, not an extension, and today's single global token set is a cross-client hazard the PRD does not mention. |
| Manual pilot to all rollout | **True** | `RolloutPilot/All/None` in `Deploy`, plus `Widen` and `Enforce` (48 hour report-only minimum, config `PC_REPORT_ONLY_HOURS`). Nuance: `applyPilot` narrows only CA policies that include "All" users. Policies aimed at roles, guests or specific groups are applied as written, with no pilot at all. A "10 percent ring" for those has no existing mechanism. |
| "the scheduler only takes snapshots" | **True** | `scheduledSnapshots` is a single goroutine ticker, sequential across tenants. |
| "Graph adapter has no tests" | **True** | No `graph_test.go`. |
| NFR-1: "Every write has a preview, a before and after snapshot and a role check." Listed as the existing safeguard | **False as a description of today** | See 5.1 and 5.3. Only `Deploy` has a preview mode. `/modify`, `/revert`, `/enforce`, `/widen` have none. Widen on an Intune policy writes no version at all. In `Write()`, a failed before-snapshot is swallowed (`if ver, _, err := ...; err == nil`) and the PATCH proceeds, so "snapshotted first" is best-effort. Role check is true (path allowlist in `auth.readOnlyPost`). |
| NFR-7: "The existing refusal to start with writes enabled and no sign in stays." | **Slightly overstated** | `writeGateError` allows writes with no sign-in on a localhost bind (the dev case), and with sign-in it only requires an allow-list. The "refusal" is for non-local binds and for missing allow-lists. Fine, but the PRD should not imply writes are never possible unauthenticated. |
| Summary: "for one operator" | **Out of date** | Code already has two roles (viewer, deployer) via `PC_DEPLOYERS` / `PC_DEPLOYER_GROUP`. Section 3 and NFR-7 then introduce a third role. |
| NFR-6: backup and restore drill "exist and run on a schedule" | **Half true** | `policyconsole backup` and `scripts/restore-drill.sh` exist; nothing schedules them. A scheduled backup and a monthly restore test are new work. |
| FR-10 / Decision: "JSON in the console database is the single source of truth" | **Conflicts with two current sources of truth** | README says OneDrive `Clients/Policy Templates` is the source of truth (synced via `sync-templates.sh` into the binary), and `scripts/build_praxis.py` is the source for the praxis set, with provenance tests. The PRD does not say how either is retired or migrated. |

Config note (not a PRD claim, but relevant): `config.DatabaseURL` is documented as "sqlite file path, or postgres:// URL", yet `store.Open` only opens SQLite. NFR-3 treats a server database as a deferred option; it is not a config switch today.

---

## 2. Requirements that are untestable or vague

| Where | Problem | Fix |
|---|---|---|
| Section 4, "Zero admin lockouts caused by a console deploy" | Zero over what window, and how is causation established? | State the evidence source (incident log) and the window (rolling 12 months). |
| Section 4, "unacknowledged alerts older than 7 days stay under 10%" | No requirement defines acknowledge, snooze, owner or resolved states. The metric cannot be measured. | Add an FR for alert lifecycle (new, acknowledged, resolved, auto-resolved when drift clears). |
| Section 4, "Share of tenants at or above their pack's target" | "Target" is never defined per pack. "Score" is also never defined; README defines Deployed, Enforced, Fidelity plus Secure Score. | Define the score (which of the existing numbers, or a new composite) and where the target is set. |
| Section 4, "Unplanned reverts per month stay low" | Not a number. | Give a threshold or drop it. |
| Section 4, "Policy changes with a recorded author, reason and prior version: 100%" | Scope unclear. Portal changes by others (the whole point of drift) cannot have a console author or reason. Today `modify` takes an optional free-text note. | Scope it to changes made through the console and make reason mandatory on those. |
| FR-7 "could lock out every administrator" | Existing `equiv.BlocksEveryone` tests one thing: block grant, all users, all apps. "Every administrator" is a different, broader check, and "could" is unbounded. | List the rules (for example: break-glass group excluded; admin roles not covered by a policy requiring a device state no admin can meet). Each rule becomes a test. |
| FR-20 "ignores fields Microsoft adds or changes on its own" | Open ended. See 3.1: this requirement as written defeats FR-22/23. | Replace "compare only fields we own" with an explicit server-field ignore list plus a protected-paths list that is always compared. |
| FR-23 "Rules are editable" | By whom? Editing a severity rule can silence critical drift fleet-wide. | Name the role (approver) and require an audit entry. |
| FR-27, FR-28 "Should" items | "Stale devices", "compliance falling" have no threshold. | Define or defer. |
| FR-32 "where Microsoft exposes it" | The gate's health signal is unspecified, and with zero devices in a ring the error share is undefined (division by zero passes vacuously). | Specify the signal, a minimum sample size, and the behavior at zero devices. |
| FR-30 "10%" ring | Entra has no percentage groups. Who picks the 10 percent? FR-36 (suggest pilot members) is a Should. | Define ring membership: static group maintained by whom, or dynamic rule. Make the Must ring plan not depend on a Should. |
| FR-36 | Pilot suggestion needs device inventory read permission not otherwise listed. | List in the permission set. |
| FR-49 "plain language", NFR-9 | No acceptance test. | Name a reading-level check or a sample review by Anthony per report template. |
| NFR-2 "100 tenants in 4 hours" | Tenant size not given (policy count, settings catalog policies are large). Marked [ASSUMPTION] but still a Must-class NFR. | State assumed objects per tenant and the test dataset. |
| FR-47 | Tagged **Must** in the heading and **[ASSUMPTION]** in the text. | Decide which. |
| FR-53 to FR-56 | "Reviewed against the House deviations" has no deliverable. Android "tested on a real device" names no device matrix. | List the deliverable and device list. |
| FR-1 / FR-52 | "Framework (CIS, SCuBA, HIPAA, CMMC)" browse and "compliance mapping HIPAA, CMMC, NIST" need a control mapping source. README shows the existing mapping is deliberately limited to controls the console can validate. | Say which frameworks are fetched versus hand-mapped, and reuse the README's "validate against the published catalog" rule. |

---

## 3. Contradictions between sections

### 3.1 FR-20 and NFR-4 versus FR-22 and FR-23 (S1)
FR-20 and NFR-4 say compare **only fields we own**. FR-22/23 want to detect the most dangerous CA drift: someone adds an exclusion. Today `diff.Compare` reports any live-only key as `added`. If it switches to "only keys the template has", an added `excludeUsers` or `excludeGroups` is invisible whenever the template omits that key. In the shipped CA templates, **at least 5 of 21** have no `excludeUsers` key at all (for example C001, C002, C003a, C004, C005). So the proposed noise fix would silently blind the tool to the exact event it exists to catch. The ignore mechanism must be a denylist of known server fields (today's `diff.Ignored`), with a protected-paths list (users, groups, exclusions, grant controls, state, session controls) that is always compared even when absent from the template.

### 3.2 Delivery order versus data dependencies (S1)
Section 9 step 1 ships scheduled drift and alerts (FR-21 to FR-29). `Engine.Compare` takes `tokens` (the placeholder values) and `Template.Render` **refuses** to render with any unfilled placeholder. A scheduled compare has no tokens: they are in one operator's browser. Result: every placeholder template returns `error: still needs values for ...`, which is either skipped (no drift detection) or scored (garbage). Per-client profiles (FR-11) arrive in step 3. Also FR-26 option 3 ("accept as the new client override") depends on overlays (F2, step 3), and FR-13 exclusions (a way to stop "missing" alerts for a client with third-party EDR) are also step 3, yet alert-noise metrics start applying in step 1. Fix: move the minimum profile store (placeholder values per tenant) and exclusions into step 1, or run step 1 in report-to-screen mode with no outbound alerts until they exist.

### 3.3 Alert latency arithmetic (S2)
Metric: setting change to alert in 24 hours or less. Facts: snapshot interval default 24h (`PC_SNAPSHOT_INTERVAL`), compare runs after the snapshot (FR-21), fleet window up to 4 hours (NFR-2), non-critical items wait for the daily digest (FR-25). Worst case for a critical is roughly 24h + 4h = 28h; for a non-critical, up to about 52h. The target cannot be met with the stated design. Either shorten the interval (and re-run the throttling math) or restate the metric as "next scheduled run".

### 3.4 "Critical posts immediately" versus "one message per client per day" (S2)
FR-25 says both. A second critical event six hours after the first on the same client: new message or folded into the first? Define: one message per client per run, criticals bypass the daily cap but are batched within a run.

### 3.5 FR-29 retention misdescribes the store (S1/S2)
FR-29: "keeps daily versions for 90 days and then keeps only changed versions." `Store.SaveVersion` **already** stores only changed versions: it skips the insert when the hash equals the previous version. There are no daily copies to prune. If an implementer builds the stated default (daily copies), storage grows, the opposite of NFR-3. What FR-21 adds is a daily **compare result**; that is probably what the retention rule means, but the requirement says snapshots. Also, pruning object versions is dangerous: `ReportOnlySince` derives the 48 hour enforcement guard from version history, `Revert` needs old bodies, and `run_items.before_ver/after_ver` plus FR-51 audit point at specific versions. Retention must say: never prune versions referenced by a run item, the latest version, or the version that started a report-only period.

A related data note: the version hash covers the raw body including volatile fields like `lastModifiedDateTime`, so a no-op touch by Microsoft creates a new version. "Changed" counts and retention estimates will run higher than the PRD assumes; use `diff.Compare` (which has the ignore list) to decide "changed", or hash a normalized body.

### 3.6 Two canary concepts (S2)
FR-5 and the decisions list a **canary tenant** (Anthony's own) used to test drafts. FR-47 says fleet writes use **the first tenants as canary**. FR-30/32 define **rings within a tenant**. Three staging concepts, no stated relationship or order (draft canary, then fleet canary tenants, then per tenant rings?). With "Careful client: one week between rings", a fleet change touching a canary tenant first could take weeks; no time budget or skip rule.

### 3.7 Success metric 1 versus FR-40 (S2)
"Consent to full standard deployed and verified in 2 hours hands-on" versus every build step running through the rollout engine with a ring plan and gate waits (FR-40, "Careful client" is one week between rings). A brand-new tenant has no devices, so rings are meaningless and gates pass vacuously. Define a "new tenant" ring plan that has no waits and applies to empty tenants, and say that report-only CA minimums (FR-35) still apply.

### 3.8 FR-35 and the Emergency ring plan (S2)
FR-35 keeps the 48h report-only minimum. FR-30 ships an "Emergency (single ring, extra confirmation)" plan. Does Emergency bypass the minimum? Today `Enforce` allows an override **with a typed reason** and logs it. A scheduled or rollout-driven enforce has no human to type a reason. State that the rollout engine may never enforce a CA policy without a human override reason on the record.

### 3.9 Roles (S2)
Section 3: Anthony "owner, deployer" and also the sole approver; technician "deployer ... can edit only drafts"; NFR-7 "three roles (viewer, deployer, approver)". Open points: who may create exceptions (FR-24), edit severity rules (FR-23), set freeze windows (FR-37), start a rollout, cancel one? Single approver means fleet changes, publishes and, per FR-30, the Emergency plan all block when Anthony is unreachable. Is that intended? Also see 5.4 for the default-open role pattern in the current code.

### 3.10 Minor
- FR-20 sits under F3 (object coverage) but is a drift requirement; it belongs in F4.
- FR-34 "never leaves an object assigned to nobody by accident" conflicts with the Foundations pack (groups, filters, scope tags are legitimately unassigned) and with current `RolloutNone` (documented, works, UI never defaults to it). Scope the rule to policy kinds.
- Risk table says "57 requirements"; there are 57 FRs plus 10 NFRs.
- Success metric counter "Any write that bypasses preview or snapshot: zero" is **already nonzero** today (see 5.1 and 5.3), so the baseline is not zero.

---

## 4. Missing requirements an MSP operator hits on day one

### 4.1 Permissions and consent (S1)
- The PRD says the permission list will be "decided up front" (Section 9) but never lists it. Architecture cannot proceed without it, and the consent round happens before step 1 ships because FR-28 (Should, in step 1) needs new reads. Add the list, with each permission mapped to the FR that needs it. (I have not asserted Graph permission names here; confirm each against Microsoft Learn when the list is written.)
- **There is no consent-state tracking and the current code actively misreports it.** `Engine.Snapshot` always ends with `UpsertTenant(... Status: "connected")` even when every `List` call failed. A client who revokes consent still shows "connected" after the nightly snapshot, so drift monitoring would show "no changes" instead of "we cannot see this tenant." Likewise `Snapshot` and `probeTenant` pass an empty `Notes`, and `UpsertTenant` overwrites `notes` on conflict, so operator notes are wiped every night. Both fix: Snapshot must set status from outcome, and upsert must not overwrite notes.
- `Probe` only reads `/organization`. FR-41 "console permissions granted" and the fleet board's "consent status per tenant" (Risks table) need a defined mechanism: probe each kind's endpoint, store per-kind result, surface a partial state ("CA ok, compliance 403").
- **Compare is all or nothing.** `Engine.Compare` returns an error on the first failed `List`. After new kinds are added, any tenant not yet re-consented would fail the entire compare and score, including the four kinds it can read today. NFR-4 ("a failing adapter degrades one feature") is therefore false for the compare path as written. Require per-kind results with a "not permitted" state that is excluded from scoring, not scored as missing.
- Separate read and write credentials already exist in practice: `scripts/run-readonly.sh` reads a **read-only app registration** from 1Password and runs with `PC_READ_ONLY=true`; the write registration is "intentionally not scripted." The PRD's design (one process running unattended drift reads, unattended ring starts, and fleet writes) needs the write credential loaded permanently, ending that separation. Decide: two registrations with the scheduler's reads using the read-only one and writes requiring a separately armed credential, or accept the larger blast radius explicitly. Note also `PC_READ_ONLY` is process-wide; the PRD does not say what happens to in-flight rollouts when it is on (FR-31 says state survives restart).
- Re-consent mechanics: README records that `az ad app permission admin-consent` reported success without granting; an explicit app role assignment was needed. Put that in the consent runbook requirement.

### 4.2 Throttling (S2)
NFR-2 asks the console to "honour Microsoft's throttling per tenant, retrying with backoff." `internal/graph/graph.go` has **no** 429 handling, no `Retry-After`, no retry, a fixed 60 second timeout, and `NewGraph` builds a fresh client (and fetches a fresh token) per operation. `score` already fans out four concurrent Graph readers per request. So this is net-new engineering, absent from the risk table, and the 4 hour NFR depends on it. Add: per-tenant concurrency cap, global cap, `Retry-After` honored, jitter, a token cache shared across calls, and a "tenant throttled" state distinct from "tenant failed."

### 4.3 Secret handling (S1/S2)
NFR-5 covers the console's own credentials only. Not covered:
- **Secrets inside policy bodies.** FR-55 ships Wi-Fi, VPN and email profiles; certificate and SCEP/PKCS profiles and pre-shared keys exist in this family. Every snapshot stores the full Graph body as plain text in `object_versions.body`, and `policyconsole backup` copies the whole database. Define: which fields are redacted before storing, what the diff and report show, and whether backups are encrypted.
- Teams Workflows webhook URL: FR-25 says "kept in the secret store." There is no secret store abstraction; configuration is environment variables. A webhook URL is a bearer credential to post into a client-facing channel. Say where it lives and who can read it.
- App secret expiry: one multi-tenant secret serves every client. Its expiry takes all tenants dark at once. README says certificates are "better" but `graph.go` supports only client secret. Require expiry monitoring (an alert at 60/30/7 days), and ideally certificate auth.
- Exports (FR-10, FR-49, FR-52) and the evidence pack must not include secret values or tenant identifiers beyond the intended client.

### 4.4 Rollback of a fleet write (S1)
- Rollback exists per object only (`Revert`). FR-45 offers a blast-radius preview but no fleet-level undo: "revert this change in all 6 tenants," plus partial-failure semantics (tenant 3 of 6 fails; do 4 to 6 proceed; who is told).
- **Revert cannot undo a create.** FR-33 says cancel "offers to revert the payload to its previous version." For a newly created policy the previous state is "absent," which is a delete. `graph.Client.Delete` exists but has **no caller** in the engine, and `Revert` refuses deletion markers ("nothing to write back") and uses PATCH, so it cannot recreate a deleted object either. The PRD never authorizes delete anywhere (FR-16, FR-19 list read, create, version, revert), yet FR-22 "extra", FR-26 "restore to standard", FR-33 and FR-44 offboarding all imply deletion or recreation. Add an explicit delete/recreate requirement with its own gate, or state that these actions will not delete. Section 5's hard rule ("writes only through previewed, snapshotted, role-checked actions") needs to name delete.
- **Revert cannot undo an assignment change.** Snapshots fetch settings catalog policies with `$expand=settings` only. Assignments are not in the stored body, so FR-33's revert of a ring expansion leaves the policy assigned. And `assign()` replaces the entire assignment list, so ring widening or `Widen` can wipe a client's existing exclusions or assignments with no record of what they were.
- Settings catalog `Write` is a PATCH and revert is "write back the stored body"; the PRD should require per-kind proof (test) that revert actually restores each new kind (FR-19 says "same revert path" but the path is only proven for four kinds).

### 4.5 Tenant offboarding (S2)
- `Store.DeleteTenant` deletes only the `tenants` row. `object_versions` and `runs` stay, orphaned (no foreign keys defined), and re-adding the same tenant id resurrects the history. For client data this needs a policy: retain for N days for audit, then purge; export to client on request.
- FR-44 (Should) removes deployed objects; nothing covers: stopping scheduled snapshot, compare, alerts and digests for that tenant; cancelling its active rollouts; removing its overrides, exceptions and freeze windows; and the one step the console cannot do, which is the client admin deleting the enterprise application (consent revocation). The runbook should say who does it and how the console confirms it (the tenant will flip to "cannot read," which is currently misreported as connected, see 4.1).
- FR-44 needs "what the MSP deployed" to be knowable. `run_items` records created object ids but nothing is stamped on the object in the tenant, and matching is by name (see 5.5). Stamp objects with a marker (description or tag) so offboarding does not delete a client's own policy that happens to share a name, or miss a renamed one.

### 4.6 Time zones (S2)
Everything stored is UTC RFC3339 (good), and the scheduler is a plain `time.Ticker` from process start, not wall-clock. The PRD introduces "daily digest," "one message per client per day," "daily versions," "change freeze windows per client" (FR-37) and a calendar view, with no time zone anywhere (FR-11's profile has none). Require: a console time zone for digest and cadence, a per-client time zone for freeze windows and ring start times, defined behavior on DST changes, and wall-clock scheduling that survives restarts (today a restart resets the 24h timer, and a deploy restart at 09:00 means the next snapshot is 09:00 tomorrow regardless of intent).

### 4.7 Concurrency between a scheduled job and a manual deploy (S1/S2)
Current behavior and gaps:
- No per-tenant lock. `Snapshot`, `Deploy`, `Write`, `Enforce`, `Widen` can all run on one tenant at once (the HTTP handlers and the ticker goroutine are independent).
- `Store.SaveVersion` is SELECT-latest-then-INSERT. Two writers on the same object can compute the same `next` and one hits `UNIQUE(tenant_id, kind, object_id, version)`. In `Deploy`/`Write` the error is swallowed (`err == nil` guards), so the deploy's post-change snapshot can be silently lost, leaving the revert chain with a gap. SQLite WAL with a 5 second busy timeout reduces but does not remove this.
- Lost update: `Write` reads, then PATCHes with no `If-Match`/ETag, so "restore to standard" from an alert (FR-26) can overwrite a legitimate portal hotfix made seconds earlier.
- Rollout state (FR-31) adds a third actor: a ring start timer that fires during an operator's manual change to the same object. Need per-object (tenant, kind, object id) exclusive lease, a "rollout owns this object" marker that manual deploy respects, and a rule for what the scheduler does to an object mid-rollout (its drift is expected: a pilot-narrowed CA policy differs from the template by design; `Compare` would flag it as drifted and alert).
- Two instances: README allows running as a container and on a Mac. Two processes would each run the ticker and each start rollout timers. Require a single-active-instance guarantee (lock row with lease) or state "one instance only."
- Related: today's `Snapshot` marks absent objects as deleted only when the whole run had zero errors, which is the right conservative rule; keep it, and apply the same rule to alerting ("missing" must not alert when the read was partial).

### 4.8 Other day-one gaps
- **Monitoring the monitor.** No requirement alerts when the scheduler did not run, the Teams webhook returns an error (Workflows triggers can be deleted or throttled), or the digest email failed. Silent failure of the alert path looks identical to a healthy tenant.
- **Email sending** is only "daily email digest." No sender identity, no provider, no credentials, no recipient list per client or per technician. This is a new outbound integration with its own permission and secret.
- **Teams assumption.** The PRD states the old webhook connectors were retired on 2026-04-30 and that Workflows does not support private channels. Both are external claims that I could not verify from the repository; confirm against Microsoft docs before the design depends on them.
- **Outward-facing action approval.** Client reports (FR-49) are sent to clients. Nothing says who reviews a report before it leaves, or whether the console sends it at all (the Summary says clients "receive reports"). By Anthony's confirm-before-outward rule this needs a human send step.
- **Licensing.** Open item 3 defers per-client licensing checks to preflight; but a template that needs a license a client lacks will create then fail or be inert. Make the preflight check a blocker for those templates, not a note.
- **Name collisions and matching** are covered in 5.5.
- **Migration.** Existing tenants already have deployed policies. No requirement covers adopting them under the new template records and overlays without producing a flood of "extra" and "missing" alerts on first run. See also 5.2.

---

## 5. Conflicts with existing safety guards

### 5.1 "Previewed" is not enforced by the server for most writes (S1)
README: "Nothing is written without a preview first." In code, the preview is a UI convention: `POST /deploy` with `preview:false` writes directly; `/modify`, `/revert`, `/enforce`, `/widen` have no preview mode at all. The Section 5 hard rule and NFR-1 treat preview as a built-in guard. For fleet apply (FR-45), unattended ring starts, and scheduled enforcement, "preview" must become a server-side object (a stored plan id that the write must reference and that must match what executes), or the guarantee does not exist for exactly the paths with the highest blast radius.

### 5.2 "An existing policy is never overwritten by a deploy" versus FR-14, FR-26, FR-45, FR-12 (S1)
`Deploy` skips any object whose name already exists (`exists, left unchanged`). Replacing a live policy is the separate `Write/modify` path. Several PRD features are exactly overwrites: FR-45 "apply a ... version change to many tenants," FR-14 follow the latest published version, FR-26 "restore to standard," and the first-run adoption of already-deployed policies. The PRD must say which path they use, that overwrite stays a distinct, confirmed, snapshotted operation with its own preview of the **field-level diff** (not "creates 14 policies"), and that the blast radius preview for a version change shows changes, not creations.

### 5.3 "Every change is snapshotted before and after" versus assignment writes (S1)
`Engine.Widen` for Intune calls `assign()` and writes a `runs` row with no run items and no version. `Deploy` also assigns after create and then takes the post-change snapshot, but assignments are not part of the stored body. Today's guarantee does not cover assignment, which is precisely what a ring engine (F5) manipulates. Requirement needed: capture assignments (include them in the read for every kind that has them) before and after, store them, and make revert restore them. This also gives FR-22 "unassigned" its missing data source, since no code today reads assignments for drift.

### 5.4 Role defaults are fail-open (S2)
`auth.IsDeployer`: if neither deployer list is configured, **every allowed user is a deployer**. The new approver role needs the opposite default or Anthony's "sole approver" decision silently becomes "every deployer is an approver" on any deployment where the new variable is unset. Require fail-closed: no approver configured means no approvals possible, and the console says so on startup. Also the role gate is a path allowlist for viewer POSTs (`/probe`, `/snapshot`, `/compare`, `/score`); every new POST (generate report, acknowledge alert, prospect scan) will be deployer-only by default, which may block the Viewer role's stated "reports and audits" use. Decide per endpoint.

### 5.5 Name-based matching versus naming prefix, edit, rename, overlay (S1)
`Compare` and `Deploy` match templates to live objects by lowercase **display name**. Consequences the PRD does not address:
- FR-11 per-client naming prefix: for every already-deployed policy, the rendered name changes, so existing objects stop matching and read as **missing** (and the old ones as **extra**), and `Deploy` would create duplicates because the name does not clash. Needs a stable identity link (template id stamped into the object, or an id mapping table) before prefixes, edits (FR-3 can change a name), or version moves exist.
- A technician renaming a policy in the portal is classified as missing plus extra rather than "changed." FR-22 classes cannot distinguish them without an identity link.
- Duplicate names in a tenant collapse in the `live` map (last wins).
- Microsoft CA templates and praxis templates are skipped from the expected set in `Compare` (by design, see code comment), so objects deployed from them appear in `Unmanaged`, which FR-22 would classify as **extra** and alert on. Define how packs built from these categories count as "expected."

### 5.6 CA lockout guard covers one pattern, new kinds have none (S1)
`BlocksEveryone` is CA only. FR-19 says new kinds get the "same preview, snapshot, role check and revert path," but the lockout guard is the safety property that matters for FR-16: an enrollment restriction that blocks all platforms, a compliance policy plus a CA "require compliant device" that no admin device can meet, an update ring that force reboots, a BitLocker or ASR policy on server groups. For each new kind, require a named "cannot do harm to everyone" check, or explicit acknowledgment that none exists and an extra human gate.

### 5.7 Pilot narrowing only works for one CA shape (S2)
`applyPilot` leaves any CA policy not targeting "All" unchanged, with a note. FR-30/34 describe rings as if every payload can be ring-scoped. State which payloads can be staged and which must be treated as single-step with a stronger gate (or report-only) rather than silently applied to everyone.

### 5.8 Two ignore lists already diverge (S3)
`engine.readOnlyFields` (used by `strip` before writes) and `diff.Ignored` (used by compare) overlap but differ (for example `settingInstanceTemplateReference`, `version` appear only in `diff`). NFR-4 promises "one adapter." Require a single source for the server-field list used by diff, version hashing and write stripping, with a contract test.

### 5.9 Existing Enforce guard is human-keyed (S2)
Covered in 3.8. The guard needs a human actor and override reason; the scheduler's actor is the literal string `scheduler`. Audit (FR-51) of unattended actions should record the approving human and approval id, not just `scheduler`.

### 5.10 Version history is the evidence for the report-only guard (S2)
`ReportOnlySince` reads `object_versions` to prove how long a policy was report-only. A retention rule (FR-29), a restore from backup, or a tenant delete/re-add changes that proof. State the dependency and protect it.

---

## 6. Requirement ID check

- FR-1 to FR-57: sequential, no gaps, **no duplicates**. NFR-1 to NFR-10: sequential, no duplicates.
- Cross-references resolve correctly: FR-41 (preflight) from the manual-prerequisites note and open item 3; FR-28 (expiry watch); FR-29 (retention) from NFR-3; FR-20 from NFR-4; Section 9 ranges (FR-21 to FR-29, FR-8, FR-53 to FR-56, FR-16) all point at the intended items.
- Mis-filing, not mis-numbering: FR-20 (drift comparison rule) sits under F3. FR-8 (import) is delivered in step 2 with F9 content while its dependents (FR-3 form editing, FR-5 draft/publish) are in step 3, so imported items have no draft/publish state to land in until step 3; say imported content lands as published-read-only.
- Priority inconsistency: FR-47 Must with [ASSUMPTION] (see 2). FR-28 is Should but sits in delivery step 1, whose consent round it would force.
- Items with no owning requirement though referenced: alert acknowledgment (Section 4), pack "target" (Section 4), "build plan" persistence beyond FR-43 (resume state), consent status on the fleet board (Risks table references it; F7 FR-46 does not list it).
- Lettered/unlettered "Should" items in delivery steps: step 5 includes FR-44 (Should) offboarding, which is the item operators need earliest after onboarding; consider promoting.

---

## 7. Prioritized fix list (smallest edits that unblock architecture)

1. **Reorder delivery or add the missing storage to step 1.** Per-tenant profile (placeholder values) and exclusions before scheduled compare; no outbound alerts before they exist. (3.2)
2. **Correct NFR-1 and Section 5 to describe the real guards, and add server-side plan objects** so "preview, then write" is enforced, plus capture and revert for assignments. (5.1, 5.3)
3. **Decide delete semantics** and add them to the hard rule, FR-33, FR-26, FR-44. (4.4)
4. **Fix FR-20/NFR-4** to a server-field denylist plus a protected-paths list. (3.1)
5. **Add consent state and per-kind degraded compare**; fix the "connected even when unreadable" status bug; list the permission set. (4.1)
6. **Add stable template identity** before overlays, prefixes and versions. (5.5)
7. Add throttling, secret, time zone, concurrency lease, offboarding and monitor-the-monitor requirements. (4.2 to 4.8)
8. Rewrite FR-29 against how the store really works; protect evidence versions. (3.5, 5.10)
9. Resolve the vague items in section 2, the alert latency arithmetic (3.3) and the immediate-versus-daily conflict (3.4).
10. Make approver fail-closed and define who may create exceptions and edit severity rules. (3.9, 5.4)
