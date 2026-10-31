---
title: Policy Console, MSP Edition
status: ready-for-architecture
created: 2026-10-27
updated: 2026-10-27
stakes: internal tool
mode: fast path
---

# Policy Console, MSP Edition: PRD

Items tagged **[ASSUMPTION]** are my inference and need your yes or no. **[NOTE FOR PM]** marks a decision that changes the design.

## 1. Summary

Policy Console today is a single program that reads a client's Microsoft tenant, compares it to the House policy baseline, deploys what is missing, keeps every version, and reverts. It handles Conditional Access and Intune "settings catalog" policies for one operator.

This PRD extends it into the tool an MSP runs its whole Intune practice from: keep a library of default policies for Windows, Mac, iPhone/iPad and Android; edit and create them; tailor them per client without forking; build a new client's Intune environment in an ordered, staged way; and get told when a client drifts from the standard. Clients do not log in. They receive reports.

We extend the existing console. We do not use Intune's native deployment plans (Windows only, public preview). The console gets its own staged rollout engine that works for every kind of policy.

## 2. Problem

- A new client takes many hours of portal clicking and is done a little differently each time.
- Nothing tells us when a client's setup is changed or broken between visits. Drift is only found when someone presses Compare.
- Changing a default policy means editing JSON files by hand and redeploying; there is no way to see who changed what, or to hold a client on an older version.
- The default set covers Windows, Mac and Defender well but has one iOS file and no Android, no compliance, no app protection, no enrollment.
- Every client is slightly different (their own EDR, their own patching tool) and today that difference lives in someone's head.

## 3. Users

- **Anthony (owner, deployer):** designs the standard, onboards clients, approves fleet changes.
- **Technician (deployer):** applies approved packs, handles alerts, can edit only drafts. A third role, *approver*, publishes templates and approves fleet changes. **Decided 2026-10-27:** Anthony is the only approver; technicians draft and deploy approved packs.
- **Viewer:** read only, for reports and audits.
- **Clients:** never use the console. They receive a score report.

## 4. Success metrics

| Metric | Target | Counter-metric (what we must not break) |
|---|---|---|
| Hands-on time to take a new tenant from consent to the full standard deployed and verified | 2 hours or less **[ASSUMPTION]** | Zero admin lockouts caused by a console deploy |
| Time from a client setting being changed to an alert | 24 hours or less | No more than 3 alerts per tenant per week after exceptions are set; unacknowledged alerts older than 7 days stay under 10% **[ASSUMPTION]** |
| Share of managed tenants scoring at or above their pack's target | 90% | Unplanned reverts per month stay low and are reviewed |
| Policy changes with a recorded author, reason and prior version | 100% | Any write that bypasses preview or snapshot: zero |

## 5. Scope

**In (first release):** policy library with draft/publish, per-client overlays, expanded object coverage, scheduled drift with alerts and exceptions, console rollout engine, build-out wizard, fleet apply, client report, content for Windows, macOS, iOS/iPadOS and Android.

**Out (now):** client logins or portal, Intune native deployment plans, PSA ticket integration (see open items), device-level actions (wipe, retire, remote actions), app packaging pipelines, Partner Center anything.

**Hard rule:** the console only ever writes to a client tenant through previewed, snapshotted, role-checked actions. Anything outside that is not built.

## 6. Features and requirements

Requirement IDs are stable. "Must" means first release.

### F1. Policy library (inventory, edit, create, publish)

Today templates are embedded files. They become records in the console's database with a state: *draft*, *published*, *retired*.

- **FR-1 (Must)** Browse the library by platform, workload (security, update, app, compliance, identity, enrollment), framework (CIS, SCuBA, HIPAA, CMMC) and pack.
- **FR-2 (Must)** Every template shows, in plain English, what it does, what can break, and who to warn, plus its source (library, Microsoft, upstream baseline, judgement).
- **FR-3 (Must)** Edit a template through a form built from Microsoft's own setting definitions, showing human setting names and the recommended value. Raw JSON is available but not the default.
- **FR-4 (Must)** Create a new template from scratch or by cloning an existing one or by adopting a live policy from a tenant.
- **FR-5 (Must)** Saving creates a draft. Publishing needs the approver role and a reason. A draft can be tested against a canary tenant before publishing.
- **FR-6 (Must)** Each publish creates a new template version (content hash, author, reason, parent). Any two versions can be compared side by side in plain words, and a template can be reverted to an earlier version (the revert is itself a new version).
- **FR-7 (Must)** A template cannot be published if it is invalid against Microsoft's setting definitions or if a rule check finds it could lock out every administrator.
- **FR-8 (Must)** Import from OpenIntuneBaseline (Windows, macOS, BYOD app protection) and from a folder of exported policy JSON. Imported items keep their source and version.
- **FR-9 (Should)** Weekly upstream watch: check OpenIntuneBaseline and Microsoft baselines for changes and open a "what changed" review item for each affected template.
- **FR-10 (Should)** Export any published template as JSON, Bicep or Terraform, so the existing generated formats keep working. **Decided 2026-10-27:** JSON in the console database is the single source of truth; the Python generator becomes an export step.

### F2. Per-client tailoring (overlays)

- **FR-11 (Must)** Each client has a profile: placeholder values (groups, named locations, company text), naming prefix, and flags (has third party EDR, has RMM patching, regulated, BYOD or corporate).
- **FR-12 (Must)** A client overlay is a small patch on top of a template, never a copy. The console shows for each client a table of every template as *Included*, *Modified*, *Excluded* or *Added*, with a reason.
- **FR-13 (Must)** Excluding a template (for example Defender policies when a third party EDR is present) removes it from that client's expected set, so it is not scored as missing.
- **FR-14 (Must)** A client can follow the latest published version or be pinned to a chosen version, with a visible "behind by N versions" marker.
- **FR-15 (Should)** Overrides carry an owner and an optional expiry date; expiry produces a review item.

### F3. Wider object coverage

Today the console writes only Conditional Access, named locations, authentication strengths and settings catalog policies. The standard needs more.

- **FR-16 (Must)** Read, compare, deploy and version: device compliance policies (all four platforms), app protection policies (iOS, Android, Windows), legacy device configuration profiles where the settings catalog has no equivalent, Windows Update rings, enrollment restrictions, Autopilot profiles, and assignment filters.
- **FR-17 (Must)** Read, create and version Entra groups (dynamic and static) and scope tags used by a pack, so a pack can be self contained.
- **FR-18 (Should)** Read and compare apps and app assignments (Company Portal, Office, Edge, Teams) and write assignments.
- **FR-19 (Must)** Each new object kind goes through the same preview, snapshot, role check and revert path as existing kinds.
- **FR-20 (Must)** Drift comparison uses an explicit list of server set fields to ignore (ids, timestamps, version counters, read only fields) so a beta API change does not raise false alarms, and a list of protected paths that are always compared even when the template does not mention them (for example Conditional Access user and group exclusions, so an added exclusion is drift). *Revised after review: the earlier wording, "compare only fields we own", would have hidden exactly the added exclusions that matter most.*
- **FR-58 (Must)** Grant consent through GDAP. Because Global Admin and GDAP exist in every client tenant, the console grants its own application permissions in a client tenant itself, instead of sending a link for the client admin to click. Verify and record the grant per client and per permission after it is made, because Microsoft's own command has reported success while granting nothing (found in this project).
- **FR-59 (Must)** Two application registrations, not one. A *read* registration (inventory, drift, assessments) and a *write* registration (deploy, rollout). The write registration is consented only in clients onboarded for management. Consent grants are writes to a client tenant, so they use the same preview, confirmation and audit trail as any deploy. Nothing here touches the Partner Center API.
- **FR-60 (Must)** Consent state is tracked per client and per object kind, so one refused permission blocks only that kind instead of the whole comparison, and a tenant is shown as connected only when its reads actually succeeded.
- **FR-61 (Must)** Alert lifecycle: an alert is *new*, can be *acknowledged* or *snoozed* by a named person, and is *resolved* automatically when the drift clears. Acknowledged and snoozed alerts are excluded from the digest but still shown on the fleet board.
- **[NOTE FOR PM]** Apple push certificate, Apple Business Manager tokens and Android Enterprise binding cannot be created by the console. They are tracked as manual prerequisites in preflight (FR-41) and watched for expiry (FR-28).

### F4. Drift monitoring and alerts

Today drift is computed only when someone presses Compare; the scheduler only takes snapshots.

- **FR-21 (Must)** After every scheduled snapshot, run the comparison and the score for each tenant and store the result.
- **FR-22 (Must)** Classify drift as *missing*, *changed*, *disabled*, *unassigned*, *extra* (a policy in the tenant that is not in the standard), or *version behind*.
- **FR-23 (Must)** Severity rules: for example a Conditional Access policy disabled or a compliance policy deleted is critical; a wording change is informational. Rules are editable.
- **FR-24 (Must)** A known exception (client, template, setting, owner, reason, optional expiry) silences matching drift and appears on the client report.
- **FR-25 (Must)** Alerts go to a Teams channel and a daily email digest. Critical drift posts to Teams immediately; everything else waits for the digest. One message per client per day, not one per policy. Microsoft retired the old Teams "incoming webhook" connectors on 2026-04-30, so the console posts to a **Teams Workflows "when a webhook request is received" trigger** (set up once per channel, with the URL kept in the secret store). Private channels are not yet supported by Workflows; use a standard or shared channel.
- **FR-26 (Must)** From an alert, one click opens the drift with three choices: restore to standard (previewed), accept as an exception, or accept as the new client override.
- **FR-27 (Should)** Use the Intune audit log to say who changed a drifted setting and when.
- **FR-28 (Should)** Tenant health alerts outside policy: Apple push certificate or token expiring, Android binding lost, Autopilot profile errors, stale devices, compliance falling.
- **FR-29 (Must)** Snapshot retention is configurable, with a default of 90 days. The store already writes a new version only when an object changed, so retention is about pruning old versions, not about daily duplicates. **[ASSUMPTION]**

### F5. Rollout engine (our version of deployment plans)

Replaces the manual pilot-to-all switch with real stages. It must work for every writable kind, not only Windows.

- **FR-30 (Must)** A *rollout plan* is a reusable template: ordered rings, each with target groups, optional filters, a wait time, and a gate. Standard plans ship: "Three ring" (internal pilot, 10%, everyone), "Careful client" (one week between rings), "Emergency" (single ring, extra confirmation).
- **FR-31 (Must)** A *rollout* applies one plan to one payload (a policy or a pack step) in one tenant. State is stored so it survives restarts.
- **FR-32 (Must)** Gates between rings: wait time, manual approval, and an automatic health check (for example the share of devices in the previous ring reporting errors or non compliance, where Microsoft exposes it). A failed gate pauses the rollout and alerts.
- **FR-33 (Must)** Pause, resume and cancel are always available. Cancel offers to revert the payload to its previous version.
- **FR-34 (Must)** Rings expand cumulatively and the last ring may be "all users" or "all devices". The console never leaves an object assigned to nobody by accident, and detects a group that would collide with an existing assignment before starting.
- **FR-35 (Must)** Conditional Access uses report-only first and a pilot group, with a minimum report-only time before enforcement (this exists today and is kept).
- **FR-36 (Should)** Suggest pilot members from device inventory (different hardware models, different departments).
- **FR-37 (Must)** A calendar and timeline view shows every active rollout across tenants, with change freeze windows per client that block scheduled ring starts.

### F6. Build-out wizard (new client environment)

- **FR-38 (Must)** The wizard asks about 10 questions (platforms, corporate or BYOD, existing EDR, existing RMM patching, regulated data, kiosk or shared devices) and produces a *build plan* from packs, adjusted by the client profile.
- **FR-39 (Must)** Packs available: Foundations (groups, filters, scope tags, naming), Enrollment (Autopilot, enrollment restrictions), Compliance, Security (Defender, ASR, firewall, LAPS, BitLocker), Updates, Identity (Conditional Access set), Apps, Mobile (iOS and Android), Mac.
- **FR-40 (Must)** Steps run in dependency order (groups and filters before policies, policies before assignments, report-only before enforced). Each step is run through the rollout engine with a ring plan chosen by pack.
- **FR-41 (Must)** Preflight before any write: licensing present, console permissions granted, existing conflicting policies listed, current score captured, manual prerequisites checked off (Apple push certificate, ABM or ASM token, Android Enterprise binding).
- **FR-42 (Must)** Postflight verification and a handover document: what was built, what is pending, the score before and after.
- **FR-43 (Must)** The whole plan is shown as a preview with counts ("creates 41 objects in 9 steps") and can be paused part way; the wizard resumes from where it stopped.
- **FR-71 (Must)** Discovery first: before any change, inventory the existing tenant (enrollment status by platform, device count, operating system spread, existing policies and their compliance state). It becomes the baseline for the handover report. *From Anthony's project checklist: "review existing Intune tenant configuration and enrollment status across 42 Windows devices".*
- **FR-72 (Must)** The Foundations pack creates the dynamic user and device groups that policies target (by platform, ownership and ring).
- **FR-73 (Must)** Check automatic MDM enrollment: report whether MDM user scope and Entra join auto-enrollment are on, and for whom, and what is still not enrolling.
- **FR-74 (Must)** Pilot validation before go-live: check that every enrolled device in the pilot ring reports compliant (observed, not predicted), list the exceptions with reasons. This is the gate for enforcing a Conditional Access policy that requires a compliant device (FR-68 supplies the threshold). *From the checklist: "establish pilot group and validate all enrolled devices report compliant before go-live", then "require a managed, compliant device for M365".*
- **FR-75 (Should)** Export the build plan as tasks to Microsoft Planner, so owners and the timeline live where the team already tracks work. The console is not a task tracker. Confirmed 2026-10-27: the team uses Planner.
- **FR-80 (Must)** Greenfield mode: confirm whether Security Defaults is on (it cannot run with Conditional Access), deploy everything report-only first, then turn Security Defaults off and the replacement policies on in the same change window so there is no gap without MFA. Enroll a pilot set of devices before any device based Conditional Access policy (the templates' C015 and C017) is enforced. *From the Policy Templates Field Guide greenfield checklist.*
- **FR-81 (Must)** Brownfield mode: inventory what exists first; policies are matched by name and an existing one is reused, never updated, so its settings are compared with the template before anyone assumes it matches; existing named locations are reused, not duplicated; existing device policies that cover the same job (antivirus, attack surface reduction, firewall) conflict, so the new ones are deployed unassigned and device groups move from the old policy to the new one group at a time; deploy only what fills a real gap. *From the Field Guide brownfield checklist, and already how Compare and Deploy behave.*
- **FR-82 (Must)** *Decided 2026-10-27.* The default compliance pack is Anthony's own B365 baseline, found in two client tenant exports: Windows B365E v4.1 (Secure Boot and code integrity), macOS v4.0, iOS v4.0 and Android v4.0. It is an **optional pack**, offered at build-out and added per client; a client without it is not flagged and it is not part of the standard. For Windows, BitLocker, TPM and a minimum OS are added as optional switches that start off, each with the who-would-fail preview (FR-62 to FR-65). Open Intune Baseline's nine Windows compliance policies stay available as a library to assess against (FR-76).
- **FR-44 (Should)** Offboarding pack: remove everything the MSP deployed from a tenant, previewed and approved.

### F7. Fleet operations

- **FR-45 (Must)** Apply a template, pack or version change to many tenants at once, with a blast radius preview ("14 policies in 6 tenants") and a two step confirmation by an approver.
- **FR-46 (Must)** Fleet board: one row per client with score, drift count by severity, version behind count, active rollouts and last change. Worst first.
- **FR-47 (Must)** Fleet writes run through rollouts, so the first tenants act as a canary and the rest wait on its gate. **[ASSUMPTION]**
- **FR-48 (Should)** Compare a client against the average of the managed fleet.

### F8. Reports and audit

- **FR-49 (Must)** Client report (HTML and PDF): score and trend, what is protected in plain language, changes this period, open exceptions, recommended next steps. CIS control IDs are cited and linked, not reproduced.
- **FR-50 (Should)** Prospect assessment: a read only scan of a prospective client that produces a "gaps" report for sales.
- **FR-51 (Must)** Every action (who, what, when, tenant, before and after) is recorded and exportable. This exists as the runs log and is extended to cover publishing, overlays, exceptions and rollouts.
- **FR-52 (Should)** Compliance mapping: for HIPAA, CMMC and NIST controls show which templates support each control and export an evidence pack.

### F9. Content (what ships in the library)

- **FR-53 (Must)** Windows 10/11: OpenIntuneBaseline Windows set reviewed against the House deviations, with BitLocker, LAPS, Edge, OneDrive, Office, Windows Update rings.
- **FR-54 (Must)** macOS: OpenIntuneBaseline macOS set plus the existing Platform SSO and Defender templates, FileVault, firewall, software update.
- **FR-55 (Must)** iOS/iPadOS: restrictions, passcode, compliance, managed apps, Wi-Fi/VPN/email profiles, and BYOD app protection, for both supervised and BYOD.
- **FR-56 (Must)** Android Enterprise: fully managed, work profile and dedicated device profiles, compliance and app protection. **[NOTE FOR PM]** No Android templates are owned today, so these are authored from scratch and tested on a real device before they ship. They are the largest content risk.
- **FR-57 (Should)** Cloud PC, kiosk and shared device packs.

### F10. Policy impact preview (who will this hit, before it is deployed)

Added 2026-10-27 after Anthony's request: settings are optional, each shows what the client's fleet looks like today (for example the oldest operating system in use), and every policy shows who would comply, who would fail, and why. A clickable prototype with sample data is in `prototypes/impact-preview.html`; **Decided 2026-10-27: layout B, the device list with reasons**, with the settings switches and the oldest device shown on the same page. (A and C were the alternatives.)

- **FR-62 (Must)** Fleet picture per setting: for every setting that can be judged from device data, show the client's current values (oldest, newest and typical for versions; counts for yes or no) and where the proposed value sits in them.
- **FR-63 (Must)** Predicted verdict per device for a policy as configured: *compliant*, *would fail* or *cannot tell*. Every "would fail" says which setting, the device's value and the required value, in plain words.
- **FR-64 (Must)** Live what-if: changing a setting (a minimum version, encryption on or off) updates the counts and the lists at once, and writes nothing to the client.
- **FR-65 (Must)** Optional settings: each setting is on, off or not configured, with the pack's recommendation shown. Off means left out of the policy. Impact is shown only for settings that are on, and the oldest device is always marked.
- **FR-66 (Must)** Honest limits: settings the console cannot judge from the data it can read are labelled "cannot tell", never guessed. After a policy reaches a pilot ring, Intune's own per device per setting results replace the prediction, and prediction and observed result are shown side by side so the preview earns trust.
- **FR-67 (Should)** Conditional Access impact: for a policy that requires a compliant or managed device, show who would be blocked, from report-only sign-in results when the client has the sign-in logs and from predicted compliance otherwise.
- **FR-68 (Must)** Gate: a deploy, a ring or an enforcement can require a minimum share of devices that would comply (for example 95 percent), or an acknowledged list of exceptions. The impact list is saved with the run for the audit trail.
- **FR-69 (Should)** A client-facing "who will be affected" export (device, user, reason), leaving out devices not seen for 30 days by default but counting them.
- **FR-70 (Must)** Staleness: every device shows its last check-in; devices not seen for more than 30 days are counted separately and not judged, so a retired laptop does not fail a policy.

### F11. Baseline assessment

- **FR-76 (Must)** Assess any client, or a prospect, against an established baseline chosen at assessment time: the House standard, Open Intune Baseline (Windows, macOS, Windows 365, BYOD), Microsoft's security baselines, CIS or CISA SCuBA. Read only: nothing is deployed.
- **FR-77 (Must)** The result gives an overall percentage, a percentage per category and, for each gap, what the baseline says, what the client has, and why it differs. Items that do not apply to this client (a third party EDR is present, an RMM does the patching) are shown as not applicable with the reason, taken from the client profile, and not counted against them.
- **FR-78 (Should)** Compare two baselines for one client ("what would moving from the House standard to Open Intune Baseline change"), and keep each baseline's score history.
- **FR-79 (Must)** An assessment is saved as a dated report; reassessing shows what changed since last time.

## 7. Non functional requirements

- **NFR-1 Safety.** Today only Deploy previews; modify, revert, enforce and widen do not, widening an Intune policy writes no version, and a failed before-snapshot does not stop the write. **Required:** every write path gets a preview, a before and after snapshot that must succeed before the write proceeds, and a role check. Assignments are versioned like any other change. A read only mode refuses all writes at the server. The existing guards (no overwrite, no unfilled placeholders, no rule that blocks everyone, report-only default) stay.
- **NFR-2 Scale.** 25 to 100 tenants. Scheduled work is staggered and honours Microsoft's throttling per tenant, retrying with backoff. A full daily snapshot and compare of 100 tenants finishes within 4 hours. **[ASSUMPTION]**
- **NFR-3 Storage.** Single file database stays acceptable at this scale only if retention (FR-29) is on; **[NOTE FOR PM]** a move to a server database is deferred, with a trigger of "over 100 tenants or snapshot compare exceeds the window."
- **NFR-4 Resilience to Microsoft beta changes.** Ignore server set fields but always compare protected paths (FR-20), pin beta endpoints behind one adapter, and a failing adapter degrades one feature, not the console.
- **NFR-5 Secrets.** Client secrets and certificates live in 1Password or the host's secret store, never in the database or in chat.
- **NFR-6 Backup.** Database backup and the restore drill exist and run on a schedule; a restore is tested monthly.
- **NFR-7 Access.** Sign in with Entra, three roles (viewer, deployer, approver). The existing refusal to start with writes enabled and no sign in stays.
- **NFR-8 Tests.** Each new object kind and each alert rule ships with tests; the Graph adapter, which has none today, gets contract tests with recorded responses.
- **NFR-9 Readability.** Anthony does not read code: every screen and every report is in plain language.
- **NFR-11 Throttling and concurrency.** Back off and retry when Microsoft slows requests (429 and 503). One lock per client: a deploy or rollout wins, and the scheduled check skips that client while it runs. A manual check waits or is refused with a clear message.
- **NFR-12 Secrets in policies.** Values that are secrets (Wi-Fi keys, VPN shared secrets, certificates) are replaced by a fixed marker plus a hash before a version is stored or a report is produced, so history never holds a readable secret yet a changed secret still shows as a change.
- **NFR-13 Device data.** Impact previews hold device names, users and versions. Keep them in the console database under the retention setting, show them only to signed-in staff, and put counts, not names, in Teams alerts and digest emails.
- **NFR-10 Distribution.** Still one program that runs on a Mac, Windows, Linux or as a container.

## 8. Risks

| Risk | Why it matters | Mitigation |
|---|---|---|
| Alert fatigue | Drift alerts get ignored within weeks | Exceptions with expiry, severity tiers, one message per client per day, noise metric in section 4 |
| Fleet write blast radius | One bad template reaches many clients | Canary first, approver gate, two step confirm, change freeze windows |
| Android content from scratch | No tested starting point | Author in a test tenant, real device test before shipping |
| Graph beta drift | Microsoft changes fields | Compare owned fields only, one adapter, contract tests |
| Apple and Android prerequisites | Cannot be automated | Tracked as manual prerequisites in preflight |
| Scope | 57 requirements is a lot | Items marked Should can slip; see open items on phasing |
| Wider object coverage is the biggest engineering cost | Today four kinds are writable; FR-16 and FR-17 add about nine more, each needing its own read, write, preview, snapshot, compare rules, revert and tests. This one group is likely more work than drift, rollouts and fleet combined | Slice it in phasing: compliance and app protection first, then enrollment and Autopilot, then groups, filters and apps |
| Re-consent across every client | The new object kinds need Microsoft permissions the console's app registration does not hold today. Adding a permission to a multi-tenant app means each client's admin must consent again, across 25 to 100 tenants | Batch all new permissions into as few consent rounds as possible, decide the full list before the first round, use the console's own consent link flow, and track consent status per tenant on the fleet board |

## 9. Delivery order (decided 2026-10-27)

1. Drift alerts and exceptions (FR-21 to FR-29), with the Teams Workflows setup and the daily email digest. This step also has to store each client's placeholder values on the server (the first slice of FR-11), because today they live in one browser and are not kept per client.
2. Content import for Windows, Mac, iOS and Android (FR-8, FR-53 to FR-56) plus the object kinds those need (FR-16 compliance and app protection first).
3. Library editor, publish flow and per-client overlays (F1, F2).
4. Rollout engine (F5).
5. Build-out wizard (F6), with the remaining object kinds (enrollment, Autopilot, groups, filters, apps).
6. Fleet operations and reports (F7, F8).

Permission additions for all steps are decided up front and requested in as few client consent rounds as possible (see Risks).

## 10. Decisions and remaining items

**Added 2026-10-27 from the project checklist screenshot:** FR-62 to FR-79 (impact preview, baseline assessment, discovery, pilot validation). Open: (a) which prototype layout, (b) DECIDED: the compliance policies were not in the Policy Templates folder or its 2026-09-15 zip (they are identical); they were found in two client tenant exports and are now the default optional pack (FR-82). The greenfield and brownfield checklists are folded into FR-80 and FR-81. (c) DECIDED: the team uses Planner.


**Decided:** extend the existing console; own rollout engine instead of Intune deployment plans; 25 to 100 tenants; alerts to Teams (Workflows) and email digest; Windows, macOS, iOS/iPadOS, Android in the first release; internal only; Anthony is the sole approver; a canary tenant exists; template master copy lives in the console database with exports; delivery order above.

**Still open (none block architecture):**

1. PSA tickets from critical drift: not requested, deferred. Which PSA, if any, later?
2. Targets in section 4 and NFR-2 marked **[ASSUMPTION]** (2 hour onboarding, 3 alerts per tenant per week, 4 hour fleet snapshot window, 90 day retention) are working numbers until measured on real clients.
3. Client licensing (Intune Plan 1 versus Business Premium) limits some compliance and Defender features; verify per client during preflight (FR-41).
4. Formal reviewer pass and input reconciliation have not been run; do them before treating this as final.

## 11. Review resolutions (2026-10-27)

Full independent review: `review-adversarial.md`. Verdict: revise before architecture.

**Applied above:** delivery order step 1 now includes per-client stored values; NFR-1 states the real current guards and the required ones; FR-20 rewritten with a protected-paths list; FR-29 retention corrected.

**Decisions needed before architecture (not yet made):**

1. **DECIDED 2026-10-27 (Anthony: ok): no deletes in the first release; extra objects are reported only; offboarding deferred.** Deleting and recreating objects. The engine has no delete path and revert cannot undo a create. FR-22 (extra), FR-26, FR-33 and FR-44 imply deletes. Decide whether the console ever deletes in a client tenant. Recommendation: no deletes in the first release; "extra" objects are reported only, and offboarding (FR-44) is deferred.
2. **DECIDED 2026-10-27 (Anthony: ok): every deployed object carries a stable template id.** Stable template identity. Matching is by display name, so a per client naming prefix (FR-11) would make every deployed policy look missing plus extra. Needs a stable id stored with each deployed object (for example a tag in the description) before overlays.
3. **DECIDED 2026-10-27 (Anthony): Global Admin and GDAP exist in every client tenant, so the console grants consent itself; see FR-58 to FR-60.** Consent and permissions. A permission list per object kind and a per tenant consent state; today one 403 fails the whole comparison, and a snapshot marks a tenant connected even when every read failed.
4. **DECIDED 2026-10-27 (Anthony: ok): four states, new, acknowledged or snoozed, resolved, and auto resolved when drift clears; see FR-61.** Alert lifecycle. Define new, acknowledged, snoozed, resolved, and auto resolved so the noise metric in section 4 can be measured.
5. **DECIDED 2026-10-27 (Anthony: ok): back off and retry on throttling; one lock per client; a deploy wins over a check and the check skips that client while a deploy runs; see NFR-11.** Throttling and concurrency. No 429 handling and no per tenant lock exist; a scheduled check and a manual deploy can overlap.
6. **DECIDED 2026-10-27 (Anthony: do it): one time import of the OneDrive set into the console, which then owns the library; OneDrive becomes a read only archive; the Praxis script exports into the console. Happens with the library storage in step 3. Verified today that the embedded templates are identical to the OneDrive set.** Source of truth migration. The OneDrive folder and the Praxis build script are both sources of truth today; say how each is retired or kept.
7. **DECIDED 2026-10-27 (Anthony: ok): secret values are redacted before a version is stored or a report is printed; a change to a secret still registers as a change; see NFR-12.** Secrets inside policy bodies (Wi-Fi keys, VPN secrets) must be redacted in stored versions and reports.

Other findings (vague metrics, FR-30 "10 percent" ring membership, FR-32 gate signal and minimum sample size, FR-47 Must versus assumption) are listed in the review file and should be resolved when those sections are built.

## 12. Build status (2026-10-27, end of the "build everything" run)

Everything below is local, committed, and tested against fakes. Nothing has been pushed, and nothing has been written to a client tenant except the five read permissions granted in the home tenant. "Built" means the engine and API exist and pass tests; screens are noted separately.

| Group | Status |
|---|---|
| F1 Policy library | Built: drafts, publish by an approver with a reason, full version history with diff, revert as a new version, built in templates editable by reuse of their id, imported libraries, safety checks at publish (lockout guard, no literal secrets). Not built: form generated from Microsoft setting definitions (FR-3), weekly upstream watch (FR-9), exports to Bicep and Terraform from the database (FR-10), the "adopt a live policy" import (FR-4 part), plain English template descriptions (FR-2). |
| F2 Per client tailoring | Built: client profile, exclude and modify overlays with reason, owner and expiry, name prefix, the Included, Modified, Excluded table, stable template id in each policy's description. Not built: pin a client to a version (FR-14), override review items on expiry (FR-15). |
| F3 Object coverage | Built: compliance, iOS and Android app protection (read, write, compare, drift); read only: legacy profiles and update rings, enrollment settings, Autopilot profiles, assignment filters. Not built: groups and filters creation, apps and app assignments. |
| F4 Drift and alerts | Built: scheduled check after each snapshot, severity, exceptions with expiry, Teams (Workflows) and email digest, acknowledge, snooze, reopen. Not built: who changed it from the audit log (FR-27), tenant health alerts (FR-28), editable severity rules (FR-23). |
| F5 Rollout engine | Built: plans, rings with waits, manual approval and a compliance gate that uses real results once devices report, pause, resume, cancel with revert, one rollout per policy, assignments for Intune kinds and Conditional Access, scheduler with Teams alerts. Not built: pilot member suggestions (FR-36), calendar view and freeze windows (FR-37). |
| F6 Build out wizard | Built: questionnaire to ordered plan (greenfield and brownfield), step by step preview, confirm and run, manual and gate steps, discovery before picture, Planner export payload. Not built: creating groups, Autopilot, enrollment settings; automated preflight and postflight; posting to Planner. |
| F7 Fleet | Built: fleet board, canary first apply with a stop on canary failure. Not built: fleet comparison (FR-48). |
| F8 Reports | Built: saved client report with change since last time. Not built: PDF, prospect assessment as its own flow, compliance mapping (FR-52). |
| F10 Impact preview | Built: engine, API, observed results beside the prediction, demo data, and the screen. Not built: Conditional Access impact (FR-67), the client export (FR-69), Defender, TPM and passcode style settings. |
| F11 Baseline assessment | Built: choose any imported library or pack as the baseline. Not built: setting level comparison for Open Intune Baseline (policies are matched by name today), CIS, SCuBA and Microsoft baselines in the same chooser. |
| Non functional | Built: throttling retry, per client change gate (a change wins over a check), secret redaction in history with a refusal to write a redacted copy back, history retention with floors. Not built: scheduled backups and restore drill (NFR-6), secret store integration beyond the existing launcher. |

Decisions still needed from Anthony before the next phase: see section 10, plus whether the console should post to Planner itself, and whether approval should become a named role in the sign in system instead of the PC_APPROVERS list.
