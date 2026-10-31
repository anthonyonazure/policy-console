# Implementation notes: step 1, drift alerts (branch feat/drift-alerts)

Built 2026-10-27 in one session. Nothing pushed. Nothing sent to Teams or email.

## What was built
- Scheduled drift check after every snapshot cycle (internal/alerts), classifying findings as missing, changed, disabled or extra (internal/drift).
- Findings with first seen, last seen, resolved and told-at times (internal/store/drift.go).
- Approved exceptions with owner, reason and optional expiry date. A lapsed exception lets the finding back in.
- Per client placeholder values stored on the server, used by the scheduled comparison.
- Teams alerts via a Workflows trigger URL, one message per client carrying all untold critical findings; daily email digest over SMTP, at most once per 24 hours, only when something is open (internal/notify).
- API: GET /api/tenants/{id}/drift, POST /api/tenants/{id}/drift/check, GET and PUT /api/tenants/{id}/tokens, POST /api/tenants/{id}/exceptions, DELETE /api/exceptions/{id}. All writes need the deployer role.
- Settings (all optional, a channel with no setting is off): PC_ALERT_TEAMS_URL, PC_ALERT_SMTP_ADDR, PC_ALERT_SMTP_USER, PC_ALERT_SMTP_PASSWORD, PC_ALERT_MAIL_FROM, PC_ALERT_MAIL_TO, PC_ALERT_DRY_RUN.

## Deviations from the PRD (conservative choice taken)
- Severity rules are fixed in code, not editable (FR-23). Editing them can silence critical drift fleet wide and needs the approver role and an audit entry; deferred until the role exists.
- "Version behind" and "unassigned" drift classes (FR-22) are not produced yet; they need overlays and assignment reads.
- No UI. The new data is reachable through the API only. Screens for findings, exceptions and client values come next.
- A comparison that fails for any reason changes nothing (findings are neither opened nor resolved). One 403 on one object kind therefore stops drift checking for that tenant, which is the safe failure but needs the per kind consent work in the PRD review.
- Templates whose client values are not filled in are counted as "unchecked", not drift, and are logged each cycle but not yet shown anywhere a person will see them.
- The Teams message and the email were verified against fake endpoints only. Neither a real Teams Workflows URL nor a real mail server was used.
- Not exercised against a live Graph tenant: no tenant database existed locally and no consent state was known.

## Known gaps to decide
- No per tenant lock; a manual check and the scheduled check can run at once (findings writes are transactional, so the result is safe, but a critical message could be sent twice in a tight race).
- Digest is sent at the first cycle after 24 hours, so its time of day drifts.
- Findings of a deleted tenant are left behind, like version history.

# Implementation notes: consent automation (branch feat/tenant-consent, off feat/drift-alerts)

## What was built
- internal/consent: a manifest of Graph application permissions by name for a read registration and a write registration (write includes read), grouped by the part of the console that needs them. Permission ids are looked up in the client's own Microsoft Graph service principal at grant time; none are hard coded.
- Preview then confirm: the preview reads the client and lists what is missing. The confirmation carries the preview's fingerprint; if the client changed in between, nothing is granted. Granting adds the console's application to the client tenant if absent, assigns each missing permission, then reads the client back and fails loudly if anything is still missing.
- Preflight on the signed-in session: the token must be for this client, and must carry Privileged Role Administrator or Global Administrator (Microsoft's rule for Graph application permissions; Application and Cloud Application Administrator are not enough).
- Per client, per permission consent state stored from every read-back, shown per kind of work (granted, partial, none).
- Read and write credentials split: PC_READ_CLIENT_ID and PC_READ_CLIENT_SECRET. Snapshots, comparisons, drift checks, probes and assessments use the read registration when configured; deploy, revert, enforce, widen and rollouts keep the write one. The drift alerts therefore run with credentials that cannot change a tenant.
- API: GET /api/tenants/{id}/consent, POST .../consent/plan, POST .../consent/apply. Apply is refused in read only mode, needs confirm plus the preview hash, and is recorded as a run.

## Deviations from the PRD and from the review advice (conservative choice taken)
- The delegated sign-in comes from the operator's own `az login` session (az account get-access-token for the client tenant), not from a new browser sign-in flow in the console. Reason: the README deliberately keeps the console's staff sign-in registration single tenant, so it cannot sign into client tenants, and a third multi tenant registration would leave an enterprise application behind in every client. The cost: the console must run where `az` is signed in (the Mac), not as a container. A browser flow can replace the token source later without changing anything else.
- The token's role claim is decoded without verifying its signature. It is a courtesy check that fails early with plain words; Microsoft Graph still enforces the real permissions.
- Existing consent links are untouched and remain the fallback for a client without GDAP.
- Nothing in this package references the Partner Center API; a test enforces it.
- Not yet done: the probe and snapshot still mark a tenant connected even if reads fail (PRD FR-60); no screens; permissions for later steps (apps, enrollment, devices, groups, audit) are in the manifest now so the clients are asked once.

## Verified live (2026-10-27, read only preview, the home tenant)
- The operator's `az login` token was accepted, passed the tenant and role preflight, and the preview read the tenant's real state in about 2 seconds: the read application is present with 4 of 9 permissions granted (Organization, Policy, DeviceManagementConfiguration, SecurityEvents) and 5 missing (apps, enrollment, devices, groups, audit). That matches what the README says the registration was given. No grant was made; the console ran in read only mode on a throwaway database.

## Not verified
- Granting itself (the write path) has only run against fakes. The home tenant is the operator's own, so this did not exercise a GDAP delegated sign-in into a client tenant. That still needs one supervised run on a client or canary tenant reached through GDAP.

# Implementation notes: Open Intune Baseline library (branch feat/oib-library, off feat/tenant-consent)

## What was built
- `policyconsole import-oib <checkout> <library folder>`: reads OIB settings catalog policies for macOS (17), Windows 365 (2) and Windows (61, from the tarball), handling UTF-8 with and without a byte order mark and UTF-16. Converts to clean UTF-8 JSON, strips tenant assigned fields and, at every depth, OData links (they embed the exporting tenant's policy id), action metadata and exported assignments. Writes `OIB-NOTICE.txt` (GPL-3.0, source, version) and a summary beside the library.
- `PC_EXTRA_TEMPLATES`: loads a library folder next to the embedded set. A library template that would collide with a core template id is refused.
- Library categories (`oib-*`) are browsable and deployable but never expected: excluded from Compare (so not "missing"), the score, and the overlap and baseline audits of the House set.
- Ran against the real checkout: 80 templates imported, 137 loaded in a live console, zero OData links left.

## Decisions made on the way (conservative)
- GPL-3.0: the library is imported to a local folder and never committed to the repository or embedded in the binary. Using it internally raises no obligation; distributing a binary that contains it would. If the console is ever sold or licensed, this is the line that matters.
- Only settings catalog policies were imported, because those are the only policy kind the console can read, compare and deploy besides Conditional Access.
- OIB stores its stable policy id in each description (`OIBID:<guid>`). That is a ready made stable template identity for the overlay work (PRD decision 2); nothing uses it yet.

## What this does not deliver (be clear with the owner)
- No iPhone or Android policies. OIB has none for devices: its BYOD folder holds two app protection policies, and the console cannot manage that kind of object yet. Android device profiles do not exist anywhere in the sources and must be authored.
- Not importable until the console learns these kinds (PRD FR-16): 16 Windows, Mac and Windows 365 compliance policies, 3 update rings, 3 driver update profiles, 1 device configuration profile, 2 app protection policies.
- Deploying any library template to a real tenant has not been tried. The bodies are Graph export shaped and the console already strips read only fields before writing, but a first supervised deploy to the canary tenant should be a preview first.
- One warning remains by design: a Windows Hello PIN credential provider id (Microsoft built in) in the Passwordless policy, for a person to confirm.

# Implementation notes: compliance and app protection (branch feat/more-kinds, off feat/oib-library)

## What was built
- Three new kinds the console reads, snapshots, versions, compares and drift-checks: compliance policies (all platforms, one kind), iOS app protection and Android app protection.
- Reads ask for the nested parts a plain read hides (actions on non-compliance, covered apps), so a policy does not look emptier than it is.
- Compare puts order-insensitive parts in a fixed order (the app list, the actions) so a different order from the service is not drift. Assignments are ignored by the comparison: where a policy applies is a per-client decision.
- Deploy creates compliance policies with their actions in one call, and app protection policies in two (create, then attach apps by identifier), because the service does not accept apps on create. Existing names are left alone.
- **Never assigned by a deploy.** These kinds are created unassigned and the result says so, even when a rollout of "all" was asked for. A compliance policy assigned to everyone can lock people out of anything that requires a compliant device, so assignment waits for the rollout engine and a deliberate decision.
- Modify and revert work for the settings of these kinds, but cannot restore the actions on non-compliance or the app list (the service has separate calls for them). The result says exactly that instead of claiming a full restore.
- Per kind permission handling (PRD FR-60, first part): if the application is forbidden from reading one kind in a tenant, that kind is reported as unreadable, its templates show as "error" (never "missing"), the rest of the comparison continues, deploy refuses to create that kind (it cannot tell whether it already exists), and snapshot records the error without marking anything deleted.
- Importer: the OIB library now includes compliance policies (Windows, macOS, Windows 365) and the two BYOD app protection policies, in `oib-windows`, `oib-macos`, `oib-windows365` and `oib-byod`. Only update rings, driver update profiles and legacy device configuration remain unimported.
- A Graph test seam (a client that talks to a local server) now exists, with 9 new engine tests against a fake Graph: matches, drift, missing, app order, forbidden kinds, clean create bodies, two step app protection, existing names, read only mode, partial revert wording, snapshot degradation. The engine had no deploy or compare tests before.

## Verified live (read only, 2026-10-27, the home tenant)
- Snapshot read 13 objects and recorded the two app protection kinds as unreadable (the read application does not hold DeviceManagementApps.Read.All, which is one of the five permissions the consent preview listed as missing). Compare reported those kinds as unreadable and kept going.
- The compliance read with its nested expansion was accepted by the real service, but the home tenant has no compliance policies, so the shape of a populated compliance read has not been seen against the real service.

## Not verified
- No compliance or app protection policy has been created, changed or reverted in a real tenant. The create bodies and the two step app protection flow are checked against a fake that mirrors the documented shapes, not against Microsoft. First live use should be a preview, then one supervised create on the canary tenant.
- App protection reads have not succeeded against a real tenant yet (permission missing).

## Open question for the owner
- Diff now ignores `assignments`. If assignment drift should be reported (a policy that is no longer assigned to anyone), it needs its own check, planned with the "unassigned" drift class.

## Review fixes made before this branch was reported (all with regression tests)
- A 401 is no longer treated as "no permission". Only 403 is. A 401 means the credential is bad (an expired secret, a revoked app), and treating it as an unreadable kind would have made every template "unchecked" and every open finding "resolved", so an expired secret would have read as "all drift fixed across the fleet". It now fails the comparison. If every kind is forbidden, the comparison fails too.
- Findings for a kind the application cannot read are kept open, not resolved. Not looking is not the same as fixed. This includes "extra" objects of that kind.
- Snapshot only skips deletion marking for kinds that failed to read, not for the whole tenant. Before, one forbidden kind switched deletion detection off for everything.
- A missing compliance policy is now Critical, matching PRD FR-23 (devices stop being judged at all). Missing app protection stays a warning.

# Implementation notes: choose a baseline to assess against (branch feat/more-kinds)

## What was built
- `CompareAgainst(tenant, baseline)`: assess a client against the House standard (default) or any imported library, read only. Against a chosen baseline, objects in the tenant that the baseline does not mention are not listed (they would just be everything else).
- `GET /api/assessment/baselines` lists what can be chosen (the standard, then each imported library with its template count). `POST /api/tenants/{id}/compare` takes an optional `baseline`; an unknown one is refused with a clear message.
- Ran it live, read only, on the home tenant: OIB Windows 61 of 61 not found, OIB macOS 17 of 17 not found, as expected for a tenant that has none of them.

## Known limit (matters for the assessment feature, PRD FR-76 to FR-77)
- This matches policies by name, so a client that has equivalent settings under a different policy name reads as "missing". Microsoft's own baselines are already compared by setting id, which is the right method. The assessment should reuse that setting level comparison for OIB (PRD FR-77: what the baseline says, what the client has, why it differs) before it is shown to a client. Not done yet.
- Not covered by this step: CIS, SCuBA and Microsoft baselines are not in the chooser (they have their own score views today), the saved dated report (FR-79), and the not-applicable handling from the client profile.

# Prototype: policy impact preview (docs/prd/prototypes/impact-preview.html)
- Sample data only (42 invented devices); no real client data. Three layouts share one model: A settings with live counts, B device list with reasons, C version spread with a slider. Checked in a real browser: toggling settings and dragging the slider updates the counts and the lists, and the reaction box copies a summary.
- Waits for Anthony to pick a layout before any real engineering. The real version needs the device inventory permission (DeviceManagementManagedDevices.Read.All, one of the five not yet granted in the home tenant) and Windows protection state for the Defender style settings.

# Compliance baseline found in client exports (2026-10-27)
- The zip `Policy Templates 2026-09-15.zip.txt` is a genuine zip (renamed .txt). Extracted to a scratch folder and compared: byte identical to the current Policy Templates folder (apart from a Python cache folder). It holds no compliance policies.
- Anthony's own compliance baseline (B365 v4.0 and v4.1, "MS Elite" variants) exists for all four platforms in two client tenant exports, not in the shared template folder. Cleaned copies (no tenant ids, checked: 0 GUIDs) are staged in `docs/prd/staged-compliance/` for review. They are not loaded by the console yet.
- Windows: two v4.1 variants differ by one setting (B365E requires code integrity; the MS Elite copy does not). Both require Secure Boot. Neither requires BitLocker, TPM or a minimum OS: those are the optional switches the impact preview is for. macOS requires a password, System Integrity Protection and disk encryption. iOS requires an alphanumeric passcode and blocks jailbroken devices. Android requires a password, encryption, blocks rooted devices and sets a threat level.
- The exports did not capture the actions on non-compliance, and Microsoft requires one on create. Deploy now adds the standard "mark non-compliant immediately" action to any compliance template that lacks one (test added).
- This also closes the Android gap: there is now an Android compliance policy in the owned set (Android app protection and device restrictions still do not exist).

# Live: five read permissions granted in the home tenant (2026-10-27, approved by Anthony)
- Granted through the console's consent path, preview then confirm, using the operator's own admin sign-in and no app credentials. The plan was checked to be exactly five permissions before applying: DeviceManagementApps.Read.All, DeviceManagementServiceConfig.Read.All, DeviceManagementManagedDevices.Read.All, Group.Read.All, AuditLog.Read.All. All five granted; the read-back showed none missing. This is the first live run of the grant path (it had only run against fakes before).
- Verified by real reads with the read-only application's own token: it now carries all nine permissions, and managed devices, groups, audit log, Autopilot profiles, iOS app protection and Android app protection each answered HTTP 200.
- Re-ran the live snapshot and compare: no unreadable kinds and no errors (the two app protection kinds were unreadable before the grant).
- The home tenant has no app protection policies and no enrolled devices, so the app protection read and the impact preview's device data have still not been seen with real content. A client or canary tenant with devices is needed for that.
- The grant was a change to the tenant (five app role assignments on the read-only application's service principal). To undo it, remove those five assignments in Entra under Enterprise applications.

# Implementation notes: policy impact preview, backend (branch feat/impact-preview, off feat/more-kinds)

## What was built (PRD FR-62 to FR-66, FR-70; layout B)
- `POST /api/tenants/{id}/impact` with a compliance template and optional what-if overrides. It reads the client's enrolled devices (read only, nothing stored) and returns, for the policy's platform: counts (compliant, would fail, cannot tell, not seen in 30 days), the oldest active device, every device with its verdict and the reason in words (setting, the device's value, the required value), and for every judgeable setting whether it is on, how many devices fail it, the fleet picture (oldest, newest, median version; yes, no, unknown counts), and a "what would happen if it were on" count for settings that are off. Viewers may use it (it only reads).
- What it can judge today from the device list: minimum operating system (all four platforms, compared numerically so 10.0.9 is older than 10.0.10), disk or storage encryption, jailbroken or rooted, and Windows Secure Boot and code integrity when Microsoft's health attestation reports them.
- Everything else that is on in a policy (passcode rules, TPM, password length, antivirus and similar) is listed as "not predictable" rather than guessed. A device that has not reported a value is "cannot tell", never "fail" or "pass". A failing setting outranks a "cannot tell".
- Devices not seen for 30 days are counted separately and not judged. A Windows policy judges only Windows devices, and so on.
- Verified live: Microsoft accepted the device query on the home tenant. That tenant has no enrolled devices, so the real shape of a populated device list, and whether health attestation is present for real Windows devices, have not been seen.

## Not built yet
- The screen. This is the data layer layout B needs; the browser page comes next.
- Live policies in the tenant (only catalog templates so far), the deploy and ring gate that uses a minimum compliant share (FR-68), prediction versus observed results (FR-66, needs a pilot), Conditional Access impact (FR-67), the client export (FR-69), and impact for app protection policies.
- Passcode, TPM and Defender style settings need per device calls (hardware information, Windows protection state). They are the next accuracy gain and cost one Graph call per device, so they need paging and throttling care at 100 tenants.

## Notes
- Device names and user names flow through this endpoint to signed in staff only and are not stored (NFR-13). Teams alerts must carry counts, not names.
- Windows lists both BitLocker and "storage encryption" because both properties exist in Microsoft's policy type; they judge the same device field, so they show the same number.


# Implementation notes: the "build everything" run (branch feat/engine-core and its siblings)

Built in one session, all local and committed, tested against fakes. See PRD section 12 for the full map of built versus not built.

## What exists now beyond the earlier notes
- Engine core: per client gate (a change always wins and checks step aside), throttling retry honouring Retry-After, secret redaction before history is stored, and a refusal to write a redacted copy back.
- Alert lifecycle, staged rollouts, tailoring (profiles, overlays, prefixes, stable ids), the build out wizard, fleet board and canary first apply, saved reports, Planner export, observed compliance results, discovery, read only kinds, retention, and the template library editor.
- Settings added: PC_APPROVERS, PC_RETENTION_DAYS, PC_DEMO_DEVICES, PC_READ_CLIENT_ID and PC_READ_CLIENT_SECRET (earlier), PC_ALERT_* (earlier), PC_EXTRA_TEMPLATES (earlier).

## Choices made without asking (conservative)
- Everything a deploy or fleet apply creates is unassigned, and Conditional Access starts report only. Assignment only ever happens through a rollout ring.
- Approval is a list of sign in names (PC_APPROVERS). If it is empty every deployer is an approver. A real role would be better.
- The fleet apply is synchronous: with many clients one request can take a while. A background job with progress would be better beyond about 20 clients.
- A custom template cannot join the standard by accident: published templates keep the category they were created with, and only the standard categories feed "missing" and the score.
- Retention below 30 days is refused and the newest version of every object and any version a run points at are always kept.
- The compliance gate uses real device results when the policy exists and devices have reported, and falls back to the prediction before that.

## Known weak spots
- Nothing here has run against a real client tenant except reading. The write paths (assign, create, targetApps, rollout activation) are checked against a fake that follows Microsoft's documented shapes, so the first live run should be a preview, then one supervised create on the canary tenant.
- Rollout ring times are computed from when the previous ring actually started, which is right, but there is no maintenance window or freeze calendar yet.
- The library editor stores whatever JSON passes the safety checks; it does not yet validate settings against Microsoft's setting definitions.
- The throttling retry waits inside the request, so a heavily throttled run is slow rather than failed.

# End of run: what is verified and what is not (2026-10-27)

- All branches merge into one stack: feat/engine-core holds everything, including the browser screens from feat/ui-screens. Nothing is pushed; master has not moved.
- Verified live against the real the home tenant tenant, read only: consent preview and grant (five read permissions), snapshot and compare including the new kinds, device query (empty tenant), baseline assessment.
- NOT verified live: Conditional Access impact from sign-in logs (the 1Password lookup failed at the moment of the test, so the call never reached Microsoft; the logic is tested on constructed sign-ins), and every write path (assign, create, rollout activation, fleet apply, compliance create, targetApps).
- Browser screens were checked in a real browser in read only demo mode: FLEET, DRIFT (acknowledge, snooze, reopen), IMPACT, CONSENT, ASSESS, BUILD OUT, CLIENT PROFILE, ROLLOUTS, REPORTS and fleet apply. The buttons that write to Microsoft were seen locked, never run.
- API gaps the screen builder found: the report list returns raw counts text (the screen works out percent and change itself), tailoring rows carry no overlay id, and rollout kinds and policy ids are typed by hand because there is no picker of a client's live policies.

## Planner posting and updating (2026-10-27)

Decision from Anthony: the console posts build outs to Microsoft Planner itself and keeps them updated. The approver list stays as `PC_APPROVERS` (no real role).

- `internal/planner`: one bucket per pack, one task per step. Creates and edits only, never deletes. A task a person ticked off in Planner is never reopened; a task a person deleted is not brought back; both are reported. Changes are skipped when nothing differs (content hash), so an unchanged sync makes no writes. A task created but not yet filled in is remembered, so a failure cannot cause a duplicate.
- Two modes: `PC_PLANNER_PLAN_ID` (one shared plan; titles and buckets are prefixed with the client name) or `PC_PLANNER_GROUP_ID` (one plan per build out, created in that Microsoft 365 group). Planner lives in our own tenant (`PC_TENANT_ID`) and uses the write app (`PC_CLIENT_ID`), which needs the `Tasks.ReadWrite.All` application permission there.
- The first post is always an explicit button press. After that, completing, skipping or running a step updates Planner in the background (failures are logged and retried on the next change or manual sync).
- Verified: unit tests against a fake Planner and API tests (full suite green). Not verified: nothing has been sent to the real Planner, and `Tasks.ReadWrite.All` has not been granted yet.
- Deviation: the old download export no longer includes a dependsOn field; dependencies are written into the task notes instead (Planner has no dependency field).

### Planner: verified live (2026-10-28)
- Created app `policy-console-planner` (app ID kept in the operator's local settings) in the home tenant, single tenant, holding only `Tasks.ReadWrite.All` (granted and read back). It is separate from the client-facing apps and has no client access.
- Its secret (expires 2027-01-26) is in the Mac Keychain as `policy-console-planner-secret` because 1Password CLI timed out five times. **Move it to 1Password when that works**, then delete the Keychain entry.
- Live run: preview said 10 tasks, sync created a plan in the IT Support group with 8 buckets and 10 tasks; completing a step ticked its task to 100% within seconds. The test plan ("Intune build out: TEST ... (Planner check)") is still in IT Support.
- Settings: PC_PLANNER_CLIENT_ID, PC_PLANNER_CLIENT_SECRET, PC_PLANNER_GROUP_ID (the IT Support group ID).
