# Policy Console

A control panel for the House policy baseline: the Conditional Access, Defender and Intune
templates that live in `Clients/Policy Templates`. It connects to a client tenant, shows what is
there against what should be there, deploys what is missing, keeps a dated history of every policy,
and puts it back the way it was when something goes wrong.

One file. No install, no runtime to keep patched. The same file runs on a Mac, a Windows machine,
a Linux server, or in Azure as a container.

## What it does

| Tab | What it is for |
|---|---|
| **Tenants** | Add a client, send the consent link, confirm the connection is live, take a snapshot. |
| **Baseline** | The 40 templates shipped inside the binary and the values each one needs. |
| **Compare** | Read a tenant and show, template by template: deployed and matching, deployed but drifted, or missing. Produces the score. |
| **Deploy** | Pick templates, fill in this client's group ids, preview, then confirm. |
| **History** | Every captured version of every policy, what changed between any two, and a revert button. |
| **Runs** | What the console did, when, and who did it. |

## The safety rules built into it

- **Nothing is written without a preview first.** Deploy always shows exactly what would be created
  before the confirm button appears, and the confirmation lists the policies by name.
- **An existing policy is never overwritten by a deploy.** If a policy with that name is already in
  the tenant, the console reports it and moves on. Replacing a live policy is a separate, deliberate action.
- **Conditional Access defaults to report-only.** Choosing "on, enforced" shows an extra warning,
  because an enforced policy with a wrong exclusion group can lock the administrators out.
- **Every change is snapshotted before and after.** A revert is therefore always available, and the
  revert itself can be reverted.
- **A template with an unfilled value is refused.** Microsoft Graph would otherwise accept the
  literal placeholder text as a real group id, and the policy would quietly apply to nobody.
- **`PC_READ_ONLY=true` refuses every write at the server.** Preview and reporting still work.

## Scoring

Three numbers about your own baseline, combined into one.

- **Deployed**: how much of the baseline exists in the tenant.
- **Enforced**: how much of it is actually switched on. A report-only policy protects nobody, so it
  counts as deployed but not enforced.
- **Fidelity**: how closely the deployed policies still match the baseline. It falls as settings
  drift, and reads zero when nothing is deployed.

## Control frameworks, and why some are fetched and some are not

Control numbering moves between versions of a benchmark, and a wrong control id in a client report
is worse than no control id. So the console never trusts a hand-typed list.

**Microsoft Secure Score** is read live from each tenant on every score. Microsoft scores its own
controls, so there is no mapping on our side and therefore nothing to mistype. It also carries the
comparison against similar tenants, which is the number clients ask about. Needs
`SecurityEvents.Read.All`.

**CISA SCuBA M365 Secure Configuration Baselines** are fetched from CISA's own repository, pinned to
a release tag, parsed into a control catalog and cached. Pinning matters: an upstream edit never
silently changes a report, and bumping the pin is a visible decision. Press FETCH LATEST in Settings.

Against that catalog the console does two useful things a static list cannot:

- **It validates itself.** Any control id this console claims that the catalog does not contain is
  reported as our bug, in red, rather than scored.
- **It shows what nothing covers.** Every published control with no template mapped to it is listed
  as a real gap. For the dev tenant that is 41 of 49, which is honest: our Defender templates cover
  endpoint protection while the SCuBA Defender baseline covers Exchange Online and DLP.

Coverage is also graded. `full` means the template satisfies the control as written; `partial` means
it moves in the right direction but does not meet the wording, and the reason is shown inline. For
example CISA requires high-risk sign-ins to be **blocked**, while template C008 requires MFA
instead. Partial counts as half a control, because claiming it in full would overstate the client's
position.

**Praxis templates** are the console's own set, with every setting chosen from the operator's library
of security books and courses. `scripts/build_praxis.py` holds one spec: each setting, its value, and
where it came from. `library` settings cite the course and passage; `microsoft` settings are ones the
library agrees should exist but gives no number for, so Microsoft's baseline supplies it; `judgement`
settings are picks between options the library offers, with the reasoning. The script writes the
deployable JSON and the provenance the Baseline tab shows beside every setting, and tests fail if a
library setting cites nothing or a non-library setting explains nothing. Rebuild after editing the
spec: `python3 scripts/build_praxis.py` (it reads Microsoft's baseline setting ids from the console
database, and refuses to guess an id that is not there).

Conditional Access policies that use fields only Graph beta supports, such as continuous access
evaluation, are created through the beta endpoint, since v1.0 would silently drop them.

**Microsoft's own Conditional Access templates** are the best source to build from: Microsoft's
recommended policies, published through Graph and updated as the product changes. The console reads
all of them (currently 23), compares them with the House templates on the Baseline tab and with each
tenant's live policies on every score, and registers the deployable ones under DEPLOY, report-only,
with the emergency access group excluded and a `Microsoft | ` name prefix. Three safety rules sit
under this:

- Templates are read from the beta API. The v1.0 API omits the agent-identity conditions, so
  "block all agent identities" arrives looking like "block everyone".
- Templates that depend on beta-only conditions are shown but not offered for deployment, because
  the console creates policies through v1.0, which would silently drop those conditions.
- Every Conditional Access deploy, from any source, is refused if the rendered policy would block
  every user from every app.

Policies are compared by what their grant accepts, not by label. A live policy meets a template only
if every way of passing the live policy also passes the template, so "MFA" does not meet "require a
compliant device", and "MFA or a compliant device" does not meet "require MFA". Session controls are
compared by kind.

**Microsoft's own Intune security baselines** are the yardstick for the Defender and Intune half.
Microsoft publishes them as settings catalog templates using the same setting and option ids Intune
policies use, so the comparison is exact: each recommended value is either held, held differently,
contradicted between two policies, or not set by any policy. Unset settings fall back to the Windows
default and are listed rather than scored as failures. The console reads the active Windows 10 and
later, Defender for Endpoint, Edge, Microsoft 365 Apps and Windows 11 STIG baselines through any
consented tenant and caches them, since they are identical in every tenant. The Baseline tab measures
the House templates themselves against them; a tenant score measures every live settings catalog
policy, whatever it is called. The STIG baseline is large enough that Microsoft's service times out
serving it in one page, so pages shrink on failure.

**CIS Benchmarks are imported from PDFs you download.** CIS publishes the free PDFs under Creative
Commons BY-NC-SA 4.0, so reading them is fine, but every download goes through a sign-up form on
CIS's site, which the console cannot complete for you. Download the benchmarks once into a folder,
set `PC_CIS_DIR` or paste the folder into Settings, and press IMPORT CIS PDFS. The console reads each
PDF with `pdftotext` (poppler) and keeps the parsed recommendations in its own database only; nothing
from a CIS PDF goes into this repository. Import on a machine that has poppler; a server then needs
neither the PDFs nor the tool.

Two things keep CIS scoring honest. Only sections this console manages are scored (for the
Microsoft 365 benchmark, 5.2.2 Conditional Access); the other recommendations are counted and shown as
out of scope rather than failed. And some controls ask for a dedicated policy, marked `exactOnly` in
the mapping: "enable sign-in risk policies" is not met by a tenant that simply requires MFA for
everyone, even though that tenant does cover the template's behavior.

The NC term matters for client work: cite CIS control ids and link to CIS rather than reproducing
recommendation text in a paid deliverable.

## Setting it up

### 1. Create the app registration (once)

In your own tenant, create a multi-tenant app registration with **application** permissions:

| Permission | Why |
|---|---|
| `Policy.Read.All` | Read Conditional Access policies |
| `Policy.ReadWrite.ConditionalAccess` | Create and change them |
| `DeviceManagementConfiguration.ReadWrite.All` | Intune and Defender settings catalog policies |
| `Organization.Read.All` | Confirm a connection actually landed |
| `SecurityEvents.Read.All` | Read Microsoft Secure Score |

Grant admin consent in your own tenant, then add a client secret or, better, a certificate.

Adding a permission later needs more than `az ad app permission admin-consent`: that command
reported success without granting anything. The permission only took effect after an explicit app
role assignment on the service principal, which is worth knowing before spending twenty minutes on
a working app that returns "does not contain valid permissions".

### 2. Run it

```bash
export PC_CLIENT_ID=<application id>
export PC_CLIENT_SECRET=<secret>
./policyconsole
```

Open http://127.0.0.1:4930.

| Variable | Default | Meaning |
|---|---|---|
| `PC_ADDR` | `127.0.0.1:4930` | Where it listens |
| `PC_DATABASE` | `policy-console.db` | History and run log file |
| `PC_CLIENT_ID` / `PC_CLIENT_SECRET` | none | The app registration |
| `PC_SNAPSHOT_INTERVAL` | `24h` | How often connected tenants are captured |
| `PC_READ_ONLY` | `false` | Refuse every write |
| `PC_TEMPLATE_DIR` | none | Read templates from a folder instead of from inside the binary |

Sign-in, for the people using the console:

| Variable | Default | Meaning |
|---|---|---|
| `PC_TENANT_ID` | none | The tenant staff sign in from |
| `PC_WEB_CLIENT_ID` / `PC_WEB_CLIENT_SECRET` | none | The console's own app registration |
| `PC_PUBLIC_URL` | `http://<addr>` | How a browser reaches the console; sets the redirect URI |
| `PC_SESSION_KEY` | generated | Signs session cookies. Generated if unset, so a restart signs everyone out |
| `PC_ALLOWED_USERS` | none | Comma-separated list of user principal names allowed in |
| `PC_ALLOWED_GROUP` | none | Object id of a group a signed-in user must belong to |
| `PC_AUTH_DISABLED` | `false` | Local development only |
| `PC_EASYAUTH_SECRET` | none | Trust App Service Easy Auth's `X-Ms-Client-Principal-Name` header only on requests that also carry this value in `X-Pc-Easyauth-Secret` (have the proxy in front add it). Unset means the header is ignored |
| `PC_DEPLOYERS` / `PC_DEPLOYER_GROUP` | none | Who may deploy, revert, modify or delete. Everyone else allowed in is a read-only viewer. If neither is set, every allowed user is a deployer |
| `PC_BACKUP_DIR` | `backups` | Where `policyconsole backup` writes snapshots |

The console refuses to start with writes enabled unless `PC_ALLOWED_USERS` or `PC_ALLOWED_GROUP` is
set (or `PC_READ_ONLY=true`). State-changing requests from a browser on another site are refused.

**Backup and restore.** `policyconsole backup` writes a consistent snapshot of the database into
`PC_BACKUP_DIR`; it is safe while the console runs. `scripts/restore-drill.sh <db file>` backs up,
restores into a temp folder and checks every table's row count matches. To restore for real, stop
the console and copy a snapshot over the database file.

**The console refuses to start** if it is listening on anything other than localhost with writes
enabled and no sign-in configured. Exposing tenant writes to a network with no authentication is not
a configuration worth supporting, so it fails loudly instead of running.

Where Azure App Service Easy Auth or a reverse proxy has already signed the person in, the console
trusts `X-Ms-Client-Principal-Name` and does not run a second login. That header is only trusted when
the console is not doing its own sign-in, because otherwise a caller could simply set it.

### 3. Set up staff sign-in

Create a second, single-tenant app registration for the console itself, with a web redirect URI of
`<public url>/auth/callback` and delegated `User.Read`. Point `PC_WEB_CLIENT_ID`,
`PC_WEB_CLIENT_SECRET` and `PC_TENANT_ID` at it. Restrict who gets in with `PC_ALLOWED_GROUP` (a
group object id) or `PC_ALLOWED_USERS`; with neither set, anyone in the tenant can sign in, and the
Settings tab says so.

Two registrations rather than one is deliberate: the tenant-reaching app is multi-tenant by
necessity, and using a multi-tenant app for staff sign-in would let users from any consented client
tenant sign in to your console.

### 4. Onboard a client

Add the tenant, press CONSENT LINK, send that link to the client's global administrator. Once they
accept, press CHECK. The status turns to connected and the tenant name appears.

## Building

```bash
./scripts/build.sh          # every platform, into dist/
./scripts/sync-templates.sh # pull the latest templates from the OneDrive folder
go test ./...
```

## Where the templates come from

The operator's master `Policy Templates` folder is the source of truth. The JSON is
copied into `internal/catalog/files` and compiled into the binary so the console works on a server
with no OneDrive. Run `scripts/sync-templates.sh` after editing the originals.

## Deploying to Azure

The Dockerfile produces a small image with no operating system inside it. Give the container a
persistent volume for the database, put the client secret in Key Vault, and put Entra ID sign-in in
front of it so only your own staff reach it. The console reads the signed-in user from the
`X-Ms-Client-Principal-Name` header and records it against every change.

## Template libraries (Open Intune Baseline)

The House set is the standard every client is measured against. Libraries are optional extra
templates you can browse and deploy on request; they are never expected in a tenant, so they do not
count as missing and take no part in the score.

Open Intune Baseline is licensed GPL-3.0, so it is not compiled into the program. Import it into a
folder on your machine and point the console at that folder:

```bash
policyconsole import-oib <Open Intune Baseline checkout> <library folder>
export PC_EXTRA_TEMPLATES=<library folder>
```

The import reads the settings catalog policies for Windows, macOS and Windows 365 (80 policies in
OIB 4.0), converts them to plain UTF-8 JSON, strips everything a tenant assigned (ids, links,
assignments), and writes `OIB-NOTICE.txt` with the licence and source. Keep that folder out of this
repository. It also imports compliance policies and iOS and Android app protection policies. It reports what it
could not import: update rings, driver update profiles and legacy device configuration profiles,
because the console cannot manage those kinds of object yet. A GUID outside Microsoft's own template fields is flagged for a person to check.

## Licence

GPL-3.0. See `LICENSE`. The Open Intune Baseline library is a separate GPL-3.0 work and is imported locally, never bundled here.
