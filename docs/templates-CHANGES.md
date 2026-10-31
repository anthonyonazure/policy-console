# Changes

## 2026-09-15: rebuilt as client-neutral templates

The previous folder held 28 JSON files: Conditional Access policies with no targeting, and Defender policies exported from a client tenant. This rebuild turns them into a complete, reusable set. The previous files are kept unchanged in `Clients/Policy Templates backup 2026-09-15`.

### Structure

- Templates are grouped into `conditional-access/`, `defender/`, and `intune/`, each with `json/`, `powershell/`, `bicep/`, and `terraform/` folders.
- Added `all-in-one/` for deploying several categories at once.
- Added README.md (what each template does, every setting and its allowed values) and DEPLOYMENT.md (how to deploy, with scenarios).

### Source

All templates were regenerated from the most recent full policy export (April 2026) so settings match a working tenant, then stripped of client data. No client names, group IDs, user IDs, tenant IDs, IP addresses, or phone numbers remain; an automated scan checked every ID in the set against the source tenant's objects.

### Applies to every Conditional Access policy

- `state` is now `enabledForReportingButNotEnforced` (report-only). The originals were a mix of on, off, and report-only.
- The emergency access group, the admin service accounts group, and the travel group are placeholders (`${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`, `${TRAVEL_EXCLUSION_GROUP_ID}`). The originals either had no targeting at all (so they could not be imported as they were) or had one client's group IDs.
- Named location and authentication strength IDs are placeholders filled in at deploy time.
- The device filter rule in C015 and C016 had stray backslashes in the original files, which would have broken the filter. Fixed.

### Files removed as duplicates

The original folder had four pairs of identical files under slightly different names. One copy of each remains:

| Kept | Removed duplicate |
|---|---|
| `B365E C003a - Require MFA for Admin Roles v5.0` | `B365E  C003a - ...` (double space) |
| `MS Elite C007 - Require MFA + Password Change for Risky Users v5.0` | `MS Elite  C007 - ...` and `MS Elite C007 - Require MFA Password Change ...` |
| `MS Elite C008 - Require MFA for Risky Signins v5.0` | `MS Elite  C008 - ...` (double space) |
| `MS Elite C002 - Require MFA for Guest and External Users v4.1` | `Require MFA for Guest and External Users v4.1` |

`MS Elite  C006` (double space) was renamed to `MS Elite C006`.

### Per-template changes

| Template | Change |
|---|---|
| C001, C002, C003a, C003b, C006 to C011, C014, C016, C018 to C020 | Targeting filled in with placeholders; report-only |
| C008 | Now includes "sign-in frequency: every time", which the original template was missing |
| C012 | Removed one client-specific user group exclusion and an exclusion for one named outside tenant |
| C013 | Removed three client vendor group exclusions. Removed an "exclude all guests" setting that cancelled the "include all guests" setting and made the policy apply to nobody |
| C015 | Removed five client security team group exclusions and one named outside tenant. Kept the admin role list and the two standard exclusion groups |
| C017 | **New.** Removed one client group and one named outside tenant |
| C004 | **New.** Removed four client group exclusions and two individually excluded users |
| C005 | **New.** Removed four client group exclusions and two individually excluded users; travel group kept as a placeholder |
| C018 | **New** |
| Named location: High Risk Countries | **New.** Country list kept as in the baseline |
| Named location: Trusted Countries | **New.** Reset to `US` only (the source had `US` and `CA`); edit per client |
| Authentication strength: MS Elite Secure MFA - EAA | **New.** Removed the restriction to three specific FIDO2 key models, so any FIDO2 key works |
| B365E W10/11 and WinServer ASR rules | One rule each changed from Block to Audit |
| Attack Surface Reduction | **New.** 17 rules changed from Block or Warn to Audit |
| B365E antivirus (W10/11, WinServer, macOS), B365E firewall, Microsoft Defender | Settings unchanged; exported read-only fields removed |
| Microsoft Defender MacOS Antivirus, Windows 10 & Later LAPS | **New** |
| Windows 10 and Later (EDR) | **New.** Removed the source tenant's encrypted onboarding token; Intune supplies it from the Defender connector |
| Default iOS/iPadOS Settings | **New.** Lock screen text with a client name and phone number replaced by `${LOCK_SCREEN_MESSAGE}` |
| macOS Platform SSO, Microsoft Defender MacOS, Visual Studio Updates, Windows 10 & Later Configuration Profile | **New** |

### Not included, on purpose

| Policy | Reason |
|---|---|
| Two "Microsoft-managed" Conditional Access policies | Microsoft creates and manages these in every tenant |
| Eleven Windows Autopatch policies | The Autopatch service creates and owns these; copies would conflict |
| An IP-range named location | A list of one client's IP addresses |
