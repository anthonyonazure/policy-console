# Policy Templates

Reusable Conditional Access, Microsoft Defender, and Intune policy templates for any client tenant. The templates hold no client data: every client-specific value (groups, named location IDs, company text) is a placeholder you fill in at deploy time.

How to deploy (PowerShell, Terraform, Bicep, or portal upload, with scenario examples) is in [DEPLOYMENT.md](DEPLOYMENT.md). What changed from the original template files is in [CHANGES.md](CHANGES.md).

## Contents

- [Folder layout](#folder-layout)
- [Safe by default: report-only and unassigned](#safe-by-default-report-only-and-unassigned)
- [Turning policies on](#turning-policies-on)
- [Placeholders](#placeholders)
- [Overlapping policies](#overlapping-policies)
- [Conditional Access templates](#conditional-access-templates)
- [Defender templates](#defender-templates)
- [Intune templates](#intune-templates)

## Folder layout

```text
Policy Templates/
  README.md            this file
  DEPLOYMENT.md        how to deploy each format, with scenarios
  CHANGES.md           what changed from the original files
  conditional-access/  Entra ID Conditional Access
    json/policies/                 the policy templates (source of truth)
    json/named-locations/          country lists used by C004, C005
    json/authentication-strengths/ custom sign-in method set used by C020
    powershell/  bicep/  terraform/
  defender/            Intune endpoint security: antivirus, attack surface reduction, firewall, EDR, LAPS
    json/  powershell/  bicep/  terraform/
  intune/              Intune settings catalog device configuration profiles
    json/  powershell/  bicep/  terraform/
  all-in-one/          deploy any combination of the folders above in one run
    powershell/  bicep/  terraform/
  _shared/             engine code the other scripts call (do not deploy directly)
  _generator/          rebuilds this whole set from a tenant export (see _generator/README.md)
    python/  powershell/  shell/  json/
```

The JSON file is the single source of truth for each template. The PowerShell, Bicep, and Terraform files read the JSON at deploy time, so editing a JSON file changes what every format deploys. Keep the folder structure intact when copying the set.

New categories (for example `copilot/` or `entra-id/`) follow the same layout: a folder with `json/`, `powershell/`, `bicep/`, and `terraform/` inside.

## Safe by default: report-only and unassigned

| Category | What happens at deploy | Effect on users |
|---|---|---|
| Conditional Access | Created in **report-only** mode (`enabledForReportingButNotEnforced`) | None. Entra logs what the policy *would* have done in each sign-in log, under the Report-only tab. |
| Named locations, authentication strength | Created | None on their own. |
| Defender and Intune | Created **without assignments** | None until you assign the policy to a group. Intune has no report-only switch; being unassigned is the safe state. |
| Attack surface reduction rules | Rules that were Block or Warn ship as **Audit** | Once assigned, rules log to Defender but block nothing. |

## Turning policies on

### Conditional Access

1. Leave the policy in report-only for at least a week. In the Entra admin center go to **Entra ID > Conditional Access > Insights and reporting** (or open a user's sign-in log and choose the **Report-only** tab) and check who would have been blocked or prompted.
2. Fix anything unexpected (add an exclusion group, adjust a location list).
3. Turn it on with one of these:
   - Portal: **Entra ID > Conditional Access > Policies >** open the policy **> Enable policy: On > Save**.
   - PowerShell: `./conditional-access/powershell/Set-ConditionalAccessState.ps1 -Policies C006,C011 -State enabled`
   - Terraform: set `state = "enabled"` (or `conditional_access_state` in all-in-one) and run `terraform apply`.
   - Bicep: deploy again with `state=enabled`. The deployment reuses existing policies, so use the portal or the PowerShell script to change the state of a policy that already exists.
4. To go back: set the state to `enabledForReportingButNotEnforced` (report-only) or `disabled` (off) the same way.

Always confirm the emergency access accounts are in the `EMERGENCY_ACCESS_GROUP_ID` group before turning on any blocking policy.

### Defender and Intune

1. Assign the policy to a small pilot group: Intune admin center > **Endpoint security** (Defender templates) or **Devices > Configuration** (Intune templates) > open the policy > **Properties > Assignments > Edit**.
2. Check the device status report on the policy after devices check in.
3. Widen the assignment to all target devices.
4. Attack surface reduction: after reviewing audit events in Microsoft Defender (**Reports > Attack surface reduction rules**), edit the policy and change each rule from **Audit** to **Block** (or **Warn**). In the JSON, that is the setting value suffix `_audit` changed to `_block`, `_warn`, or `_off`.

## Placeholders

Templates contain `${NAME}` placeholders. Every deploy method asks for these values; a template that still has an unfilled placeholder is refused with a message naming it.

| Placeholder | What to supply | Used by |
|---|---|---|
| `EMERGENCY_ACCESS_GROUP_ID` | Emergency access (break-glass) accounts group | C001, C003a, C003b, C004, C005, C006, C007, C008, C009, C010, C011, C012, C013, C014, C015, C017, C018, C019, C020 |
| `SERVICE_ACCOUNTS_GROUP_ID` | Admin service accounts exclusion group | C001, C003a, C003b, C007, C008, C009, C010, C015, C017, C018 |
| `TRAVEL_EXCLUSION_GROUP_ID` | Users allowed to sign in while traveling | C005 |
| `HIGH_RISK_COUNTRIES_LOCATION_ID` | High-risk countries named location | C004 |
| `TRUSTED_COUNTRIES_LOCATION_ID` | Trusted countries named location | C005 |
| `EMERGENCY_ACCESS_AUTH_STRENGTH_ID` | Emergency access authentication strength | C020 |
| `LOCK_SCREEN_MESSAGE` | iOS lock screen text | Default iOS_iPadOS Settings |

Named location and authentication strength IDs are filled in automatically when the deploy script creates those objects. Supply them only to reuse objects that already exist in the tenant.

## Overlapping policies

Some templates cover the same settings. Assigning both to the same devices causes conflicts that Intune reports as errors. Pick one per pair for any device group:

- `B365E W10_11-Endpoint-Antivirus-Defender Configuration` and `Microsoft Defender`
- `B365E W10_11-Endpoint-ASR-Attack Surface Reduction Rules` and `Attack Surface Reduction`
- `B365E macOS-Endpoint-Antivirus-Defender Configuration` and `Microsoft Defender MacOS Antivirus`
- `B365E W10_11-Endpoint-Firewall-Defender Configuration` and `Windows 10 & Later Configuration Profile` (firewall settings)
- Conditional Access `C003a` and `C003b` (same purpose, different versions)

## Conditional Access templates

### Settings you can change on any Conditional Access template

| Setting (JSON path) | Possible values |
|---|---|
| `state` | `enabledForReportingButNotEnforced` (report-only), `enabled` (on), `disabled` (off) |
| `conditions.users.includeUsers` / `excludeUsers` | `All`, `None`, `GuestsOrExternalUsers`, or user object IDs |
| `conditions.users.includeGroups` / `excludeGroups` | group object IDs |
| `conditions.users.includeRoles` / `excludeRoles` | built-in role template IDs |
| `conditions.applications.includeApplications` | `All`, `Office365`, `MicrosoftAdminPortals`, or app IDs |
| `conditions.locations.includeLocations` / `excludeLocations` | `All`, `AllTrusted`, or named location IDs |
| `conditions.platforms.includePlatforms` / `excludePlatforms` | `all`, `android`, `iOS`, `windows`, `macOS`, `linux`, `windowsPhone` |
| `conditions.clientAppTypes` | `all`, `browser`, `mobileAppsAndDesktopClients`, `exchangeActiveSync`, `other` |
| `conditions.signInRiskLevels` / `userRiskLevels` | `low`, `medium`, `high`, `none` |
| `grantControls.operator` | `OR` (any control), `AND` (all controls) |
| `grantControls.builtInControls` | `block`, `mfa`, `compliantDevice`, `domainJoinedDevice`, `approvedApplication`, `compliantApplication`, `passwordChange` |
| `grantControls.authenticationStrength.id` | `00000000-0000-0000-0000-000000000002` MFA, `...0003` passwordless MFA, `...0004` phishing-resistant MFA, or a custom strength ID |
| `sessionControls.signInFrequency` | `value` + `type` (`hours`/`days`), or `frequencyInterval: everyTime` |
| `sessionControls.persistentBrowser.mode` | `always`, `never` |

### C001: Require MFA from Untrusted Locations v5.1

Asks every user for MFA at sign-in, and again once a day. Android and iOS are left out because the mobile apps handle this through app protection.

- **File:** `conditional-access/json/policies/MS Elite C001 - Require MFA from Untrusted Locations v5.1.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts; all guest and external user types
- **Apps:** All cloud apps
- **Device platforms:** include all; exclude android, iOS
- **Locations:** include any location
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Sign-in frequency:** every 1 days
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C002: Require MFA for Guest and External Users v4.1

Makes guests and external users complete MFA before they reach any app.

- **File:** `conditional-access/json/policies/MS Elite C002 - Require MFA for Guest and External Users v4.1.json`
- **Applies to:** all guest and external user types
- **Apps:** All cloud apps
- **Locations:** include any location
- **Grant (OR):** mfa
- **Sign-in frequency:** every 8 hours
- **Placeholders:** none

### C003a: Require MFA for Admin Roles v5.0

Requires MFA for anyone holding an admin role. The older B365E version; C003b is the stronger replacement. Deploy one or the other.

- **File:** `conditional-access/json/policies/B365E C003a - Require MFA for Admin Roles v5.0.json`
- **Applies to:** 26 admin roles
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** All cloud apps
- **Grant (OR):** mfa
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C003b: Require phishing-resistant MFA for Admin Roles v5.0

Requires MFA for anyone holding an admin role (the MS Elite version of C003a).

- **File:** `conditional-access/json/policies/MS Elite C003b - Require phishing-resistant MFA for Admin Roles v5.0.json`
- **Applies to:** 26 admin roles
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** All cloud apps
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C004: Block Access from High-risk Countries (No Exclusions) v5.2

Blocks every sign-in that comes from a country on the high-risk list. No travel exceptions.

- **File:** `conditional-access/json/policies/MS Elite C004 - Block Access from High-risk Countries (No Exclusions) v5.2.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`; all guest and external user types
- **Apps:** All cloud apps
- **Locations:** include `${HIGH_RISK_COUNTRIES_LOCATION_ID}`
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `HIGH_RISK_COUNTRIES_LOCATION_ID`

### C005: Block Access from Untrusted Countries (Exclude Travel) v5.2

Blocks sign-ins from any country outside the trusted list, except for members of the travel group.

- **File:** `conditional-access/json/policies/MS Elite C005 - Block Access from Untrusted Countries (Exclude Travel) v5.2.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${TRAVEL_EXCLUSION_GROUP_ID}`; all guest and external user types
- **Apps:** All cloud apps
- **Locations:** include any location; exclude `${TRUSTED_COUNTRIES_LOCATION_ID}`
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `TRAVEL_EXCLUSION_GROUP_ID`, `TRUSTED_COUNTRIES_LOCATION_ID`

### C006: Block Legacy Authentication v5.1

Blocks legacy authentication (old mail protocols such as POP, IMAP, SMTP basic auth, and old Office clients). These cannot do MFA, so attackers use them to get around it.

- **File:** `conditional-access/json/policies/MS Elite C006 - Block Legacy Authentication v5.1.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`
- **Apps:** All cloud apps
- **Client apps:** exchangeActiveSync, other
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`

### C007: Require MFA + Password Change for Risky Users v5.0

When Entra ID Protection rates a user as high risk (for example a leaked password), forces MFA and a password change.

- **File:** `conditional-access/json/policies/MS Elite C007 - Require MFA + Password Change for Risky Users v5.0.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** All cloud apps
- **User risk:** high
- **Grant (AND):** passwordChange, authentication strength: Multifactor authentication (built-in)
- **Sign-in frequency:** every time
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C008: Require MFA for Risky Signins v5.0

When a single sign-in looks risky (medium or high), forces MFA on every such sign-in.

- **File:** `conditional-access/json/policies/MS Elite C008 - Require MFA for Risky Signins v5.0.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** All cloud apps
- **Sign-in risk:** high, medium
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Sign-in frequency:** every time
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C009: Require MFA for Admin Roles signing to Azure Management v5.0

Requires MFA for admins who reach Azure management (portal, CLI, PowerShell, ARM).

- **File:** `conditional-access/json/policies/MS Elite C009 - Require MFA for Admin Roles signing to Azure Management v5.0.json`
- **Applies to:** 26 admin roles
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** Windows Azure Service Management API (Azure portal, CLI, PowerShell)
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C010: Require MFA for Admin Roles signing to Admin Portals v5.0

Requires MFA for admins who reach the Microsoft admin portals (Microsoft 365, Entra, Intune, Exchange and others).

- **File:** `conditional-access/json/policies/MS Elite C010 - Require MFA for Admin Roles signing to Admin Portals v5.0.json`
- **Applies to:** 26 admin roles
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** Microsoft Admin Portals
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C011: Block Device Code Flow v5.1

Blocks the device code sign-in flow, a common phishing technique where a victim types a code on a real Microsoft page.

- **File:** `conditional-access/json/policies/MS Elite C011 - Block Device Code Flow v5.1.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`
- **Apps:** All cloud apps
- **Authentication flows:** deviceCodeFlow
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`

### C012: Require TAP for Security Information Registration from Untrusted Locations v5.0

Registering MFA methods from outside a trusted location requires a Temporary Access Pass or existing MFA. Stops an attacker with a password from enrolling their own phone.

- **File:** `conditional-access/json/policies/MS Elite C012 - Require TAP for Security Information Registration from Untrusted Locations v5.0.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`
- **User action:** register security information (MFA methods)
- **Locations:** include any location; exclude all trusted locations
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`

### C013: Block Guest Security Information Registration from Untrusted Locations v5.0

Blocks guests from registering MFA methods when they are outside a trusted location.

- **File:** `conditional-access/json/policies/MS Elite C013 - Block Guest Security Information Registration from Untrusted Locations v5.0.json`
- **Applies to:** all guest and external user types
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`
- **User action:** register security information (MFA methods)
- **Locations:** include any location; exclude all trusted locations
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`

### C014: Block Unsupported OS Platforms v4.0

Blocks sign-ins from operating systems the organization does not support (for example Linux or Windows Phone).

- **File:** `conditional-access/json/policies/MS Elite C014 - Block Unsupported OS Platforms v4.0.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`
- **Apps:** All cloud apps
- **Device platforms:** include all; exclude android, iOS, windows, macOS, linux
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`

### C015: Block Admin Access from Unmanaged Devices v5.1

Blocks admins unless they use a managed device: Entra joined, hybrid joined, or marked compliant.

- **File:** `conditional-access/json/policies/MS Elite C015 - Block Admin Access from Unmanaged Devices v5.1.json`
- **Applies to:** 83 admin roles
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** All cloud apps
- **Device filter (exclude):** `device.trustType -eq "ServerAD" -or device.trustType -eq "AzureAD" -or device.isCompliant -eq True`
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C016: Limit Web Sessions Time from Unmanaged Devices v5.1

On devices that are not managed, web sessions expire sooner and browsers do not stay signed in.

- **File:** `conditional-access/json/policies/MS Elite C016 - Limit Web Sessions Time from Unmanaged Devices v5.1.json`
- **Applies to:** all users
- **Apps:** All cloud apps
- **Device platforms:** include all; exclude android, iOS, macOS
- **Client apps:** browser
- **Device filter (exclude):** `device.trustType -eq "ServerAD" -or device.trustType -eq "AzureAD" -or device.isCompliant -eq True`
- **Sign-in frequency:** every 8 hours
- **Persistent browser session:** never
- **Placeholders:** none

### C017: Block Unmanaged Devices v5.1

Blocks everyone unless they use a managed device. Very strict; plan device enrollment first.

- **File:** `conditional-access/json/policies/MS Elite C017 - Block Unmanaged Devices v5.1.json`
- **Applies to:** all users
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** All cloud apps
- **Device filter (exclude):** `device.trustType -eq "ServerAD" -or device.trustType -eq "AzureAD" -or device.isCompliant -eq True`
- **Grant (OR):** block access
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C018: Require MFA for Admin roles signing to Azure DevOps v5.0

Requires MFA for admins who reach Azure DevOps.

- **File:** `conditional-access/json/policies/MS Elite C018 - Require MFA for Admin roles signing to Azure DevOps v5.0.json`
- **Applies to:** 26 admin roles
- **Excluded:** groups `${EMERGENCY_ACCESS_GROUP_ID}`, `${SERVICE_ACCOUNTS_GROUP_ID}`; roles Directory Synchronization Accounts
- **Apps:** Azure DevOps
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`, `SERVICE_ACCOUNTS_GROUP_ID`

### C019: Require TAP for Emergency Accounts Security Information Registration v5.0

Emergency access accounts can only register security info with a Temporary Access Pass or MFA.

- **File:** `conditional-access/json/policies/MS Elite C019 - Require TAP for Emergency Accounts Security Information Registration v5.0.json`
- **Applies to:** group `${EMERGENCY_ACCESS_GROUP_ID}`
- **User action:** register security information (MFA methods)
- **Grant (OR):** authentication strength: Multifactor authentication (built-in)
- **Placeholders:** `EMERGENCY_ACCESS_GROUP_ID`

### C020: Require FIDO2 or TAP Authentication for Emergency Accounts v5.0

Emergency access accounts must sign in with a FIDO2 security key or a Temporary Access Pass.

- **File:** `conditional-access/json/policies/MS Elite C020 - Require FIDO2 or TAP Authentication for Emergency Accounts v5.0.json`
- **Applies to:** group `${EMERGENCY_ACCESS_GROUP_ID}`
- **Apps:** All cloud apps
- **Grant (OR):** authentication strength: MS Elite Secure MFA - EAA (custom, created from this template set)
- **Placeholders:** `EMERGENCY_ACCESS_AUTH_STRENGTH_ID`, `EMERGENCY_ACCESS_GROUP_ID`

### Named locations

- **MS Elite | High Risk Countries v5.0** (`MS Elite High Risk Countries v5.0.json`): countries BY, BR, CN, IN, IR, KR, NG, KP, RU, TH, UA. Edit `countriesAndRegions` (two-letter ISO codes) per client; `includeUnknownCountriesAndRegions` true also matches IP addresses with no country.
- **MS Elite | Trusted Countries v4.0** (`MS Elite Trusted Countries v4.0.json`): countries US. Edit `countriesAndRegions` (two-letter ISO codes) per client; `includeUnknownCountriesAndRegions` true also matches IP addresses with no country.

### Authentication strength

- **MS Elite | Secure MFA - EAA**: allows fido2, temporaryAccessPassOneTime, temporaryAccessPassMultiUse. To allow only specific FIDO2 key models, add them in the portal (**Entra ID > Authentication methods > Authentication strengths**) after deployment.

## Defender templates

### Attack Surface Reduction

A second, broader set of attack surface reduction rules (the older, non-B365E policy). Overlaps the B365E ASR policy; use one of them per device group.

- **File:** `defender/json/Attack Surface Reduction.json`
- **Platform:** windows10
- **Settings:** 21
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Attack Surface Reduction Rules | (group) |  |
| &nbsp;&nbsp;Block execution of potentially obfuscated scripts | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Win32 API calls from Office macros | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block executable files from running unless they meet a prevalence, age, or trusted list criterion | Off | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office communication application from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block all Office applications from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Adobe Reader from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block credential stealing from the Windows local security authority subsystem | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block JavaScript or VBScript from launching downloaded executable content | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Webshell creation for Servers | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block untrusted and unsigned processes that run from USB | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block persistence through WMI event subscription | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block use of copied or impersonated system tools | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block abuse of exploited vulnerable signed drivers (Device) | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block process creations originating from PSExec and WMI commands | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office applications from creating executable content | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office applications from injecting code into other processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block rebooting machine in Safe Mode | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Use advanced protection against ransomware | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block executable content from email client and webmail | Audit | Off, Block, Audit, Warn |
| Enable Controlled Folder Access | Audit Mode | Disabled, Enabled, Audit Mode, Block disk modification only, Audit disk modification only |

</details>

### B365E | W10/11-Endpoint-ASR-Attack Surface Reduction Rules v4.2

Attack surface reduction rules for Windows 10 and 11. These stop common malware tricks such as Office apps launching scripts.

- **File:** `defender/json/B365E W10_11-Endpoint-ASR-Attack Surface Reduction Rules v4.2.json`
- **Platform:** windows10
- **Settings:** 20
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Attack Surface Reduction Rules | (group) |  |
| &nbsp;&nbsp;Block execution of potentially obfuscated scripts | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Win32 API calls from Office macros | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block executable files from running unless they meet a prevalence, age, or trusted list criterion | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office communication application from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block all Office applications from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Adobe Reader from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block credential stealing from the Windows local security authority subsystem | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block JavaScript or VBScript from launching downloaded executable content | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Webshell creation for Servers | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block untrusted and unsigned processes that run from USB | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block persistence through WMI event subscription | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block use of copied or impersonated system tools | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block abuse of exploited vulnerable signed drivers (Device) | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office applications from creating executable content | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office applications from injecting code into other processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block rebooting machine in Safe Mode | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Use advanced protection against ransomware | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block executable content from email client and webmail | Audit | Off, Block, Audit, Warn |
| Enable Controlled Folder Access | Audit Mode | Disabled, Enabled, Audit Mode, Block disk modification only, Audit disk modification only |

</details>

### B365E | W10/11-Endpoint-Antivirus-Defender Configuration v4.1

Microsoft Defender Antivirus settings for Windows 10 and 11 workstations.

- **File:** `defender/json/B365E W10_11-Endpoint-Antivirus-Defender Configuration v4.1.json`
- **Platform:** windows10
- **Settings:** 34
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Threat Severity Default Action | (group) |  |
| &nbsp;&nbsp;Remediation action for High severity threats | Block. Blocks file execution. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| &nbsp;&nbsp;Remediation action for Severe threats | Block. Blocks file execution. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| &nbsp;&nbsp;Remediation action for Low severity threats | Clean. Service tries to recover files and try to disinfect. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| &nbsp;&nbsp;Remediation action for Moderate severity threats | Quarantine. Moves files to quarantine. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| Allow Archive Scanning | Allowed. Scans the archive files. | Not allowed. Turns off scanning on archived files., Allowed. Scans the archive files. |
| Allow Behavior Monitoring | Allowed. Turns on real-time behavior monitoring. | Not allowed. Turns off behavior monitoring., Allowed. Turns on real-time behavior monitoring. |
| Allow Cloud Protection | Allowed. Turns on Cloud Protection. | Not allowed. Turns off Cloud Protection., Allowed. Turns on Cloud Protection. |
| Allow Email Scanning | Allowed. Turns on email scanning. | Not allowed. Turns off email scanning., Allowed. Turns on email scanning. |
| Allow Full Scan On Mapped Network Drives | Not allowed. Disables scanning on mapped network drives. | Not allowed. Disables scanning on mapped network drives., Allowed. Scans mapped network drives. |
| Allow Full Scan Removable Drive Scanning | Allowed. Scans removable drives. | Not allowed. Turns off scanning on removable drives., Allowed. Scans removable drives. |
| Allow Realtime Monitoring | Allowed. Turns on and runs the real-time monitoring service. | Not allowed. Turns off the real-time monitoring service., Allowed. Turns on and runs the real-time monitoring service. |
| Allow scanning of all downloaded files and attachments | Allowed. | Not allowed., Allowed. |
| Allow Scanning Network Files | Not allowed. Turns off scanning of network files. | Not allowed. Turns off scanning of network files., Allowed. Scans network files. |
| Allow Script Scanning | Allowed. | Not allowed., Allowed. |
| Allow User UI Access | Allowed. Lets users access UI. | Not allowed. Prevents users from accessing UI., Allowed. Lets users access UI. |
| Avg CPU Load Factor | 30 | number 0 to 100 |
| Check For Signatures Before Running Scan | Enabled | Disabled, Enabled |
| Cloud Block Level | High Plus | Default State, High, High Plus, Zero Tolerance |
| Cloud Extended Timeout | 50 | number 0 to 50 |
| Disable Catchup Full Scan | Enabled | Disabled, Enabled |
| Disable Catchup Quick Scan | Disabled | Disabled, Enabled |
| Enable Low CPU Priority | Enabled | Disabled, Enabled |
| Enable Network Protection | Enabled (block mode) | Disabled, Enabled (block mode), Enabled (audit mode) |
| PUA Protection | PUA Protection on. Detected items are blocked. They will show in history along with other threats. | PUA Protection off. Windows Defender will not protect against potentially unwanted applications., PUA Protection on. Detected items are blocked. They will show in history along with other threats., Audit mode. Windows Defender will detect potentially unwanted applications, but take no action. You can review information about the applications Windows Defender would have taken action against by searching for events created by Windows Defender in the Event Viewer. |
| Real Time Scan Direction | Monitor all files (bi-directional). | Monitor all files (bi-directional)., Monitor incoming files., Monitor outgoing files. |
| Scan Parameter | Quick scan | Quick scan, Full scan |
| Schedule Quick Scan Time | 1080 | number 0 to 1380 |
| Schedule Scan Day | Every day | Every day, Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, No scheduled scan |
| Signature Update Interval | 4 | number 0 to 24 |
| Submit Samples Consent | Send safe samples automatically. | Always prompt., Send safe samples automatically., Never send., Send all samples automatically. |
| Allow On Access Protection | Allowed. | Not allowed., Allowed. |
| Disable Dns Over Tcp Parsing | DNS over TCP parsing is enabled | DNS over TCP parsing is disabled, DNS over TCP parsing is enabled |
| Disable Http Parsing | HTTP parsing is enabled | HTTP parsing is disabled, HTTP parsing is enabled |

</details>

### B365E | W10/11-Endpoint-Firewall-Defender Configuration v4.1

Turns on Windows Firewall for the domain, private and public network profiles.

- **File:** `defender/json/B365E W10_11-Endpoint-Firewall-Defender Configuration v4.1.json`
- **Platform:** windows10
- **Settings:** 5
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Disable Stateful Ftp | True | False, True |
| Security association idle time | 300 | number 300 to 3600 |
| Enable Domain Network Firewall | True | False, True |
| Enable Private Network Firewall | True | False, True |
| Enable Public Network Firewall | True | False, True |

</details>

### B365E | WinServer-Endpoint-ASR-Attack Surface Reduction Rules v4.2

Attack surface reduction rules for Windows Server.

- **File:** `defender/json/B365E WinServer-Endpoint-ASR-Attack Surface Reduction Rules v4.2.json`
- **Platform:** windows10
- **Settings:** 20
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Attack Surface Reduction Rules | (group) |  |
| &nbsp;&nbsp;Block execution of potentially obfuscated scripts | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Win32 API calls from Office macros | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block executable files from running unless they meet a prevalence, age, or trusted list criterion | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office communication application from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block all Office applications from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Adobe Reader from creating child processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block credential stealing from the Windows local security authority subsystem | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block JavaScript or VBScript from launching downloaded executable content | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Webshell creation for Servers | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block untrusted and unsigned processes that run from USB | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block persistence through WMI event subscription | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block use of copied or impersonated system tools | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block abuse of exploited vulnerable signed drivers (Device) | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office applications from creating executable content | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block Office applications from injecting code into other processes | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block rebooting machine in Safe Mode | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Use advanced protection against ransomware | Audit | Off, Block, Audit, Warn |
| &nbsp;&nbsp;Block executable content from email client and webmail | Audit | Off, Block, Audit, Warn |
| Enable Controlled Folder Access | Audit Mode | Disabled, Enabled, Audit Mode, Block disk modification only, Audit disk modification only |

</details>

### B365E | WinServer-Endpoint-Antivirus-Defender Configuration v4.1

Microsoft Defender Antivirus settings for Windows Server.

- **File:** `defender/json/B365E WinServer-Endpoint-Antivirus-Defender Configuration v4.1.json`
- **Platform:** windows10
- **Settings:** 34
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Threat Severity Default Action | (group) |  |
| &nbsp;&nbsp;Remediation action for High severity threats | Block. Blocks file execution. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| &nbsp;&nbsp;Remediation action for Severe threats | Block. Blocks file execution. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| &nbsp;&nbsp;Remediation action for Low severity threats | Clean. Service tries to recover files and try to disinfect. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| &nbsp;&nbsp;Remediation action for Moderate severity threats | Quarantine. Moves files to quarantine. | Clean. Service tries to recover files and try to disinfect., Quarantine. Moves files to quarantine., Remove. Removes files from system., Allow. Allows file/does none of the above actions., User defined. Requires user to make a decision on which action to take., Block. Blocks file execution. |
| Allow Archive Scanning | Allowed. Scans the archive files. | Not allowed. Turns off scanning on archived files., Allowed. Scans the archive files. |
| Allow Behavior Monitoring | Allowed. Turns on real-time behavior monitoring. | Not allowed. Turns off behavior monitoring., Allowed. Turns on real-time behavior monitoring. |
| Allow Cloud Protection | Allowed. Turns on Cloud Protection. | Not allowed. Turns off Cloud Protection., Allowed. Turns on Cloud Protection. |
| Allow Email Scanning | Allowed. Turns on email scanning. | Not allowed. Turns off email scanning., Allowed. Turns on email scanning. |
| Allow Full Scan On Mapped Network Drives | Not allowed. Disables scanning on mapped network drives. | Not allowed. Disables scanning on mapped network drives., Allowed. Scans mapped network drives. |
| Allow Full Scan Removable Drive Scanning | Allowed. Scans removable drives. | Not allowed. Turns off scanning on removable drives., Allowed. Scans removable drives. |
| Allow Realtime Monitoring | Allowed. Turns on and runs the real-time monitoring service. | Not allowed. Turns off the real-time monitoring service., Allowed. Turns on and runs the real-time monitoring service. |
| Allow scanning of all downloaded files and attachments | Allowed. | Not allowed., Allowed. |
| Allow Scanning Network Files | Not allowed. Turns off scanning of network files. | Not allowed. Turns off scanning of network files., Allowed. Scans network files. |
| Allow Script Scanning | Allowed. | Not allowed., Allowed. |
| Allow User UI Access | Allowed. Lets users access UI. | Not allowed. Prevents users from accessing UI., Allowed. Lets users access UI. |
| Avg CPU Load Factor | 30 | number 0 to 100 |
| Check For Signatures Before Running Scan | Enabled | Disabled, Enabled |
| Cloud Block Level | Default State | Default State, High, High Plus, Zero Tolerance |
| Cloud Extended Timeout | 50 | number 0 to 50 |
| Disable Catchup Full Scan | Enabled | Disabled, Enabled |
| Disable Catchup Quick Scan | Disabled | Disabled, Enabled |
| Enable Low CPU Priority | Enabled | Disabled, Enabled |
| Enable Network Protection | Enabled (block mode) | Disabled, Enabled (block mode), Enabled (audit mode) |
| PUA Protection | PUA Protection on. Detected items are blocked. They will show in history along with other threats. | PUA Protection off. Windows Defender will not protect against potentially unwanted applications., PUA Protection on. Detected items are blocked. They will show in history along with other threats., Audit mode. Windows Defender will detect potentially unwanted applications, but take no action. You can review information about the applications Windows Defender would have taken action against by searching for events created by Windows Defender in the Event Viewer. |
| Real Time Scan Direction | Monitor all files (bi-directional). | Monitor all files (bi-directional)., Monitor incoming files., Monitor outgoing files. |
| Scan Parameter | Quick scan | Quick scan, Full scan |
| Schedule Quick Scan Time | 1080 | number 0 to 1380 |
| Schedule Scan Day | Every day | Every day, Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, No scheduled scan |
| Allow On Access Protection | Allowed. | Not allowed., Allowed. |
| Disable Dns Over Tcp Parsing | DNS over TCP parsing is enabled | DNS over TCP parsing is disabled, DNS over TCP parsing is enabled |
| Disable Http Parsing | HTTP parsing is enabled | HTTP parsing is disabled, HTTP parsing is enabled |
| Allow Datagram Processing On Win Server | Datagram processing on Windows Server is enabled. | Datagram processing on Windows Server is enabled., Datagram processing on Windows Server is disabled. |
| Allow Network Protection Down Level | Network protection will be enabled downlevel. | Network protection will be enabled downlevel., Network protection will be disabled downlevel. |

</details>

### B365E | macOS-Endpoint-Antivirus-Defender Configuration v1.0

Microsoft Defender Antivirus settings for Macs.

- **File:** `defender/json/B365E macOS-Endpoint-Antivirus-Defender Configuration v1.0.json`
- **Platform:** macOS
- **Settings:** 19
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Enable / disable cloud delivered protection | Enabled | Disabled, Enabled |
| Enable / disable automatic sample submissions | Enabled | Disabled, Enabled |
| Automatic security intelligence updates | Enabled | Disabled, Enabled |
| Diagnostic collection level | optional | optional, required |
| Enable real-time protection (deprecated) | Enabled | Disabled, Enabled |
| Scan results retention | 30 | number 1 to 180 |
| Exclusions merge | admin_only | merge, admin_only |
| Threat type settings | (group) |  |
| &nbsp;&nbsp;Threat type | potentially_unwanted_application | potentially_unwanted_application, archive_bomb |
| &nbsp;&nbsp;Action to take | block | audit, block, off |
| &nbsp;&nbsp;Threat type | archive_bomb | potentially_unwanted_application, archive_bomb |
| &nbsp;&nbsp;Action to take | audit | audit, block, off |
| Threat type settings merge | admin_only | merge, admin_only |
| Run a scan after definitions are updated | Enabled | Disabled, Enabled |
| Scanning inside archive files | True | False, True |
| Enforcement level | passive | passive, on_demand, real_time |
| Enforcement level | block | disabled, audit, block |
| Enforcement level | block | disabled, audit, block |
| Show / hide status menu icon | Enabled | Disabled, Enabled |

</details>

### Microsoft Defender MacOS Antivirus

An older Mac antivirus policy. Overlaps the B365E macOS antivirus policy; use one per device group.

- **File:** `defender/json/Microsoft Defender MacOS Antivirus.json`
- **Platform:** macOS
- **Settings:** 21
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Enable / disable cloud delivered protection | Enabled | Disabled, Enabled |
| Enable / disable automatic sample submissions | Enabled | Disabled, Enabled |
| Diagnostic collection level | optional | optional, required |
| Automatic security intelligence updates | Enabled | Disabled, Enabled |
| Threat type settings | (group) |  |
| &nbsp;&nbsp;Threat type | potentially_unwanted_application | potentially_unwanted_application, archive_bomb |
| &nbsp;&nbsp;Action to take | block | audit, block, off |
| &nbsp;&nbsp;Threat type | archive_bomb | potentially_unwanted_application, archive_bomb |
| &nbsp;&nbsp;Action to take | block | audit, block, off |
| Enable file hash computation | False | False, True |
| Run a scan after definitions are updated | Enabled | Disabled, Enabled |
| Scanning inside archive files | True | False, True |
| Enforcement level | real_time | passive, on_demand, real_time |
| Enforcement level | audit | disabled, audit, block |
| Enforcement level | block | disabled, audit, block |
| Control sign-in to consumer version | enabled | enabled, disabled |
| Show / hide status menu icon | Disabled | Disabled, Enabled |
| User initiated feedback | enabled | enabled, disabled |
| Scan results retention | 90 | number 1 to 180 |
| Scan history size | 10000 | number 5000 to 15000 |
| Degree of parallelism for on-demand scans | 2 | number 1 to 64 |

</details>

### Microsoft Defender

An older, general Microsoft Defender Antivirus policy for Windows. Overlaps the B365E W10/11 antivirus policy; use one per device group.

- **File:** `defender/json/Microsoft Defender.json`
- **Platform:** windows10
- **Settings:** 23
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Allow Archive Scanning | Allowed. Scans the archive files. | Not allowed. Turns off scanning on archived files., Allowed. Scans the archive files. |
| Allow Behavior Monitoring | Allowed. Turns on real-time behavior monitoring. | Not allowed. Turns off behavior monitoring., Allowed. Turns on real-time behavior monitoring. |
| Allow Cloud Protection | Allowed. Turns on Cloud Protection. | Not allowed. Turns off Cloud Protection., Allowed. Turns on Cloud Protection. |
| Allow Email Scanning | Allowed. Turns on email scanning. | Not allowed. Turns off email scanning., Allowed. Turns on email scanning. |
| Allow Full Scan On Mapped Network Drives | Not allowed. Disables scanning on mapped network drives. | Not allowed. Disables scanning on mapped network drives., Allowed. Scans mapped network drives. |
| Allow Full Scan Removable Drive Scanning | Allowed. Scans removable drives. | Not allowed. Turns off scanning on removable drives., Allowed. Scans removable drives. |
| [Deprecated] Allow Intrusion Prevention System | Allowed. | Not allowed., Allowed. |
| Allow scanning of all downloaded files and attachments | Allowed. | Not allowed., Allowed. |
| Allow Realtime Monitoring | Allowed. Turns on and runs the real-time monitoring service. | Not allowed. Turns off the real-time monitoring service., Allowed. Turns on and runs the real-time monitoring service. |
| Allow Scanning Network Files | Not allowed. Turns off scanning of network files. | Not allowed. Turns off scanning of network files., Allowed. Scans network files. |
| Allow Script Scanning | Allowed. | Not allowed., Allowed. |
| Allow User UI Access | Allowed. Lets users access UI. | Not allowed. Prevents users from accessing UI., Allowed. Lets users access UI. |
| Check For Signatures Before Running Scan | Enabled | Disabled, Enabled |
| Cloud Block Level | High Plus | Default State, High, High Plus, Zero Tolerance |
| Days To Retain Cleaned Malware | 7 | number 0 to 90 |
| Enable Network Protection | Enabled (block mode) | Disabled, Enabled (block mode), Enabled (audit mode) |
| PUA Protection | PUA Protection on. Detected items are blocked. They will show in history along with other threats. | PUA Protection off. Windows Defender will not protect against potentially unwanted applications., PUA Protection on. Detected items are blocked. They will show in history along with other threats., Audit mode. Windows Defender will detect potentially unwanted applications, but take no action. You can review information about the applications Windows Defender would have taken action against by searching for events created by Windows Defender in the Event Viewer. |
| Real Time Scan Direction | Monitor all files (bi-directional). | Monitor all files (bi-directional)., Monitor incoming files., Monitor outgoing files. |
| Scan Parameter | Quick scan | Quick scan, Full scan |
| Schedule Quick Scan Time | 1080 | number 0 to 1380 |
| Schedule Scan Day | Every day | Every day, Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, No scheduled scan |
| Schedule Scan Time | 120 | number 0 to 1380 |
| Cloud Extended Timeout | 50 | number 0 to 50 |

</details>

### Windows 10 & Later LAPS

Windows LAPS: gives every device a unique local administrator password that rotates and is stored in Entra ID.

- **File:** `defender/json/Windows 10 & Later LAPS.json`
- **Platform:** windows10
- **Settings:** 1
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Backup Directory  | Backup the password to Microsoft Entra ID only | Disabled (password will not be backed up), Backup the password to Microsoft Entra ID only, Backup the password to Active Directory only |

</details>

### Windows 10 and Later

Onboards Windows devices to Microsoft Defender for Endpoint (EDR). Needs the Intune to Defender for Endpoint connector turned on in the tenant.

- **File:** `defender/json/Windows 10 and Later.json`
- **Platform:** windows10
- **Settings:** 1
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Microsoft Defender for Endpoint client configuration package type | Auto from connector | Auto from connector, Onboard, Offboard |

</details>

## Intune templates

### Default iOS/iPadOS Settings

Basic iPhone and iPad restrictions, passcode rules, and a lock screen message.

- **File:** `intune/json/Default iOS_iPadOS Settings.json`
- **Platform:** iOS
- **Settings:** 9
- **Placeholders:** `LOCK_SCREEN_MESSAGE`

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Top Level Setting Group Collection | (group) |  |
| &nbsp;&nbsp;Allow Account Modification | True | False, True |
| &nbsp;&nbsp;Allow App Installation | True | False, True |
| &nbsp;&nbsp;Allow App Removal | True | False, True |
| Top Level Setting Group Collection | (group) |  |
| &nbsp;&nbsp;Allow Simple Passcode | True | False, True |
| &nbsp;&nbsp;Min Length | 16 | number 0 to 16 |
| Top Level Setting Group Collection | (group) |  |
| &nbsp;&nbsp;Lock Screen Footnote | ${LOCK_SCREEN_MESSAGE} | text (up to 1032 characters) |

</details>

### Microsoft Defender MacOS

Allows the Defender for Endpoint system and network extensions on Macs, so Defender can run without user prompts.

- **File:** `intune/json/Microsoft Defender MacOS.json`
- **Platform:** macOS
- **Settings:** 4
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Top Level Setting Group Collection | (group) |  |
| &nbsp;&nbsp;Allowed System Extensions | (group) |  |
| &nbsp;&nbsp;&nbsp;&nbsp;Allowed System Extensions | com.microsoft.wdav.epsext	, com.microsoft.wdav.netext	 | text (up to 1032 characters) |
| &nbsp;&nbsp;&nbsp;&nbsp;Team Identifier | UBF8T346G9 | text (up to 1032 characters) |

</details>

### Visual Studio Updates

Controls automatic updates for Visual Studio on Windows.

- **File:** `intune/json/Visual Studio Updates.json`
- **Platform:** windows10
- **Settings:** 2
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Allow standard users to execute installer operations | Enabled | Disabled, Enabled |
| &nbsp;&nbsp;Define which installer commands Standard Users can execute | Enabled for Update and Rollback | Enabled for Update and Rollback, Enabled for all installer operations |

</details>

### Windows 10 & Later Configuration Profile

A broad Windows settings profile (67 settings), mostly Windows Firewall options. Overlaps the B365E firewall policy; review before deploying both.

- **File:** `intune/json/Windows 10 & Later Configuration Profile.json`
- **Platform:** windows10
- **Settings:** 67
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| [Deprecated] Allow Intrusion Prevention System | Allowed. | Not allowed., Allowed. |
| Allow Archive Scanning | Allowed. Scans the archive files. | Not allowed. Turns off scanning on archived files., Allowed. Scans the archive files. |
| Allow Behavior Monitoring | Allowed. Turns on real-time behavior monitoring. | Not allowed. Turns off behavior monitoring., Allowed. Turns on real-time behavior monitoring. |
| Allow Cloud Protection | Allowed. Turns on Cloud Protection. | Not allowed. Turns off Cloud Protection., Allowed. Turns on Cloud Protection. |
| Allow Email Scanning | Allowed. Turns on email scanning. | Not allowed. Turns off email scanning., Allowed. Turns on email scanning. |
| Allow Full Scan On Mapped Network Drives | Not allowed. Disables scanning on mapped network drives. | Not allowed. Disables scanning on mapped network drives., Allowed. Scans mapped network drives. |
| Allow Full Scan Removable Drive Scanning | Allowed. Scans removable drives. | Not allowed. Turns off scanning on removable drives., Allowed. Scans removable drives. |
| Allow On Access Protection | Allowed. | Not allowed., Allowed. |
| Allow Realtime Monitoring | Allowed. Turns on and runs the real-time monitoring service. | Not allowed. Turns off the real-time monitoring service., Allowed. Turns on and runs the real-time monitoring service. |
| Allow Scanning Network Files | Not allowed. Turns off scanning of network files. | Not allowed. Turns off scanning of network files., Allowed. Scans network files. |
| Allow scanning of all downloaded files and attachments | Allowed. | Not allowed., Allowed. |
| Allow Script Scanning | Allowed. | Not allowed., Allowed. |
| Allow User UI Access | Allowed. Lets users access UI. | Not allowed. Prevents users from accessing UI., Allowed. Lets users access UI. |
| Enable Network Protection | Enabled (block mode) | Disabled, Enabled (block mode), Enabled (audit mode) |
| Real Time Scan Direction | Monitor all files (bi-directional). | Monitor all files (bi-directional)., Monitor incoming files., Monitor outgoing files. |
| Enable Domain Network Firewall | True | False, True |
| &nbsp;&nbsp;Allow Local Ipsec Policy Merge | True | False, True |
| &nbsp;&nbsp;Allow Local Policy Merge | True | False, True |
| &nbsp;&nbsp;Auth Apps Allow User Pref Merge | True | False, True |
| &nbsp;&nbsp;Default Inbound Action for Domain Profile | Block | Allow, Block |
| &nbsp;&nbsp;Default Outbound Action | Allow | Allow, Block |
| &nbsp;&nbsp;Disable Inbound Notifications | False | False, True |
| &nbsp;&nbsp;Disable Stealth Mode | False | False, True |
| &nbsp;&nbsp;Disable Stealth Mode Ipsec Secured Packet Exemption | True | False, True |
| &nbsp;&nbsp;Disable Unicast Responses To Multicast Broadcast | False | False, True |
| &nbsp;&nbsp;Enable Log Dropped Packets | Disable Logging Of Dropped Packets | Disable Logging Of Dropped Packets, Enable Logging Of Dropped Packets |
| &nbsp;&nbsp;Enable Log Ignored Rules | Disable Logging Of Ignored Rules | Disable Logging Of Ignored Rules, Enable Logging Of Ignored Rules |
| &nbsp;&nbsp;Enable Log Success Connections | Disable Logging Of Successful Connections | Disable Logging Of Successful Connections, Enable Logging Of Successful Connections |
| &nbsp;&nbsp;Global Ports Allow User Pref Merge | True | False, True |
| &nbsp;&nbsp;Log File Path | %systemroot%\system32\LogFiles\Firewall\pfirewall.log | text (up to 87516 characters) |
| &nbsp;&nbsp;Log Max File Size | 1024 | number 0 to 4294967295 |
| &nbsp;&nbsp;Shielded | False | False, True |
| Enable Private Network Firewall | True | False, True |
| &nbsp;&nbsp;Allow Local Ipsec Policy Merge | True | False, True |
| &nbsp;&nbsp;Allow Local Policy Merge | True | False, True |
| &nbsp;&nbsp;Auth Apps Allow User Pref Merge | True | False, True |
| &nbsp;&nbsp;Default Inbound Action for Private Profile | Block | Allow, Block |
| &nbsp;&nbsp;Default Outbound Action | Allow | Allow, Block |
| &nbsp;&nbsp;Disable Inbound Notifications | False | False, True |
| &nbsp;&nbsp;Disable Stealth Mode | False | False, True |
| &nbsp;&nbsp;Disable Stealth Mode Ipsec Secured Packet Exemption | True | False, True |
| &nbsp;&nbsp;Disable Unicast Responses To Multicast Broadcast | False | False, True |
| &nbsp;&nbsp;Enable Log Dropped Packets | Disable Logging Of Dropped Packets | Disable Logging Of Dropped Packets, Enable Logging Of Dropped Packets |
| &nbsp;&nbsp;Enable Log Ignored Rules | Disable Logging Of Ignored Rules | Disable Logging Of Ignored Rules, Enable Logging Of Ignored Rules |
| &nbsp;&nbsp;Enable Log Success Connections | Disable Logging Of Successful Connections | Disable Logging Of Successful Connections, Enable Logging Of Successful Connections |
| &nbsp;&nbsp;Global Ports Allow User Pref Merge | True | False, True |
| &nbsp;&nbsp;Log File Path | %systemroot%\system32\LogFiles\Firewall\pfirewall.log | text (up to 87516 characters) |
| &nbsp;&nbsp;Log Max File Size | 1024 | number 0 to 4294967295 |
| &nbsp;&nbsp;Shielded | False | False, True |
| Enable Public Network Firewall | True | False, True |
| &nbsp;&nbsp;Allow Local Ipsec Policy Merge | True | False, True |
| &nbsp;&nbsp;Allow Local Policy Merge | True | False, True |
| &nbsp;&nbsp;Auth Apps Allow User Pref Merge | True | False, True |
| &nbsp;&nbsp;Default Inbound Action for Public Profile | Block | Allow, Block |
| &nbsp;&nbsp;Default Outbound Action | Allow | Allow, Block |
| &nbsp;&nbsp;Disable Inbound Notifications | False | False, True |
| &nbsp;&nbsp;Disable Stealth Mode | False | False, True |
| &nbsp;&nbsp;Disable Stealth Mode Ipsec Secured Packet Exemption | True | False, True |
| &nbsp;&nbsp;Disable Unicast Responses To Multicast Broadcast | False | False, True |
| &nbsp;&nbsp;Enable Log Dropped Packets | Disable Logging Of Dropped Packets | Disable Logging Of Dropped Packets, Enable Logging Of Dropped Packets |
| &nbsp;&nbsp;Enable Log Ignored Rules | Disable Logging Of Ignored Rules | Disable Logging Of Ignored Rules, Enable Logging Of Ignored Rules |
| &nbsp;&nbsp;Enable Log Success Connections | Disable Logging Of Successful Connections | Disable Logging Of Successful Connections, Enable Logging Of Successful Connections |
| &nbsp;&nbsp;Global Ports Allow User Pref Merge | True | False, True |
| &nbsp;&nbsp;Log File Path | %systemroot%\system32\LogFiles\Firewall\pfirewall.log | text (up to 87516 characters) |
| &nbsp;&nbsp;Log Max File Size | 1024 | number 0 to 4294967295 |
| &nbsp;&nbsp;Shielded | False | False, True |
| Accounts Enable Administrator Account Status | Enable | Enable, Disable |

</details>

### macOS - Platform SSO

Platform single sign-on for Macs, so users sign in to the Mac with their Entra ID account.

- **File:** `intune/json/macOS - Platform SSO.json`
- **Platform:** macOS
- **Settings:** 15
- **Placeholders:** none

<details><summary>Every setting, its configured value, and the allowed values</summary>

| Setting | Configured | Possible values |
|---|---|---|
| Top Level Setting Group Collection | (group) |  |
| &nbsp;&nbsp;Authentication Method (Deprecated) | Password | Password, UserSecureEnclaveKey |
| &nbsp;&nbsp;Extension Identifier | com.microsoft.CompanyPortalMac.ssoextension | text (up to 1032 characters) |
| &nbsp;&nbsp;Platform SSO | (group) |  |
| &nbsp;&nbsp;&nbsp;&nbsp;Authentication Method | UserSecureEnclaveKey | Password, UserSecureEnclaveKey, SmartCard |
| &nbsp;&nbsp;&nbsp;&nbsp;FileVault Policy | AttemptAuthentication | text (up to 1032 characters) |
| &nbsp;&nbsp;&nbsp;&nbsp;Token To User Mapping | (group) |  |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Account Name | preferred_username | text (up to 1032 characters) |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Full Name | name | text (up to 1032 characters) |
| &nbsp;&nbsp;&nbsp;&nbsp;Use Shared Device Keys | Enabled | Disabled, Enabled |
| &nbsp;&nbsp;Registration Token | {{DEVICEREGISTRATION}} | text (up to 1032 characters) |
| &nbsp;&nbsp;Screen Locked Behavior | Do Not Handle | Do Not Handle |
| &nbsp;&nbsp;Team Identifier | UBF8T346G9 | text (up to 1032 characters) |
| &nbsp;&nbsp;Type | Redirect | Credential, Redirect |
| &nbsp;&nbsp;URLs | https://login.microsoftonline.com, https://login.microsoft.com, https://sts.windows.net | text (up to 1032 characters) |

</details>

