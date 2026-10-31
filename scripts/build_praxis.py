#!/usr/bin/env python3
"""Builds the Praxis template set from one spec.

Every setting in a Praxis template is chosen from the operator's own library of
security books and courses (the praxis corpus). Each one records where the
choice came from:

  library     the corpus says so; citations give course and passage id
  microsoft   the corpus agrees the control should exist but gives no value;
              Microsoft's own baseline or template supplies the number
  judgement   the corpus gives a range or two options; the pick is explained

The spec below is the single source. This script writes the deployable policy
JSON (internal/catalog/files/praxis) and the provenance the console shows
beside every setting (internal/praxisprov/provenance.json). Edit the spec, not
the outputs.
"""
import json, os, sqlite3, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "internal/catalog/files/praxis")
PROV = os.path.join(ROOT, "internal/praxisprov/provenance.json")

# ---- citations: passages from the praxis corpus, by id -------------------------
C = {
    "ab900_packt_session":  {"course": "Packt AB-900 Microsoft 365 Copilot and Agent Administration 2026", "passage": 793717},
    "ab900_packt_legacy":   {"course": "Packt AB-900 Microsoft 365 Copilot and Agent Administration 2026", "passage": 793717},
    "ab900_packt_browser":  {"course": "Packt AB-900 Microsoft 365 Copilot and Agent Administration 2026", "passage": 793718},
    "ab900_packt_cae":      {"course": "Packt AB-900 Microsoft 365 Copilot and Agent Administration 2026", "passage": 793718},
    "ab900_packt_reportonly": {"course": "Packt AB-900 Microsoft 365 Copilot and Agent Administration 2026", "passage": 793718},
    "ab900_ps_sms":         {"course": "Pluralsight AB-900 Identify the Core Features and Objects of Microsoft 365 Services 2026", "passage": 1245882},
    "ab900_authenticator":  {"course": "Packt AB-900 Microsoft 365 Copilot and Agent Administration 2026", "passage": 793697},
    "secops_defaults":      {"course": "Packt Unified SecOps Playbook with Microsoft Sentinel, Defender XDR and Security Copilot 2025", "passage": 3118285},
    "ransomware_fido":      {"course": "O'Reilly Learning Ransomware Response and Recovery 2026", "passage": 3107020},
    "ransomware_admins":    {"course": "O'Reilly Learning Ransomware Response and Recovery 2026", "passage": 3107019},
    "zt_fido":              {"course": "O'Reilly Zero Trust Networks 2nd Edition 2024", "passage": 3113654},
    "az500_risk":           {"course": "AZ-500 Microsoft Azure Security Technologies", "passage": 3189606},
    "sc200_risk":           {"course": "SC-200 Microsoft Security Operations Analyst", "passage": 842732},
    "az500_device":         {"course": "AZ-500 Microsoft Azure Security Technologies", "passage": 3189603},
    "ab900_device":         {"course": "Packt AB-900 Microsoft 365 Copilot and Agent Administration 2026", "passage": 793717},
    "enroll_mobile":        {"course": "Pluralsight Device Enrollment Strategies in Microsoft Intune 2026", "passage": 814164},
    "cookbook_locations":   {"course": "Azure Security Cookbook", "passage": 3200615},
    "sharepoint_guests":    {"course": "Pluralsight SharePoint Fundamentals and Architecture 2026", "passage": 817648},
    "sc200_asr":            {"course": "SC-200 Microsoft Security Operations Analyst", "passage": 842706},
    "intune_ops_pilot":     {"course": "Pluralsight Reporting, Monitoring and Intune Operations at Scale 2026", "passage": 974615},
    "config_av":            {"course": "Pluralsight Configuration Profiles and Settings Management in Microsoft Intune 2026", "passage": 3155528},
    "copilot_av_bad":       {"course": "Packt Microsoft Security Copilot 2025", "passage": 3114712},
    "small_net_rtp":        {"course": "Cybersecurity for Small Networks", "passage": 1147175},
    "practical_laps":       {"course": "Practical Security: Simple Practices for Defending Your Systems", "passage": 1251773},
}

def cite(*keys):
    return [dict(C[k], key=k) for k in keys]

# Microsoft's own admin role list, from its phishing-resistant admin template.
ADMIN_ROLES = ["62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "29232cdf-9323-42fd-ade2-1d097af3e4de", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", "fe930be7-5e62-47db-91af-98c3a49a38b1", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "158c047a-c907-4556-b7ef-446551a6b5f7", "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "e8611ab8-c189-46e8-94e1-60213ab1f814", "17315797-102d-40b4-93e0-432062caca18",
    "e6d1a23a-da11-4be4-9570-befc86d067a7", "3a2c62db-5318-420d-8d74-23affee5d9d5", "44367163-eba1-44c3-98af-f5787879f96a",
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc"]

BG = "${EMERGENCY_ACCESS_GROUP_ID}"
REPORT_ONLY = "enabledForReportingButNotEnforced"
EVERY_TIME = {"isEnabled": True, "authenticationType": "primaryAndSecondaryAuthentication", "frequencyInterval": "everyTime"}

def users(include=None, roles=None, groups=None, exclude_groups=()):
    u = {"excludeGroups": [BG, *exclude_groups]}
    if include: u["includeUsers"] = include
    if roles: u["includeRoles"] = roles
    if groups: u["includeGroups"] = groups
    return u

def ca(code, title, conditions, grant=None, session=None):
    doc = {"displayName": f"Praxis | {code} - {title}", "state": REPORT_ONLY, "conditions": conditions}
    if grant: doc["grantControls"] = grant
    if session: doc["sessionControls"] = session
    return doc

ALL_APPS = {"includeApplications": ["All"]}

# ---- the Conditional Access spec ------------------------------------------------
CA = [
 {"file": "P01 - Require MFA for all users on every platform",
  "why": "Replaces C001. Same intent, but phones are included: the library's answer for phones is app protection (P11), not an exemption from MFA.",
  "body": ca("P01", "Require MFA for all users on every platform",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["all"]},
             {"operator": "OR", "builtInControls": ["mfa"]}),
  "settings": [
    {"setting": "Require MFA for every user", "value": "grant: MFA", "source": "library", "citations": cite("secops_defaults", "ab900_ps_sms")},
    {"setting": "No platform exclusions", "value": "all platforms, phones included", "source": "library", "citations": cite("enroll_mobile"),
     "note": "C001 excluded Android and iOS. The library protects phones with app protection policies instead, see P11."},
  ]},
 {"file": "P02 - Require phishing-resistant MFA for administrators",
  "why": "Replaces C003a and C003b. C003b was named phishing-resistant but granted ordinary MFA, which accepts SMS.",
  "body": ca("P02", "Require phishing-resistant MFA for administrators",
             {"users": users(roles=ADMIN_ROLES), "applications": ALL_APPS, "clientAppTypes": ["all"]},
             {"operator": "AND", "authenticationStrength": {"id": "00000000-0000-0000-0000-000000000004"}}),
  "settings": [
    {"setting": "Authentication strength", "value": "Phishing-resistant MFA (built-in 0004: Windows Hello, FIDO2, certificate)", "source": "library",
     "citations": cite("ransomware_fido", "zt_fido", "ab900_ps_sms")},
    {"setting": "Applies on every administrator sign-in", "value": "all apps, every sign-in", "source": "library", "citations": cite("secops_defaults")},
    {"setting": "Administrator roles covered", "value": "Microsoft's 19-role list", "source": "microsoft",
     "note": "The library says administrators; which roles count as administrator is Microsoft's list from its own phishing-resistant template. C003a covered 11 of Microsoft's 14 MFA roles."},
  ]},
 {"file": "P03 - Block legacy authentication",
  "body": ca("P03", "Block legacy authentication",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["exchangeActiveSync", "other"]},
             {"operator": "OR", "builtInControls": ["block"]}),
  "settings": [
    {"setting": "Block Exchange ActiveSync and other legacy clients", "value": "block", "source": "library", "citations": cite("ab900_packt_legacy", "secops_defaults")},
  ]},
 {"file": "P04 - High-risk users must change password with MFA",
  "requires": "Microsoft Entra ID P2",
  "body": ca("P04", "High-risk users must change password with MFA",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["all"], "userRiskLevels": ["high"]},
             {"operator": "AND", "builtInControls": ["mfa", "passwordChange"]}, {"signInFrequency": EVERY_TIME}),
  "settings": [
    {"setting": "Response to a high-risk user", "value": "allow only with MFA and a password change", "source": "library", "citations": cite("az500_risk", "sc200_risk"),
     "note": "The library gives block or password change. Password change lets a real user recover without a helpdesk call; block is the stricter alternative."},
    {"setting": "Re-authenticate every time", "value": "sign-in frequency: every time", "source": "microsoft",
     "note": "Microsoft's own risk-remediation template sets this; the library is silent on it."},
  ]},
 {"file": "P05 - Block high-risk sign-ins",
  "requires": "Microsoft Entra ID P2",
  "body": ca("P05", "Block high-risk sign-ins",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["all"], "signInRiskLevels": ["high"]},
             {"operator": "OR", "builtInControls": ["block"]}),
  "settings": [
    {"setting": "Response to a high-risk sign-in", "value": "block", "source": "judgement", "citations": cite("sc200_risk"),
     "note": "The library gives block or MFA challenge. High risk gets block and medium gets a challenge (P06); CIS 5.2.2.8 asks for block at both, which this meets at high only."},
  ]},
 {"file": "P06 - Medium-risk sign-ins must re-authenticate with MFA",
  "requires": "Microsoft Entra ID P2",
  "body": ca("P06", "Medium-risk sign-ins must re-authenticate with MFA",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["all"], "signInRiskLevels": ["medium"]},
             {"operator": "OR", "builtInControls": ["mfa"]}, {"signInFrequency": EVERY_TIME}),
  "settings": [
    {"setting": "Response to a medium-risk sign-in", "value": "MFA, every time", "source": "library", "citations": cite("sc200_risk")},
  ]},
 {"file": "P07 - Standard users re-authenticate every 24 hours",
  "body": ca("P07", "Standard users re-authenticate every 24 hours",
             {"users": users(["All"], exclude_groups=["${HIGH_VALUE_GROUP_ID}"]), "applications": ALL_APPS, "clientAppTypes": ["all"]},
             None, {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 24, "authenticationType": "primaryAndSecondaryAuthentication", "frequencyInterval": "timeBased"}}),
  "settings": [
    {"setting": "Sign-in frequency, standard users", "value": "24 hours", "source": "library", "citations": cite("ab900_packt_session")},
  ]},
 {"file": "P08 - High-value users re-authenticate every 4 hours",
  "body": ca("P08", "High-value users re-authenticate every 4 hours",
             {"users": users(groups=["${HIGH_VALUE_GROUP_ID}"]), "applications": ALL_APPS, "clientAppTypes": ["all"]},
             None, {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4, "authenticationType": "primaryAndSecondaryAuthentication", "frequencyInterval": "timeBased"}}),
  "settings": [
    {"setting": "Sign-in frequency, executives and other high-value users", "value": "4 hours", "source": "library", "citations": cite("ab900_packt_session"),
     "note": "Needs a group per client holding the executives, finance and anyone else a phishing campaign would target first."},
  ]},
 {"file": "P09 - No persistent browser sessions on unmanaged devices",
  "body": ca("P09", "No persistent browser sessions on unmanaged devices",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["browser"],
              "devices": {"deviceFilter": {"mode": "exclude", "rule": "device.isCompliant -eq True -or device.trustType -eq \"ServerAD\""}}},
             None, {"persistentBrowser": {"isEnabled": True, "mode": "never"}}),
  "settings": [
    {"setting": "Stay signed in after the browser closes", "value": "never, on devices that are not compliant or hybrid-joined", "source": "library", "citations": cite("ab900_packt_browser")},
  ]},
 {"file": "P10 - Administrators must use a compliant or hybrid-joined device",
  "body": ca("P10", "Administrators must use a compliant or hybrid-joined device",
             {"users": users(roles=ADMIN_ROLES), "applications": ALL_APPS, "clientAppTypes": ["all"]},
             {"operator": "OR", "builtInControls": ["compliantDevice", "domainJoinedDevice"]}),
  "settings": [
    {"setting": "Device requirement for administrators", "value": "compliant or hybrid-joined", "source": "library", "citations": cite("az500_device", "ab900_device", "ransomware_admins")},
  ]},
 {"file": "P11 - Phones must use app protection or be compliant",
  "why": "Closes the phone gap C001 left open, the way the library recommends: protect company data in the app rather than exempt the phone.",
  "body": ca("P11", "Phones must use app protection or be compliant",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["all"],
              "platforms": {"includePlatforms": ["android", "iOS"]}},
             {"operator": "OR", "builtInControls": ["compliantApplication", "compliantDevice"]}),
  "settings": [
    {"setting": "Access from iOS and Android", "value": "app protection policy or compliant device", "source": "library", "citations": cite("enroll_mobile"),
     "note": "Needs Intune app protection policies for iOS and Android assigned to the same users before this is enforced; otherwise phones are simply blocked."},
  ]},
 {"file": "P12 - Require MFA for guests",
  "body": ca("P12", "Require MFA for guests",
             {"users": users(["GuestsOrExternalUsers"]), "applications": ALL_APPS, "clientAppTypes": ["all"]},
             {"operator": "OR", "builtInControls": ["mfa"]}),
  "settings": [
    {"setting": "Guests and external users", "value": "MFA", "source": "library", "citations": cite("sharepoint_guests")},
  ]},
 {"file": "P13 - Block device code flow",
  "body": ca("P13", "Block device code flow",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["all"],
              "authenticationFlows": {"transferMethods": "deviceCodeFlow"}},
             {"operator": "OR", "builtInControls": ["block"]}),
  "settings": [
    {"setting": "Device code sign-in", "value": "block", "source": "microsoft",
     "note": "The library has nothing on device code flow. Microsoft ships this as its own managed policy, and CIS 5.2.2.12 requires it."},
  ]},
 {"file": "P14 - Block sign-in from outside trusted countries",
  "body": ca("P14", "Block sign-in from outside trusted countries",
             {"users": users(["All"], exclude_groups=["${TRAVEL_EXCLUSION_GROUP_ID}"]), "applications": ALL_APPS, "clientAppTypes": ["all"],
              "locations": {"includeLocations": ["All"], "excludeLocations": ["${TRUSTED_COUNTRIES_LOCATION_ID}"]}},
             {"operator": "OR", "builtInControls": ["block"]}),
  "settings": [
    {"setting": "Access from outside the client's countries", "value": "block, with a travel exclusion group", "source": "library", "citations": cite("cookbook_locations"),
     "note": "The library lists location control as a common policy; the trusted list is per client."},
  ]},
 {"file": "P15 - Strictly enforce location in continuous access evaluation",
  "body": ca("P15", "Strictly enforce location in continuous access evaluation",
             {"users": users(["All"]), "applications": ALL_APPS, "clientAppTypes": ["all"]},
             None, {"continuousAccessEvaluation": {"mode": "strictLocation"}}),
  "settings": [
    {"setting": "Continuous access evaluation", "value": "strictly enforce location policies", "source": "library", "citations": cite("ab900_packt_cae"),
     "note": "Revokes sessions as soon as a user is disabled or leaves an allowed location. Clients whose traffic leaves through different IP addresses (split tunnel VPN) need testing in report-only first."},
  ]},
]

# ---- Intune spec, built from Microsoft baseline setting ids --------------------
def load_baselines():
    db = os.environ.get("PC_DATABASE", "/tmp/pc-dev.db")
    row = sqlite3.connect(db).execute("select body from benchmark_cache where source='microsoft-baselines'").fetchone()
    if not row:
        sys.exit("Microsoft baselines are not cached in " + db + "; fetch them in the console first.")
    return json.loads(row[0])

def choice(defid, opt):
    return {"settingInstance": {"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
            "settingDefinitionId": defid, "choiceSettingValue": {"value": opt, "children": []}}}

def simple_int(defid, n):
    return {"settingInstance": {"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": defid, "simpleSettingValue": {"@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue", "value": n}}}

def intune(name, settings, description):
    return {"name": f"Praxis | {name}", "description": description, "platforms": "windows10", "technologies": "mdm,microsoftSense",
            "roleScopeTagIds": ["0"], "settings": settings}

def build_intune(bls):
    mde = next(b for b in bls if b["name"].startswith("Microsoft Defender for Endpoint"))
    labels = {k.lower(): v for k, v in mde["labels"].items()}
    rec = {r["definitionId"]: r for r in mde["recs"]}
    D = "device_vendor_msft_policy_config_defender_"
    def need(defid):
        if defid not in rec:
            sys.exit("setting not in Microsoft's baseline, refusing to guess an id: " + defid)
        return rec[defid]

    # Antivirus: the library decides on/off; Microsoft supplies numbers the library does not give.
    av_spec = [
        ("allowrealtimemonitoring", "library", cite("small_net_rtp", "copilot_av_bad")),
        ("allowcloudprotection", "library", cite("copilot_av_bad", "config_av")),
        ("allowemailscanning", "library", cite("config_av")),
        ("allowscanningnetworkfiles", "library", cite("config_av")),
        ("allowfullscanremovabledrivescanning", "library", cite("config_av")),
        ("allowbehaviormonitoring", "microsoft", []),
        ("allowonaccessprotection", "microsoft", []),
        ("allowioavprotection", "microsoft", []),
        ("allowscriptscanning", "microsoft", []),
        ("puaprotection", "microsoft", []),
        ("enablenetworkprotection", "microsoft", []),
        ("cloudblocklevel", "microsoft", []),
        ("submitsamplesconsent", "microsoft", []),
    ]
    av_settings, av_prov = [], []
    for key, src, cites in av_spec:
        r = need(D + key)
        av_settings.append(choice(r["definitionId"], r["expected"]))
        entry = {"setting": r["name"], "value": r["expectedLabel"], "source": src, "citations": cites}
        if src == "microsoft":
            entry["note"] = "The library does not give a value for this; Microsoft's Defender for Endpoint baseline 24H1 does."
        av_prov.append(entry)
    for key, src in (("cloudextendedtimeout", "microsoft"), ("signatureupdateinterval", "microsoft")):
        r = need(D + key)
        av_settings.append(simple_int(r["definitionId"], int(r["expected"])))
        av_prov.append({"setting": r["name"], "value": r["expected"], "source": src, "citations": [],
                        "note": "Number from Microsoft's Defender for Endpoint baseline 24H1; the library gives none."})
    av_prov.append({"setting": "Tamper protection", "value": "on (set in the Defender portal, not this policy)", "source": "library",
                    "citations": cite("copilot_av_bad"),
                    "note": "Tamper protection is switched on tenant-wide in Microsoft Defender, where the Intune connection is also enabled; it is not a settings catalog value."})

    # ASR: every rule Microsoft's baseline blocks, in Audit, per the library's rollout order.
    asr_children, asr_prov = [], []
    for r in mde["recs"]:
        d = r["definitionId"]
        if not d.startswith(D + "attacksurfacereductionrules_"):
            continue
        audit = r["expected"].rsplit("_", 1)[0] + "_audit"
        if audit.lower() not in labels:
            sys.exit("no audit option for " + d)
        asr_children.append({"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                             "settingDefinitionId": d, "choiceSettingValue": {"value": audit, "children": []}})
        asr_prov.append({"setting": r["name"], "value": "Audit (Microsoft's baseline: " + r["expectedLabel"] + ")", "source": "library",
                         "citations": cite("sc200_asr", "intune_ops_pilot"),
                         "note": "Audit first, then Block once the audit events show no business impact. Graduating a rule to Block is a per-client decision."})
    asr = {"settingInstance": {"@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
           "settingDefinitionId": D + "attacksurfacereductionrules",
           "groupSettingCollectionValue": [{"children": asr_children}]}}

    return [
        ("P20 - Microsoft Defender Antivirus",
         intune("P20 - Microsoft Defender Antivirus", av_settings,
                "Antivirus settings chosen from the praxis library; numbers the library does not give come from Microsoft's Defender for Endpoint baseline."),
         av_prov, "The library is clear that real-time, cloud and tamper protection must be on and scanning must cover email, network and removable drives."),
        ("P21 - Attack surface reduction rules in audit",
         intune("P21 - Attack surface reduction rules in audit", [asr],
                "Every ASR rule Microsoft's baseline blocks, set to Audit first, per the praxis library."),
         asr_prov, "Every rule Microsoft recommends, started in Audit so nothing breaks before the audit events are reviewed."),
    ]

def main():
    prov = {"_about": "Where every Praxis setting came from. Generated by scripts/build_praxis.py; edit the spec there.", "templates": {}}
    for d in ("conditional-access", "intune"):
        os.makedirs(os.path.join(OUT, d), exist_ok=True)
        for f in os.listdir(os.path.join(OUT, d)):
            os.remove(os.path.join(OUT, d, f))
    for t in CA:
        path = os.path.join(OUT, "conditional-access", t["file"] + ".json")
        json.dump(t["body"], open(path, "w"), indent=2)
        prov["templates"][t["body"]["displayName"]] = {"why": t.get("why", ""), "requires": t.get("requires", ""), "settings": t["settings"]}
    for fname, body, settings, why in build_intune(load_baselines()):
        path = os.path.join(OUT, "intune", fname + ".json")
        json.dump(body, open(path, "w"), indent=2)
        prov["templates"][body["name"]] = {"why": why, "requires": "", "settings": settings}
    json.dump(prov, open(PROV, "w"), indent=2)
    counts = {"library": 0, "microsoft": 0, "judgement": 0}
    for t in prov["templates"].values():
        for s in t["settings"]:
            counts[s["source"]] += 1
    print(f"{len(prov['templates'])} Praxis templates, {sum(counts.values())} settings: {counts}")

if __name__ == "__main__":
    main()
