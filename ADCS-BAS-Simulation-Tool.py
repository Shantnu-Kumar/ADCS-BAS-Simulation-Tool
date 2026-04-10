import subprocess
import json
import pandas as pd
from datetime import datetime

OUTPUT_FILE = "ADCS_BAS_Report.xlsx"

MITRE = {
    "ESC1": ["T1550.003", "T1649"]
}

# -----------------------------
# POWERSHELL RUNNER
# -----------------------------
def run_ps(script):
    result = subprocess.run(
        ["powershell", "-Command", script],
        capture_output=True,
        text=True
    )
    return result.stdout.strip(), result.stderr.strip()

# -----------------------------
# FALLBACK LDAP ENUM (NO AD MODULE)
# -----------------------------
def get_templates_ldap():
    ps_script = r'''
    $root = [ADSI]"LDAP://RootDSE"
    $config = $root.configurationNamingContext
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$config"
    $searcher.Filter = "(objectClass=pKICertificateTemplate)"
    $searcher.PropertiesToLoad.Add("displayName") | Out-Null
    $searcher.PropertiesToLoad.Add("msPKI-Certificate-Name-Flag") | Out-Null
    $searcher.PropertiesToLoad.Add("pKIExtendedKeyUsage") | Out-Null

    $results = $searcher.FindAll()

    $output = @()

    foreach ($r in $results) {
        $obj = @{
            displayName = $r.Properties["displayname"]
            NameFlag = $r.Properties["msPKI-Certificate-Name-Flag"]
            EKU = $r.Properties["pkiextendedkeyusage"]
        }
        $output += $obj
    }

    $output | ConvertTo-Json -Depth 3
    '''
    out, err = run_ps(ps_script)

    if err:
        print("[!] LDAP fallback error:", err)

    try:
        return json.loads(out)
    except:
        return []

# -----------------------------
# FLAG DECODER
# -----------------------------
def decode_flags(val):
    flags = []
    if not val:
        return flags

    v = int(val[0])
    if v & 0x1:
        flags.append("ENROLLEE_SUPPLIES_SUBJECT")

    return flags

# -----------------------------
# EKU PARSER
# -----------------------------
def parse_eku(eku):
    if not eku:
        return []

    eku_map = {
        "1.3.6.1.5.5.7.3.2": "ClientAuth",
        "1.3.6.1.5.5.7.3.1": "ServerAuth"
    }

    return [eku_map.get(e, e) for e in eku]

# -----------------------------
# SIMULATED ACL (SAFE MODE)
# -----------------------------
def simulate_acl():
    # simulate weak ACL scenario
    return ["Authenticated Users"]

# -----------------------------
# EXPLOITABILITY ENGINE
# -----------------------------
def check_exploitability(flags, eku, acl, name):
    if "ENROLLEE_SUPPLIES_SUBJECT" in flags and "ClientAuth" in eku and acl:
        return True, "HIGH", "ESC1 fully exploitable"

    if "ClientAuth" in eku and acl:
        return True, "MEDIUM", "Partial abuse possible"

    return False, "LOW", "Not exploitable"

# -----------------------------
# SAFE EXPLOIT SIMULATION
# -----------------------------
def simulate_exploit(name):
    # This is SAFE BAS simulation (no real attack)
    return f"Simulated cert request for template: {name}"

# -----------------------------
# DEFENDER LOG CHECK
# -----------------------------
def check_logs():
    ps_script = r'''
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 5 |
    Select-Object Id, TimeCreated | ConvertTo-Json
    '''
    out, err = run_ps(ps_script)

    if err or not out:
        return "No logs"

    return "Logs Found"

# -----------------------------
# MAIN ANALYSIS
# -----------------------------
def analyze():
    print("[*] Running Safe BAS Simulation...")

    templates = get_templates_ldap()

    if not templates:
        print("[!] No templates found — switching to simulated dataset")
        templates = [
            {
                "displayName": "Vuln-Machine",
                "NameFlag": [1],
                "EKU": ["1.3.6.1.5.5.7.3.2"]
            }
        ]

    results = []

    for t in templates:
        name = t.get("displayName", ["Unknown"])[0]

        flags = decode_flags(t.get("NameFlag"))
        eku = parse_eku(t.get("EKU"))
        acl = simulate_acl()

        exploitable, confidence, reason = check_exploitability(flags, eku, acl, name)

        exploit_result = simulate_exploit(name)

        findings = []
        mitre = []

        if exploitable:
            findings.append("ESC1 Misconfiguration")
            mitre = MITRE["ESC1"]

        results.append({
            "Template": name,
            "Flags": ", ".join(flags),
            "EKU": ", ".join(eku),
            "ACL": ", ".join(acl),
            "Findings": "; ".join(findings),
            "MITRE": ", ".join(mitre),
            "Exploitable": "YES" if exploitable else "NO",
            "Confidence": confidence,
            "Exploit Simulation": exploit_result,
            "Defender Logs": check_logs()
        })

    return results

# -----------------------------
# EXPORT REPORT
# -----------------------------
def export_excel(data):
    df = pd.DataFrame(data)
    df.to_excel(OUTPUT_FILE, index=False)
    print(f"[+] Report generated: {OUTPUT_FILE}")

# -----------------------------
# ENTRY
# -----------------------------
if __name__ == "__main__":
    data = analyze()
    export_excel(data)
