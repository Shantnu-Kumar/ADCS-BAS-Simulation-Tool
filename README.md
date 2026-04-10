# ADCS-BAS-Simulation-Tool
Description: AD CS NPA Prelogon Misconfiguration Simulation Tool  This Python-based tool performs a safe security assessment simulation of Active Directory Certificate Services (AD CS) certificate templates to identify potential NPA (Network Policy Authentication) pre-logon misconfigurations and related certificate abuse risks.

**Breach & Attack Simulation (BAS)** framework for analyzing **Active Directory Certificate Services (ADCS)** misconfigurations, focusing on:

> ⚠️ Machine certificate template abuse & NPA pre-logon attack paths

## 🚀 Features
- LDAP-based ADCS template discovery (safe fallback mode supported)
- Detection of certificate misconfigurations (ESC1-style logic)
- Exploitability scoring engine (LOW / MEDIUM / HIGH)
- Safe attack simulation (no real exploitation)
- MITRE ATT&CK mapping:
  - T1550.003 – Pass-the-Certificate
  - T1649 – Certificate Theft / Forgery
- Microsoft Defender log validation
- Excel report generation
-----------------------------------------------------------------------------------------------
## 📦 Requirements
pip install pandas openpyxl
