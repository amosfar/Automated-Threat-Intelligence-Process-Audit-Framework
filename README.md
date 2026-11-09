# Automated-Threat-Intelligence-Process-Audit-Framework

A security auditing and threat intelligence framework built using **PowerShell** and **Python** for the Scripting for Security module at TU Dublin.

## 📌 Project Overview
This project bridges local host monitoring with online threat intelligence to identify hazardous processes running on a Windows system. The framework consists of two main stages:
1. **Process Audit (PowerShell):** Gathers live running process metadata, computes SHA256 cryptographic hashes, and outputs the data to a structured JSON file (`process_report.json`).
2. **Threat Intelligence Analysis (Python):** Automatically cross-references process hashes against the **VirusTotal API**, implements caching to optimize performance, and generates a final security report (`threat_report.json`).

---

## 🛠️ Architecture & Workflow

```text
Windows Processes ---> PowerShell Audit Script ---> process_report.json ---> Python Threat Intel (VirusTotal API) ---> threat_report.json
