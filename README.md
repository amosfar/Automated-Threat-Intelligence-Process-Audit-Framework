<div align="center">

# 🔐 Automated Threat Intelligence Process Audit Framework

### Windows process auditing + VirusTotal enrichment

A lightweight security workflow that collects running process metadata from a Windows host, computes SHA256 hashes, and cross-checks them against VirusTotal for potential malicious indicators.

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## Overview

This project automates a practical threat-hunting workflow:

1. A PowerShell script inventories running processes.
2. It extracts process metadata and SHA256 hashes.
3. A Python script reads the JSON report and queries VirusTotal for each hash.
4. The result is a structured threat report that highlights suspicious or malicious binaries.

This is designed as a simple, educational security auditing framework for local host investigation and enrichment workflows.

## Architecture

```text
Windows Process List
        ↓
process_audit.ps1
        ↓
process_report.json
        ↓
threat_intel.py
        ↓
VirusTotal API lookup
        ↓
threat_report.json
```

## Workflow

### 1) Process collection
`process_audit.ps1` gathers:

- Process name
- PID
- Memory usage
- Executable path
- Start time
- SHA256 hash

It exports the data to `process_report.json`.

### 2) Threat intelligence enrichment
`threat_intel.py` reads the JSON report and queries VirusTotal for each file hash using the API key in `config.ini`.

It then produces a summary with:

- `MaliciousHits` counts from VirusTotal
- Clean or suspicious classifications
- Final structured output saved to `threat_report.json`

## Repository structure

```text
.
├── LICENSE
├── README.md
├── config.ini
├── config.example.ini
├── process_audit.ps1
├── process_report.json
├── threat_intel.py
├── threat_report.json
└── .gitignore
```

## Quick start

### Requirements

- Windows PowerShell 5.1+
- Python 3.9+
- A valid VirusTotal API key
- `requests` Python package

Install the Python dependency:

```bash
pip install requests
```

### 1) Configure your API key

Copy the example config and replace the placeholder:

```bash
copy config.example.ini config.ini
```

Then edit `config.ini`:

```ini
[API]
virustotal_key = YOUR_API_KEY_HERE

[FILES]
input_json = process_report.json
output_json = threat_report.json
```

### 2) Run the PowerShell audit

From the repository root:

```powershell
./process_audit.ps1
```

This creates `process_report.json`.

### 3) Run the threat intelligence check

```bash
python threat_intel.py
```

The script reads the process report and writes the enriched results to `threat_report.json`.

## Output

The JSON output is structured similarly to this:

```json
[
  {
    "Process": "chrome.exe",
    "PID": 4321,
    "MemoryMB": 254.76,
    "Hash": "abc123...",
    "MaliciousHits": 12
  }
]
```

A malicious process will be flagged when `MaliciousHits > 0`.

## Notes

- This framework is intended for research, education, and defensive investigation workflows.
- VirusTotal API usage is subject to the provider’s rate limits and API terms.
- The project uses a local cache pattern to reduce duplicate lookups during analysis.
- Use this responsibly and only against systems or data you are authorized to inspect.

## License

This project is distributed under the [MIT License](LICENSE).
