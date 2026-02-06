# CVE Details Fetcher

A command-line tool to fetch and display comprehensive details for a given Common Vulnerabilities and Exposures (CVE) identifier.

## Description

This tool aggregates information from multiple sources to provide a holistic view of a specific vulnerability. It is designed to help security researchers, analysts, and system administrators quickly gather relevant data to assess the risk and impact of a CVE.

## Features

The tool fetches the following information:

* **CVE Record:** Retrieves the official CVE record from the MITRE Corporation, including the description and CVSS v3.1 base score.
* **CISA KEV Check:** Checks if the CVE is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog.
* **EPSS Score:** Fetches the Exploit Prediction Scoring System (EPSS) score, which estimates the probability of a vulnerability being exploited in the wild.
* **GitHub POCs:** Searches for publicly available Proof-of-Concept (POC) exploits on GitHub.
* **Nessus Coverage:** Lists the relevant Nessus plugins available for detecting the vulnerability.

## Installation

1. Clone the repository or download the `cve_details.py` script.
2. Install the required Python libraries:

    ```bash
    pip install click requests prompt_toolkit beautifulsoup4
    ```

## Usage

Run the script from your terminal, providing a CVE ID as an argument.

```bash
python cve_details.py <CVE_ID>
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output results as JSON (for scripting and integration) |

### Examples

```bash
# Standard colored output
python cve_details.py CVE-2024-1086

# JSON output
python cve_details.py CVE-2024-1086 --json
```

## JSON Output & jq Examples

The `--json` flag outputs structured data for scripting and integration with other tools.

### Basic Queries

```bash
# Get just the CVSS base score
python cve_details.py CVE-2024-1086 --json | jq '.cvss.cvssV3_1.baseScore'

# Get EPSS score and percentile
python cve_details.py CVE-2024-1086 --json | jq '.epss'

# Check if exploited (boolean)
python cve_details.py CVE-2024-1086 --json | jq '.kev.exploited'

# List all POC URLs (one per line)
python cve_details.py CVE-2024-1086 --json | jq -r '.pocs[]'

# Get Nessus plugin IDs only
python cve_details.py CVE-2024-1086 --json | jq '.nessus_plugins[].id'

# Get CWE list as plain text
python cve_details.py CVE-2024-1086 --json | jq -r '.cwe[]'
```

### Formatting & Summaries

```bash
# Compact summary (one-liner)
python cve_details.py CVE-2024-1086 --json | jq -r '"\(.cve_id): CVSS=\(.cvss.cvssV3_1.baseScore // "N/A"), EPSS=\(.epss.percentile)%, Exploited=\(.kev.exploited)"'

# Pretty-print essential fields
python cve_details.py CVE-2024-1086 --json | jq '{cve: .cve_id, title, cvss: .cvss.cvssV3_1.baseScore, epss: .epss.percentile, exploited: .kev.exploited}'

# Extract for CSV export
python cve_details.py CVE-2024-1086 --json | jq -r '[.cve_id, .cvss.cvssV3_1.baseScore, .epss.score, .kev.exploited] | @csv'
```

### Filtering

```bash
# Only show if EPSS percentile > 50
python cve_details.py CVE-2024-1086 --json | jq 'select(.epss.percentile > 50)'

# Only show if exploited
python cve_details.py CVE-2024-1086 --json | jq 'select(.kev.exploited == true)'

# Count POCs
python cve_details.py CVE-2024-1086 --json | jq '.pocs | length'

# Get first 3 references
python cve_details.py CVE-2024-1086 --json | jq '.references[:3]'
```

### Batch Processing

```bash
# Process a list of CVEs into a JSON array
for cve in CVE-2024-1086 CVE-2023-44487 CVE-2024-3094; do
  python cve_details.py "$cve" --json
done | jq -s '.'

# Filter to only exploited CVEs from a list
for cve in CVE-2024-1086 CVE-2023-44487 CVE-2024-3094; do
  python cve_details.py "$cve" --json
done | jq -s '[.[] | select(.kev.exploited == true)]'

# Generate a quick tab-separated report
for cve in CVE-2024-1086 CVE-2023-44487; do
  python cve_details.py "$cve" --json
done | jq -rs '.[] | "\(.cve_id)\t\(.cvss.cvssV3_1.baseScore // "-")\t\(.kev.exploited)"'
```
