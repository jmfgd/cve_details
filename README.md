# CVE Details Fetcher

A command-line tool to fetch and display comprehensive details for a given Common Vulnerabilities and Exposures (CVE) identifier.

## Description

This tool aggregates information from multiple sources to provide a holistic view of a specific vulnerability. It is designed to help security researchers, analysts, and system administrators quickly gather relevant data to assess the risk and impact of a CVE.

## Features

The tool fetches the following information:

*   **CVE Record:** Retrieves the official CVE record from the MITRE Corporation, including the description and CVSS v3.1 base score.
*   **CISA KEV Check:** Checks if the CVE is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog.
*   **EPSS Score:** Fetches the Exploit Prediction Scoring System (EPSS) score, which estimates the probability of a vulnerability being exploited in the wild.
*   **GitHub POCs:** Searches for publicly available Proof-of-Concept (POC) exploits on GitHub.
*   **Nessus Coverage:** Lists the relevant Nessus plugins available for detecting the vulnerability.

## Installation

1.  Clone the repository or download the `cve_details.py` script.
2.  Install the required Python libraries:

    ```bash
    pip install click requests prompt_toolkit beautifulsoup4
    ```

## Usage

Run the script from your terminal, providing a CVE ID as an argument.

```bash
python cve_details.py <CVE_ID>
```

### Example

```bash
python cve_details.py CVE-2024-1086
```
