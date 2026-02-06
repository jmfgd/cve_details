"""
retrieve CVE information 

CVE.org --> CVE record (descriptions)
NVD --> Analysis (CPE, CVSS, CWE...)
Cisa KEV Catalog
EPSS scores
NESSUS plugin coverage
Github POC availability

"""

import click
import json
from prompt_toolkit import print_formatted_text, HTML  # type: ignore
import requests
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from html import escape
import re
from concurrent.futures import ThreadPoolExecutor


#--------------------------------------------------------------------------
# API and resources
#--------------------------------------------------------------------------
KEV_CATALOG = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
POC_API = "https://poc-in-github.motikan2010.net/api/v1/"
NESSUS_PLUGIN_URL = "https://www.tenable.com/cve/"
CVE_RECORD_API = "https://cveawg.mitre.org/api/cve/"
CVE_ORG_API = "https://cveawg.mitre.org/api/cve-id/"
EPSS_SCORE_API = "https://api.first.org/data/v1/epss"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

REQUEST_TIMEOUT = 10  # seconds
NESSUS_TIMEOUT = 20   # Nessus can be slower

# Session for connection reuse and consistent headers
session = requests.Session()
session.headers.update({"User-Agent": "cve-details/1.0"})

# Output mode control
_quiet = False  # When True, suppress colored output (for JSON mode)
#--------------------------------------------------------------------------

def get_cisa_catalog() -> list:
    
    try:
        local_copy_name = KEV_CATALOG.split("/")[-1]
        with open(local_copy_name, "r") as f:
            kev_dict = json.loads(f.read())
        kev_time = datetime.fromisoformat(kev_dict["dateReleased"])   # "dateReleased": "2024-07-08T15:48:15.0847Z"
        today = datetime.now(timezone.utc)
        age = today - kev_time
        if age.days > 1:
            raise Exception(f"Local KEV catalog age is {age.days} days old. downloading the latest version")
    except Exception as err:
        log(f"{err}", "error")
        log(f"Downloading {KEV_CATALOG}", "info")
        try:
            r = session.get(KEV_CATALOG, timeout=REQUEST_TIMEOUT)
            kev_dict = json.loads(r.text)
            with open(KEV_CATALOG.split("/")[-1], "w") as outfile:
                json.dump(kev_dict, outfile)
        except Exception as err:
            log(f"{err}", "error")
            return []
    
    kev_vulns = list(kev_dict["vulnerabilities"])  
    return kev_vulns   

#--------------------------------------------------------------------------
# Get EPSS scoring
#--------------------------------------------------------------------------
def get_epss_score(cve_id: str) -> dict:
    result = {"score": None, "percentile": None}
    try:
        r = session.get(EPSS_SCORE_API + f"?cve={cve_id}", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        epss_dict = json.loads(r.text)
        epss_data = epss_dict.get("data", [])
        if epss_data:
            result["score"] = epss_data[0].get("epss")
            result["percentile"] = int(float(epss_data[0].get("percentile")) * 100)
            log(f"EPSS Score : {result['score']} - percentile : {result['percentile']}", "success")
        else:
            log("No EPSS Score", "info")
    except requests.exceptions.RequestException as e:
        log(f"EPSS Score error : {e}", "error")
    return result  

#-------------------------------------------------------------------------- 
#    Extracts the first CVE ID from a given text line.
 #   Returns the CVE ID string if found, otherwise None.
#-------------------------------------------------------------------------- 
def validate_cve_id(text_line):
    
    if not isinstance(text_line, str):
        return None
    
    # Regex pattern for CVE IDs: CVE-YYYY-NNNN+
    pattern = r"\bCVE-\d{4}-\d{4,}\b"
    match = re.search(pattern, text_line, re.IGNORECASE)
    return match.group(0) if match else None

#--------------------------------------------------------------------------
# get CVE RECORD Details
#--------------------------------------------------------------------------
def get_cve_record(cve_id: str) -> dict | None:
    result = {
        "cve_id": cve_id,
        "status": None,
        "title": None,
        "date_public": None,
        "description": None,
        "cvss": {}
    }
    try:
        r = session.get(CVE_ORG_API + cve_id, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        cve_dict = json.loads(r.text)
        cveStatus = cve_dict.get("state", "N/A")
        result["status"] = cveStatus
        if cveStatus != "PUBLISHED":
            log(f"{cve_id} Status: {cveStatus}", "info")
            return None
        r = session.get(CVE_RECORD_API + f"{cve_id}", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        log(f"{cve_id} details:", "success")
        cve_dict = json.loads(r.text)
        cveMetadata = cve_dict.get("cveMetadata", {})
        if cveMetadata is not None:
            if cveMetadata["state"] == "PUBLISHED":
                cna = cve_dict.get("containers", {}).get("cna", {})
                if cna is not None:
                    result["title"] = cna.get("title")
                    result["date_public"] = cna.get("datePublic")
                    if result["title"]:
                        log(f"{result['title']}", "info")
                    if result["date_public"]:
                        log(f"Date public : {result['date_public']}", "info")
                    metrics = cve_dict.get("containers", {}).get("cna", {}).get("metrics", [])
                    versions = ["cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"]
                    if metrics:
                        for d in metrics:
                            for version in versions:
                                if d.get(version):
                                    result["cvss"][version] = {
                                        "baseScore": d.get(version).get("baseScore"),
                                        "vectorString": d.get(version).get("vectorString")
                                    }
                                    log(f"{version} : {d.get(version).get('baseScore', 'N/A')} | {d.get(version).get('vectorString', 'N/A')}", "info")
                    # Get description
                    for dict_entry in cve_dict["containers"]["cna"]["descriptions"]:
                        if dict_entry["lang"] == "en":
                            result["description"] = dict_entry["value"]
                            break
                    else:
                        result["description"] = cve_dict["containers"]["cna"]["descriptions"][0]["value"]
                    if not _quiet:
                        print(result["description"])
                    return result
                else:
                    log("CVE RECORD error : missing mandatory CNA container", "error")
                    return None
            else:
                log("REJECTED CVE-ID", "error")
                return None
    except requests.exceptions.RequestException as e:
        log(f"{cve_id} Record error - {e}", "error")
        return None
    except Exception as err:
        log(f"{err}", "error")
        return None
#--------------------------------------------------------------------------
def is_exploited(cve_id: str) -> dict:
    result = {"exploited": False, "vulnerability_name": None, "date_added": None}
    kev_vulns = get_cisa_catalog()
    if kev_vulns:
        for vuln in kev_vulns:
            if vuln["cveID"] == cve_id:
                result["exploited"] = True
                result["vulnerability_name"] = vuln.get("vulnerabilityName")
                result["date_added"] = vuln.get("dateAdded")
                log(f"{cve_id} ({result['vulnerability_name']}) is exploited", "success")
                break
        else:
            log(f"{cve_id} is NOT known to be exploited", "info")
    return result

#--------------------------------------------------------------------------
# get possible POCs available on GitHub
#--------------------------------------------------------------------------
def get_pocs(cve_id: str) -> list:
    result = []
    try:
        r = session.get(POC_API + f"?cve_id={cve_id}", timeout=REQUEST_TIMEOUT)
        if r.status_code == requests.codes.ok:
            poc_dict = json.loads(r.text)
            if poc_dict["pocs"]:
                result = [poc["html_url"] for poc in poc_dict["pocs"]]
            if result:
                log("Available POC(s)", "success")
                if not _quiet:
                    print("\n".join(result))
            else:
                log("Unable to find any PoCs for this CVE", "info")
        else:
            log(f"requests.get returned {r.status_code}", "info")
    except requests.exceptions.RequestException as e:
        log(f"get_pocs error {e}", "error")
    return result
    
#--------------------------------------------------------------------------
# get NESSUS plugins coverage for CVE ID
#--------------------------------------------------------------------------
def get_nessus_plugins(cve_id: str) -> list:
    result = []
    try:
        r = session.get(NESSUS_PLUGIN_URL + f"{cve_id}/plugins", timeout=NESSUS_TIMEOUT)
        if r.status_code == requests.codes.ok:
            soup = BeautifulSoup(r.text, "html.parser")
            last_script_tag = soup.find("script", id="__NEXT_DATA__")
            if last_script_tag is not None:
                nessus_dict = json.loads(last_script_tag.text)
                plugin_list = nessus_dict["props"]["pageProps"]["plugins"]
                result = [
                    {
                        "id": plugin["_source"]["script_id"],
                        "name": plugin["_source"]["script_name"],
                        "family": plugin["_source"]["script_family"]
                    }
                    for plugin in plugin_list
                ]
                if result:
                    log("NESSUS plugins coverage:", "success")
                    if not _quiet:
                        for p in result:
                            print(f"{p['id']} - {p['name']} - {p['family']}")
                else:
                    log("No NESSUS coverage for this vulnerability", "info")
        else:
            log("Unable to get NESSUS coverage for this vulnerability", "error")
    except requests.exceptions.RequestException as e:
        log(f"get NESSUS plugins data error {e}", "error")
    return result

#------------------------------------------------------------------------
def get_nvd(cve_id: str) -> dict:
    result = {"cwe": [], "references": []}
    try:
        r = session.get(NVD_CVE_API + f"?cveId={cve_id}", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        nvd_data = json.loads(r.text)
        vulnerabilities = nvd_data.get("vulnerabilities", [])
        if vulnerabilities:
            cve_item = vulnerabilities[0].get("cve", {})
            # Extract CWE
            weaknesses = cve_item.get("weaknesses", [])
            for w in weaknesses:
                for desc in w.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        result["cwe"].append(desc["value"])
            # Extract references
            refs = cve_item.get("references", [])
            result["references"] = [ref.get("url") for ref in refs if ref.get("url")]
    except requests.exceptions.RequestException as e:
        log(f"get NVD data error {e}", "error")
    return result

#--------------------------------------------------------------------------
def log(message: str, level: str = "info"):
    if _quiet:
        return
    colors = {"info": "skyblue", "success": "ansigreen", "error": "ansired"}
    symbols = {"info": "[ ]", "success": "[+]", "error": "[-]"}
    color = colors.get(level, "white")
    symbol = symbols.get(level, "[?]")
    print_formatted_text(HTML(f"<{color}>{symbol} {escape(message)}</{color}>"))

#--------------------------------------------------------------------------
@click.command()
@click.argument("cve_id")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
def get_cve_details(cve_id: str, output_json: bool):
    global _quiet
    _quiet = output_json

    cve_id = validate_cve_id(cve_id.upper())
    if cve_id is None:
        if output_json:
            print(json.dumps({"error": "Bad CVE ID format"}))
        else:
            log("Bad CVE ID format", "error")
        exit(1)

    cve_record = get_cve_record(cve_id)
    if cve_record:
        # Run remaining checks in parallel for faster results
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_nvd = executor.submit(get_nvd, cve_id)
            future_epss = executor.submit(get_epss_score, cve_id)
            future_kev = executor.submit(is_exploited, cve_id)
            future_pocs = executor.submit(get_pocs, cve_id)
            future_nessus = executor.submit(get_nessus_plugins, cve_id)

            # Collect results
            nvd_data = future_nvd.result()
            epss_data = future_epss.result()
            kev_data = future_kev.result()
            pocs_data = future_pocs.result()
            nessus_data = future_nessus.result()

        if output_json:
            output = {
                "cve_id": cve_record["cve_id"],
                "status": cve_record["status"],
                "title": cve_record["title"],
                "date_public": cve_record["date_public"],
                "description": cve_record["description"],
                "cvss": cve_record["cvss"],
                "cwe": nvd_data["cwe"],
                "epss": epss_data,
                "kev": kev_data,
                "pocs": pocs_data,
                "nessus_plugins": nessus_data,
                "references": nvd_data["references"]
            }
            print(json.dumps(output, indent=2))
    elif output_json:
        print(json.dumps({"error": f"Could not retrieve CVE record for {cve_id}"}))

#--------------------------------------------------------------------------
if __name__ == "__main__":
    
    get_cve_details()



