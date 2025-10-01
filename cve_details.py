'''
TO DO

check format of CISA ADP container in CVE RECORD 
extract CISA ADP info if any

also: CNA container has references, some may have 'exploit' tag --> collect url
'''


import click
import json
from prompt_toolkit import print_formatted_text, HTML, ANSI # type: ignore
import requests
from  datetime import datetime, timezone
from bs4 import BeautifulSoup
from pprint import pprint
from html import escape

#-------------------------------------------------------------------------- 
# useful resources URL 
#-------------------------------------------------------------------------- 
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
POC_URL = 'https://poc-in-github.motikan2010.net/api/v1/?cve_id='
NESSUS_PLUGIN_URL = 'https://www.tenable.com/cve/'
CVE_RECORD_URL = 'https://cveawg.mitre.org/api/cve/'
EPSS_SCORE_URL = 'https://api.first.org/data/v1/epss?cve='

#--------------------------------------------------------------------------
def get_cisa_catalog() -> list:
    
    try:
        local_copy_name = KEV_URL.split('/')[-1]
        with open(local_copy_name, 'r') as f:
            kev_dict = json.loads(f.read())
        kev_time = datetime.fromisoformat(kev_dict['dateReleased'])   # "dateReleased": "2024-07-08T15:48:15.0847Z"
        today = datetime.now(timezone.utc)
        age = today - kev_time
        if age.days > 7:
            raise Exception(f'Local KEV catalog age is {age.days} days. downloading latest version')
    except Exception as err:
        log(f"{err}", 'error')
        log(f'Downloading {KEV_URL}', 'info')
        try:
            r = requests.get(KEV_URL, timeout=10)
            kev_dict = json.loads(r.text)
            with open(KEV_URL.split('/')[-1], "w") as outfile:
                json.dump(kev_dict, outfile)
        except Exception as err:
            log(f"{err}", 'error')
            return []
    
    kev_vulns = list(kev_dict['vulnerabilities'])  
    return kev_vulns   

#-------------------------------------------------------------------------- 
# Get EPSS scoring
#-------------------------------------------------------------------------- 
def get_epss_score(cve_id : str) -> None:
    
    try:
        r = requests.get(EPSS_SCORE_URL + f'{cve_id}', timeout=10)
        r.raise_for_status()
        epss_dict = json.loads(r.text)
        epss_data = epss_dict.get('data', [])
        if epss_data:
            epss_score = epss_data[0].get('epss', 'N/A')
            log(f'EPSS Score : {epss_score}', 'success')  
        else:
            log(f'No EPSS Score', 'info')  
    except requests.exceptions.RequestException as e:
        log(f'EPSS Score error : {e}', 'error')  

#--------------------------------------------------------------------------
# get CVE RECORD Details 
#--------------------------------------------------------------------------
def get_cve_record(cve_id : str):
    
    try:
        r = requests.get(CVE_RECORD_URL + f'{cve_id}', timeout=10)
        r.raise_for_status()
        log(f'{cve_id} details:', 'success')
        cve_dict = json.loads(r.text)
        cveMetadata = cve_dict.get('cveMetadata', {})
        if cveMetadata is not None:
            if cveMetadata['state'] == "PUBLISHED":
                cna = cve_dict.get('containers', {}).get('cna', {})
                #pprint(cna)
                if cna is not None:
                    if cna.get('title'):
                        log(f'{cna['title']}', 'info')
                    if cna.get('datePublic'):
                        log(f'Date public : {cna['datePublic']}', 'info')
                    metrics = cve_dict.get('containers', {}).get('cna', {}).get('metrics', [])  
                    if metrics:
                        cvss_v3_1_data = next((d['cvssV3_1'] for d in metrics if 'cvssV3_1' in d), None)    # get CVSS v3.1 score if exists
                        if cvss_v3_1_data:
                            score = cvss_v3_1_data.get('baseScore', 'N/A')
                            log(f'CVSS v3.1 : {score}', 'info')
                    for dict_entry in cve_dict['containers']['cna']['descriptions']:
                        if dict_entry['lang'] == 'en':                                      # try to find an english description
                            print(dict_entry['value'])
                            break
                    else:
                        print(cve_dict['containers']['cna']['descriptions'][0]['value'])    # else print first available description
                    #print(cve_dict['containers']['cna']['affected'])
                    return True
                else:
                    log('CVE RECORD error : missing mandatory CNA container', 'error')
                    return False
            else: 
                log('REJECTED CVE-ID', 'error')
                return False

    except requests.exceptions.RequestException as e:
        log(f'{cve_id} Record error - {e}', 'error')
        return False
#--------------------------------------------------------------------------      
def is_exploited(cve_id : str):
    # check if exploited
    kev_vulns = get_cisa_catalog()  
    if kev_vulns:
        for vuln in kev_vulns:
            if vuln['cveID'] == cve_id:
                log(f'{cve_id} ({vuln['vulnerabilityName']}) is exploited', 'success')
                break
        else:
            log(f'{cve_id} is NOT known to be exploited', 'info')

#--------------------------------------------------------------------------
# get possible POCs available on GitHub
#--------------------------------------------------------------------------
def get_pocs(cve_id : str):
    
    try:
        r = requests.get(POC_URL + cve_id, timeout=10)
        if r.status_code == requests.codes.ok:
            poc_dict = json.loads(r.text)
            html_urls = []
            if len(poc_dict['pocs']):
                for poc in poc_dict['pocs']:
                    html_urls.append(poc['html_url'])
            html_urls_txt = '\n'.join(html_urls)
            if len(html_urls):
                log('Available POC(s)', 'success')
                print(html_urls_txt)
            else:
                log('Unable to find any PoCs for this CVE', 'info')
        else:
            log(f'requests.get returned {r.status_code}', 'info')        
    
    except requests.exceptions.RequestException as e:
        log(f'get_pocs error {e}', 'error')
        return False
    
#--------------------------------------------------------------------------
# get NESSUS plugins coverage for CVE ID
#--------------------------------------------------------------------------
def get_nessus_plugins(cve_id : str):
 
    r = requests.get(NESSUS_PLUGIN_URL + f'{cve_id}/plugins', timeout=10)
    if r.status_code == requests.codes.ok:
        soup = BeautifulSoup(r.text, 'html.parser')
        """ for tag in soup.find_all('script'):
            print(tag) """
        last_script_tag = soup.find("script", id="__NEXT_DATA__")
        if last_script_tag is not None:
            nessus_dict = json.loads(last_script_tag.text)
            plugin_list = nessus_dict['props']['pageProps']['plugins']
            #pprint(plugin_list)
            p = [f'{plugin['_source']['script_id']} - {plugin['_source']['script_name']} - {plugin['_source']['script_family']}' for plugin in plugin_list]
            if p:
                p_string = '\n'.join(p)
                log('NESSUS plugins coverage:', 'success')
                print(p_string)
            else:
                log('No NESSUS coverage for this vulnerability', 'info')   
    else:
        log('Unable to get NESSUS coverage for this vulnerability', 'error')   
    return None

#--------------------------------------------------------------------------
def log(message: str, level: str = 'info'):
    colors = {'info': 'skyblue', 'success': 'ansigreen', 'error': 'ansired'}
    symbols = {'info': '[ ]', 'success': '[+]', 'error': '[-]'}
    color = colors.get(level, 'white')
    symbol = symbols.get(level, '[?]')
    print_formatted_text(HTML(f'<{color}>{symbol} {escape(message)}</{color}>'))

#--------------------------------------------------------------------------
@click.command()
@click.argument('cve_id')
def get_cve_details(cve_id : str):
    
    if get_cve_record(cve_id):
        get_epss_score(cve_id)
        is_exploited(cve_id)
        get_pocs(cve_id)
        get_nessus_plugins(cve_id)

#--------------------------------------------------------------------------
if __name__ == '__main__':
    get_cve_details()



