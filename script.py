import pandas as pd
import requests

# listing API Keys
abuseip_key=""
virustotal_key=""
otx_api_key=""

# the list of IPs to analyse
ip_add_list=[ "27.81.7.52","195.178.191.4","218.92.0.118","51.79.27.107","125.72.150.250"]

# functions to query AbuseIPDB and Virus Total
def abuseipdb_query(ip,api_key):
 url=f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
 headers = {"Key": api_key}
 response = requests.get(url, headers=headers)
 return response.json()

# Virus Total
def virustotal_query(ip,api_key):
  url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
  headers = {"x-apikey": api_key}
  response = requests.get(url, headers=headers)
  return response.json()

# OTX 
def get_otx_ip_info(ip, api_key):
    headers = {'X-OTX-API-KEY': api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general" 
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"❗️OTX API request failed for {ip} with status code {response.status_code}")
        return {}
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        print(f"❗️Failed to parse JSON from OTX response for {ip}")
        print("Raw response:", response.text)  # This helps you debug bad API responses
        return {}


# processing the IP Addresses given
def process_ip(ip_list):
  results=[]
  for ip in ip_list:
    # call the abuse ipdb query
    abuseip_data=abuseipdb_query(ip,abuseip_key)
    # call the virus total query
    virustotal_data=virustotal_query(ip,virustotal_key)
    #can add OTX for additional threat info
    otx_data=get_otx_ip_info(ip,otx_api_key)

    results.append ({
      "IP": ip,
            "AbuseIPDB Score": abuseip_data['data']['abuseConfidenceScore'],
            "VirusTotal Malicious Count": virustotal_data['data']['attributes']['last_analysis_stats']['malicious'],
            "OTX Data": otx_data 
    })

    #Therefore save data in .csv format
    ip_results=pd.DataFrame(results)
    ip_results.to_csv('IP_ANALYSIS.csv',index=False)
    print(ip_results)


 
process_ip(ip_add_list)
