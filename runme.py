#!/bin/bash
# ------------------------------------------------------------------------------------
# Title: SentinelOne - SOAR - Sandbox Integration (runme.py)
# Version: V1.0
# Dev Date: 08-03-2021
# Developed by SentinelOne (www.sentinelone.com)
# Developer: Martin de Jongh
# Developer email: martind@sentinelone.com

#   Copyright 2021, SentinelOne
#   Licensed under the Apache License, Version 2.0 (the "License"); 
#   You may not use this Script except in compliance with the License.
#   You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and limitations under the License.
#
# ------------------------------------------------------------------------------------
# Important:
# Before executing below Python script to monitor and collect S1 Platform Data.
# Make certain you have an active Cuckoo Sandbox up & running. 
# Additional provided Cuckoo_Start.sh script to automate Sandbox startup & configuration.
#
# Run following bash command as ROOT to start S1 SOAR API script 'python3 runme.py'
# ------------------------------------------------------------------------------------
#

#################################################
#               CREDENTIALS AND API Config
#################################################

S1_hostname = "https://X.sentinelone.net/" #TODO: Put URL of SentinelOne management (Example: https://x.sentinelone.net/).
S1_api_token = "XXXXXXXXXXXXXXXXX" # TODO: Put SentinelOne API_TOKEN.
S1_site_name = "SITE NAME" #TODO: Put SentinelOne Management "Site" Name.
S1_auto_mode = False #If set to "True" Sandbox analyse result will automatically mark threat/start remediation policy in SentinelOne Management.

S1_headers = {
    "Content-type": "application/json",
    "Authorization": "APIToken " + S1_api_token
}

#region Cuckoo credentials and variables
Cuckoo_hostname = "http://X.X.X.X:8000/" #TODO: Put Cuckoo Sandbox management URL with port (Example: http(s)://x.x.x.x:8000/).
Cuckoo_hostname_api = "http://X.X.X.X:8090/" #TODO: Put Cuckoo Sandbox API URL with port (Example: http(s)://x.x.x.x:8090/).
Cuckoo_api_token = "XXXXXXXXXXX" #TODO: Put Cuckoo Sandbox API token
Cuckoo_file_path = "/root/" #TODO: Put file path where python code is run (Example: /root/).

##############################################################

import requests
import json
import urllib3
import sys
import time
import zipfile
import zlib
import subprocess
import pprint
import io
import os
import shutil
import pyfiglet
from datetime import datetime

S1_secret = "PASSWORD" # Enter preffered SentinelOne Zip file password to encrypt/decrypt downloaded malware files.

##############################################################

def S1_Get_Site_Id(arg):
    params = {"name": arg}
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = requests.get(S1_hostname+'web/api/v2.1/sites', verify=False, headers=S1_headers, params=params)
    if r.status_code != 200:
        print ("Error: %s" % r.json())
        sys.exit()
    return r.json()['data']['sites'][0]['id']

##############################################################

def S1_Fetch_Threat_File(arg):
    '''
    API call to fetch threat file, it takes as argument threat id.
    Example: S1_Fetch_Threat_File('threat id')
    '''
    params = {
        "siteIds": site_id,
        }
    data = { 
        "filter": {
            "ids": [
                arg
                ]
        },
        "data": {
            "password": S1_secret            
            }
        }

    urllib3.disable_warnings()

    r = requests.post(S1_hostname+'web/api/v2.1/threats/fetch-file', data=json.dumps(data), verify=False, headers=S1_headers, params=params)
    if r.status_code != 200:
        pass
    results = r.json()['data']['affected']
    if results == 1:
        return(True)
    else:
        return(False)

##############################################################

def S1_Annotate_Threat(threat_id,arg):
    '''
    Annotates a Threat (Threat Notes within SentinelOne Managment)
    '''
    data = {
       "data": {
           "text": arg
           },
       "filter": {
       "ids": threat_id
       }
    }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = requests.post(S1_hostname+'/web/api/v2.1/threats/notes', data=json.dumps(data), verify=False, headers=S1_headers)
    if r.status_code != 200:
        print ("Error: %s" % r.json())
        sys.exit()
        return(False)
    return(True)

##############################################################

def S1_Mark_As_Threat(sha1_to_push):

    data = {
        "filter": {
            "siteIds": site_id
        },
        "data": {
            "description": "S1 Detonator Marked as Threat",
            "value": sha1_to_push,
            "source": "S1 Detonator: Marked as Threat",
            "osType": "windows",
            "type": "black_hash"
        }
    }

    r = requests.post(S1_hostname+'web/api/v2.1/restrictions', verify=False, headers=S1_headers, data=json.dumps(data))
    if r.status_code != 200:
        print ('{}: Cant add blacklist, probably exist{}'.format((datetime.now()),sha1_to_push))
        return False
    return True

##############################################################

def S1_Get_Url_File_Path(arg):
    '''
    Reads activities to extract the download of the threat file.
    '''
    global file_url_path

    params = {
        "siteIds": site_id,
        "skipCount": False,
        "countOnly": False,
        "activityTypes": '86',
        "sortOrder": 'desc',
        "limit": 1,
        "agentIds": arg,
        "includeHidden": False
        }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
  
    r = requests.get(S1_hostname+'web/api/v2.1/activities', verify=False, headers=S1_headers, params=params)
    if r.status_code != 200:
        print ("Error: %s" % r.json())
        sys.exit()
    results = r.json()['data'][0]
    file_url_path = results['data']['filePath']
    malware_file_name = results['data']['filename']
    return(file_url_path, malware_file_name)

##############################################################

def S1_Download_File(url_file_path, url_file_name):
    '''
    Downloads Zip File from Management console, with provided path.
    Example:
    S1_Download_File('/agents/419190073385287843/uploads/636931808327607884')
    Returns True
    '''
    global malware_file

    S1_headers = {
        "Content-type": "*/*",
        "Authorization": "APIToken " + S1_api_token
    }
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = requests.get(S1_hostname+'web/api/v2.1' + url_file_path + '?apitoken=' + S1_api_token, verify=False, headers=S1_headers)
    malware_file = url_file_name + '.zip'
    time.sleep(60)
    open (malware_file, 'wb').write(r.content) 
    
    with zipfile.ZipFile(malware_file, mode='r') as zipObj:
        zipObj.extractall(path=threat_id, pwd=b'Infected2021!')

    cmd_find_file = ("find " + threat_id + "/"  " -type f | grep -v .DS_ | grep -v '.json'")
    
    file_path_searched = subprocess.getoutput(cmd_find_file)

    cmd_copy_file_from_path = ("cp '" + file_path_searched + "' '" + threat_id + "/" + fileDisplayName + "'")

    subprocess.getoutput(cmd_copy_file_from_path)

    file_to_boom = (threat_id + "/" + fileDisplayName)
    
    return(file_to_boom)

##############################################################

def Submit_Cuckoo_Sandbox(arg):
    '''
    Submit_Cuckoo_Sandbox(path/filename)
    RETURNS: Veredict of Sandbox and Report...
    '''

    file_passed = Cuckoo_file_path + arg
    print("Cuckoo File Submit cmd: "+ file_passed)
    # connect to the sandbox
    
    Cuckoo_rest_url = Cuckoo_hostname_api + "tasks/create/file"
    Cuckoo_headers = {
        "Authorization": "Bearer " + Cuckoo_api_token
        }

    Cuckoo_view_url = Cuckoo_hostname_api + "tasks/view/"
    cuckoo_summary_url = Cuckoo_hostname_api + "tasks/summary/"
    # submit a file
    with open(file_passed, "rb") as sample:
        files = {"file": (arg, sample)}
        r = requests.post(Cuckoo_rest_url, headers=Cuckoo_headers, files=files)
        task_id = r.json()["task_id"]
        print('{}: Submission ID:                    {}'.format((datetime.now()),task_id))
    # Add your code for error checking if task_id is None.
    if task_id > 0:
        pass
    else:
        print ("Task ID is None, error: %s" % r.json())
        sys.exit()

    # Add your code to error checking for r.status_code.
    if r.status_code != 200:
        print ("Error: %s" % r.json())
        sys.exit()

    time.sleep(120) # wait for the analysis to complete
    r = requests.get(Cuckoo_view_url + str(task_id), headers=Cuckoo_headers)
    Analysis_Status = r.json()['task']['status']

    if Analysis_Status != 'reported':
        time.sleep(60)   # Adjust to your Sandbox SL
    else:
        Analysis_SHA1 = r.json()['task']['sample']['sha1']
        Cuckoo_FileName = r.json()['task']['target']
        Analysis_FileType = r.json()['task']['sample']['file_type']
        Analysis_ID = r.json()['task']['id']

        #get analysis score result
        r2 = requests.get(cuckoo_summary_url + str(task_id), headers=Cuckoo_headers)

        Cuckoo_Score = r2.json()['info']['score']

        print('{}: Sandbox Analysis Completed:    {}'.format((datetime.now()),Cuckoo_FileName))
        print('{}: File SHA1:                        {}'.format((datetime.now()),Analysis_SHA1))
        print('{}: Submission Analysis ID:           {}'.format((datetime.now()),Analysis_ID))
        print('{}: Sandbox Analysis Status:       {}'.format((datetime.now()),Analysis_Status))
        print('{}: Sandbox Score is:            {}'.format((datetime.now()),Cuckoo_Score))
        print('{}: Report Available at:              {}analysis/{}/summary/'.format((datetime.now()),Cuckoo_hostname,Analysis_ID))

        Annotate_URL = (str(Cuckoo_hostname) + "analysis/" + str(Analysis_ID) + '/summary/')

        #check analysis result
        if 'malicious' in r2.json() and S1_auto_mode == True:
            Annotate_Veredict = 'S1-SOAR Result: Marked as THREAT! MALICIOUS: '
            S1_marked = S1_Mark_As_Threat(Analysis_SHA1)
            print('{}: Marked as Threat in AUTO-mode:    {}'.format((datetime.now()),S1_marked))

        elif 'malicious' in r2.json() and S1_auto_mode == False:
            Annotate_Veredict = 'S1-SOAR Result: MALICIOUS '

        elif Cuckoo_Score > 3:
            Annotate_Veredict = 'S1-SOAR Result: Potential MALICIOUS, Sandbox score is ' + str(Cuckoo_Score)

        else:
            Annotate_Veredict = 'S1-SOAR Result: BENIGN '
            Annotate_String = (Annotate_Veredict + Annotate_URL)
            S1_Annotate_Threat(threat_id, Annotate_String)
            print('{}: Threat Annotated ID:              {} - {}'.format((datetime.now()),threat_id,Annotate_Veredict))

            #SANDBOX Clean-UP comand
            clean_command1 = ("rm" + " " + malware_file)
            clean_command2 = ("rm -rf" + " " + threat_id)

            subprocess.getoutput(clean_command1)
            subprocess.getoutput(clean_command2)
            print('{}: S1-SOAR-Sandbox Finished Cleaning up:          {}'.format((datetime.now()),threat_id))
            exit()

##############################################################

def S1_Get_Threats(site_id):
    filename = 'hashfile.txt'
    hash_sha1 = int()
    
    # Change below JSON Parms if needed to accomidate required Agent alert monitoring state.
    params = {
        "siteIds": site_id,
        "agentIsActive": True,
        "osTypes": 'windows',
        "resolved": False,
        "mitigationStatuses": 'not_mitigated',
        "incidentStatuses": 'in_progress',
        "analystVerdicts": 'undefined',
        "skipCount": True,
        "limit": 30,
        "countOnly": False,
        "sortOrder": 'desc'
        }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = requests.get(S1_hostname+'web/api/v2.1/threats', verify=False, headers=S1_headers, params=params)
    if r.status_code != 200:
        print ("Error: %s" % r.json())
        sys.exit()

    with open(filename,mode='r') as current_file:
        known_hashes = current_file.readline()
        current_file.close()

        for x in r.json()['data']:
            if x['threatInfo']['sha1'] in known_hashes:
                pass
            elif x['threatInfo']['confidenceLevel'][0] != 's':
                pass
            else:
                global threat_id
                global fileDisplayName
                threat_id = x['threatInfo']['threatId']
                hash_sha1 = x['threatInfo']['sha1']
                agent_id = x['agentRealtimeInfo']['agentId']
                fileDisplayName = x['threatInfo']['threatName']

                with open(filename,mode='a') as current_file:
                    current_file.write(str(hash_sha1) + "\n")
                    current_file.close()

                    S1_Fetch_Threat_File(threat_id)
                    print('{}: Fetched File ID:                  {}'.format((datetime.now()),threat_id))
                    
                    S1_Annotate_Threat(threat_id, 'Payload shared with Sandbox for Alert validation.')
                    print('{}: Threat Annotated ID:              {}'.format((datetime.now()),threat_id))
                    
                    time.sleep(60)

                    s1_get_url_file_path = S1_Get_Url_File_Path(agent_id)
                    url_file_path = s1_get_url_file_path[0]
                    url_file_name = s1_get_url_file_path[1]
                    file_to_boom = S1_Download_File(url_file_path,url_file_name)
                    print('{}: File Dowloaded to local:          {}'.format((datetime.now()),file_to_boom))
                    pid=os.fork()
                    if pid==0:
                        print('{}: Submiting to Sandbox:          {}'.format((datetime.now()),file_to_boom))
                        Submit_Cuckoo_Sandbox(file_to_boom)
                    pid = 0

##############################################################



#################################################
#               Script Start
#################################################

separator = '#######################################################################'
print('\n'*100)

print(separator)

ascii_banner_S1 = pyfiglet.figlet_format("  S1-SOAR")
print(ascii_banner_S1)
ascii_banner_SandBox = pyfiglet.figlet_format(" Cuckoo-Sandbox")
print(ascii_banner_SandBox)

print(separator)
print('\n')
print('          S1-SOAR-CuckooSandbox     V1.0 Started! ')
print('\n')
print(separator)
print('\n')
print('{}:       Starting up CuckooSandbox                  ')
os.system('sh cuckoo-start.sh')
time.sleep(5)
print('\n')
print(separator)
site_id = (S1_Get_Site_Id(S1_site_name))
while True:
    S1_Get_Threats(site_id)
    print('{}: Waiting for S1 Input:                {}'.format((datetime.now()),'60 seconds' ))
    time.sleep(60)
