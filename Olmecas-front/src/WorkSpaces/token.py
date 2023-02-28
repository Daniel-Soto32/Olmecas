#!/usr/bin/env python3

import json
from base64 import b64encode

import requests  # To install requests, use: pip install requests
import urllib3

# Configuration
endpoint = '/agents?select=lastKeepAlive&select=id&status=active'

protocol = 'https'
host = '54.145.241.208'
port = '55000'
user = 'wazuh-wui'
password = 'uvVZM6eL1tb.1VELhQ1SxUo7RxUauw+N'
#seguridad
#Pruebas123$

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Functions
def get_response(url, headers, verify=False):
    request_result = requests.get(url, headers=headers, verify=verify)

    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

# Variables
base_url = f"{protocol}://{host}:{port}"
login_url = f"{base_url}/security/user/authenticate"
basic_auth = f"{user}:{password}".encode()
headers = {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
headers['Authorization'] = f'Bearer {get_response(login_url, headers)["data"]["token"]}'

#Request
response = get_response(base_url + endpoint, headers)

# WORK WITH THE RESPONSE AS YOU LIKE
print(json.dumps(response, indent=4, sort_keys=True))
print(base_url + endpoint)