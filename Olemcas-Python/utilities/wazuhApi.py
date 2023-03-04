import json
from base64 import b64encode

import requests  # To install requests, use: pip install requests
import urllib3
import pandas as pd
import numpy as np

class apiHandler:
    
    # Configuration
    endpoint = '/agents?select=lastKeepAlive&select=id&status=active'
    
    protocol = 'https'
    host = '54.159.199.49'
    #host = '54.145.241.208'
    port = '55000'
    user = 'wazuh-wui'
    password = 'uvVZM6eL1tb.1VELhQ1SxUo7RxUauw+N'
    
    # Variables
    base_url = f"{protocol}://{host}:{port}"
    login_url = f"{base_url}/security/user/authenticate"
    basic_auth = f"{user}:{password}".encode()
    
    #jsonApi
    jsonApi = None
    
    headers = {}
    allAgents = None

    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Functions
    def get_response(self, url, headers, verify=False):
        request_result = requests.get(url, headers=headers, verify=verify)
    
        if request_result.status_code == 200:
            return json.loads(request_result.content.decode())
        else:
            raise Exception(f"Error obtaining response: {request_result.json()}")
            
    def put_response(self, url, headers, verify=False):
        request_result = requests.put(url, headers=headers, verify=verify)
    
        if request_result.status_code == 200:
            return json.loads(request_result.content.decode())
        else:
            raise Exception(f"Error obtaining response: {request_result.json()}")
            
    def delete_response(self, url, headers, verify=False):
        request_result = requests.delete(url, headers=headers, verify=verify)
    
        if request_result.status_code == 200:
            return json.loads(request_result.content.decode())
        else:
            raise Exception(f"Error obtaining response: {request_result.json()}")
            
    def get_token(self):
        
        self.headers = {'Authorization': f'Basic {b64encode(self.basic_auth).decode()}'}
        self.headers['Authorization'] = f'Bearer {self.get_response(self.login_url, self.headers)["data"]["token"]}'

    def get_agents(self):
        url = self.base_url + '/agents'
        self.allAgents = self.get_response(url, self.headers)
        self.jsonApi = self.allAgents['data']
        return self.jsonApi
    
    def get_vul(self, agent_id):
        url = self.base_url + "/vulnerability/" + agent_id
        return self.get_response(url, self.headers)['data']
        
    
    def get_vul_by_crit(self, severity):
        total_vulnerabilities = 0
        url_start = "/vulnerability/"
        url_end = "/summary/severity"
        url_mid = ""
        
        for i in range(1, self.jsonApi["total_affected_items"]):
            url_mid = self.jsonApi["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            num_crit = self.get_response(url, self.headers)['severity'].get(severity)
            if( num_crit is not None):
                total_vulnerabilities += num_crit
        return total_vulnerabilities
    
    def get_vul_by_key(self, keyWord, limite = 10):
        url_start = "/vulnerability/"
        url_end = f"?pretty=true&search={keyWord}&select=name,condition,status,severity,cve&limit={limite}"
        url_mid = ""
        all_responses = {}
        
        for i in range(1, self.jsonApi["data"]["total_affected_items"]):
            url_mid = self.jsonApi["data"]["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            
            response = self.get_response(url, self.headers)['data']['affected_items']
            if( len(response) > 0 ):
                all_responses[url_mid] = {
                    'device_name': self.jsonApi["data"]["affected_items"][i]["name"],
                    'vulnerabilities': response
                    }
            
        return all_responses
        
    ''' ________________________ Pending testing ________________________ '''
    def upgrade_agents(self, agents):
        url = self.base_url + "/agents/upgrade?agents_list=" + agents
        response = self.put_response(url, self.headers)['data']
        return response
    
    def restart_agents(self, agents):
        url = self.base_url + "/agents/restart?agents_list=" + agents
        response = self.put_response(url, self.headers)['data']
        return response
    
    def delete_agents(self, agents, status, older_than = '7d'):
        url = self.base_url + "/agents?agents_list=" + agents + '&status=' + status + '&older_than=' + older_than
        response = self.put_response(url, self.headers)['data']
        return response
    
    def get_common_agents(self, keyWord, limite = 100):
        response = self.get_vul_by_key(keyWord, limite)
        return response.keys()
                
    def get_top_10_vul(self):
        all_agents_vul = {}
        agents = self.jsonApi["affected_items"][1:]
        for agent in agents:
            agent_vul = self.get_vul(agent['id'])
            for vuls in agent_vul.values():
                print(vuls)
                for vul in vuls:
                    if (vul['cve'] not in all_agents_vul):
                        all_agents_vul[vul['cve']] = 1
                    else:
                        all_agents_vul[vul['cve']] += 1
        
        print(all_agents_vul)
            
        

apiTest = apiHandler()

''' Generar tokens '''
apiTest.get_token()
#print(apiTest.headers["Authorization"])

''' Sacar la info de todos los agentes '''
jsonApi = apiTest.get_agents()
#print(jsonApi["data"].keys())
#print(jsonApi["data"]["total_affected_items"])
#print(jsonApi["data"]["affected_items"][11])

''' 1) Sacar el numero total de vulnerabilidades por severidad '''
#print(apiTest.get_vul_by_crit("High"))

''' 2) Sacar vulnerabilidades por palabra clave con limite default de 10 por agente '''
#print(apiTest.get_vul_by_key("Window"))

''' 3) '''
#print(apiTest.upgrade_agents('001,002'))
#print(apiTest.restart_agents('001,002'))
#STATUS AVAILABLES: "all" "active" "pending" "never_connected" "disconnected"
#print(apiTest.delete_agents('001,002', "disconnected))

''' 4) '''
#print(apiTest.get_common_agents("Windows"))

''' 5) '''
print(apiTest.get_top_10_vul())

''' 6) '''

''' 7) '''

''' 8) '''
