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
            num_crit = self.get_response(url, self.headers)['data']['severity'].get(severity)
            if( num_crit is not None):
                total_vulnerabilities += num_crit
        return total_vulnerabilities
    
    def get_vul_by_key(self, keyWord, limite = 10):
        url_start = "/vulnerability/"
        url_end = f"?pretty=true&search={keyWord}&select=name,condition,status,severity,cve&limit={limite}"
        url_mid = ""
        all_responses = {}
        
        for i in range(1, self.jsonApi["total_affected_items"]):
            url_mid = self.jsonApi["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            
            response = self.get_response(url, self.headers)['data']['affected_items']
            if( len(response) > 0 ):
                all_responses[url_mid] = {
                    'device_name': self.jsonApi["affected_items"][i]["name"],
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
        common = []
        for key in response.keys():
            common.append( response[key]['device_name'] )
        return common
                
    def get_top_10_vul(self):
        all_agents_vul = {}
        agents = self.jsonApi["affected_items"][1:]
        for agent in agents:
            agent_vul = self.get_vul(agent['id'])['affected_items']
            for vul in agent_vul:
                if (vul['cve'] not in all_agents_vul):
                    all_agents_vul[f'{vul["cve"]}'] = 1
                else:
                    all_agents_vul[f'{vul["cve"]}'] += 1
        
        all_agents_vul_sorted = sorted(all_agents_vul.items(), key=lambda x:x[1], reverse=True)
        return all_agents_vul_sorted[:10]
    
    ''' Punto 6 '''
    def get_top_agents(self):
        url_start = "/vulnerability/"
        url_end = "/summary/severity"
        url_mid = ""
        vul_array = []
        
        for i in range(1, self.jsonApi["total_affected_items"]):
            url_mid = self.jsonApi["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            num_vul = self.get_response(url, self.headers)
            vul_array.append(0)
            if (num_vul != -1 and bool(num_vul['data']['severity'])):
                for element in num_vul['data']['severity'].values():
                    vul_array[i-1] += int(element)
            
        vul_array = np.array(vul_array)
        index = (-vul_array).argsort()
        top = {}
        n = 10
        if(len(self.jsonApi["affected_items"]) <= 10):
            n = len(self.jsonApi["affected_items"])-1
        for i in range(n):
            top[self.jsonApi["affected_items"][index[i] + 1]['id']] = {
                'name': self.jsonApi["affected_items"][index[i] + 1]['name'], 
                'num_of_vul': vul_array[index[i]]}
        return top
    
    ''' Punto 7 '''
    def get_config(self):
        url = self.base_url + "/manager/configuration"
        response = self.get_response(url, self.headers)['data']
        return response
    
    def get_logs(self):
        url = self.base_url + "/manager/logs"
        response = self.get_response(url, self.headers)['data']
        return response
    
    def get_resume(self):
        url = self.base_url + "/manager/logs/summary"
        response = self.get_response(url, self.headers)['data']
        return response
    
    def get_groups(self):
        url = self.base_url + "/groups"
        response = self.get_response(url, self.headers)['data']
        return response
    
    def get_tasks_status(self):
        url = self.base_url + "/tasks/status"
        response = self.get_response(url, self.headers)['data']
        return response
    
    
    '''Extras '''
    def get_sysCollector(self, agent, endpoint):
        url = self.base_url + '/syscollector/' + agent + '/' + endpoint
        response = self.get_response(url, self.headers)['data']
        return response
            
        

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
#print(apiTest.delete_agents('001,002', "never_connected"))

''' 4) '''
#print(apiTest.get_common_agents("Windows"))

''' 5) '''
#print(apiTest.get_top_10_vul())

''' 6) Sacar el top 10 de agentes con más vulnerabilidades '''
#print(apiTest.get_top_agents())

''' 7) Mostrar el estado del servidor de Wazuh '''
#print(apiTest.get_config())
#print(apiTest.get_logs())
#print(apiTest.get_resume())
#print(apiTest.get_groups())
#print(apiTest.get_tasks_status())


''' Extras ''' 
#print(apiTest.get_sysCollector('016', 'hardware'))
#print(apiTest.get_sysCollector('016', 'hotfixes'))
#print(apiTest.get_sysCollector('016', 'netaddr'))
#print(apiTest.get_sysCollector('016', 'netiface'))
#print(apiTest.get_sysCollector('016', 'netproto'))
#print(apiTest.get_sysCollector('016', 'os'))
#print(apiTest.get_sysCollector('016', 'packages'))
#print(apiTest.get_sysCollector('016', 'ports'))
#print(apiTest.get_sysCollector('016', 'processes'))
