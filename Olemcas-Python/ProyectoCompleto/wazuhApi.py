import json
from base64 import b64encode
import requests  # To install requests, use: pip install requests
import urllib3
import numpy as np
from main import * 
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
    
    headers = {}
    allAgents = None

    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Functions
    def get_response(self, url, headers, verify=False):
        
        try:
            request_result = requests.get(url, headers=headers, verify=verify)
        
            if request_result.status_code == 200:
                return json.loads(request_result.content.decode())
            else:
                raise Exception(f"Error obtaining response: {request_result.json()}")
        except Exception:
            print("ERROR Se detectó una exception en get_response")
            return -1
        
            
    def put_response(self, url, headers, verify=False):
        
        try:
            request_result = requests.put(url, headers=headers, verify=verify)
        
            if request_result.status_code == 200:
                return json.loads(request_result.content.decode())
            else:
                raise Exception(f"Error obtaining response: {request_result.json()}")
        except Exception:
            print("ERROR Se detectó una exception en put_response")
            return -1
            
    def delete_response(self, url, headers, verify=False):
        
        try:
            request_result = requests.delete(url, headers=headers, verify=verify)
        
            if request_result.status_code == 200:
                return json.loads(request_result.content.decode())
            else:
                raise Exception(f"Error obtaining response: {request_result.json()}")
        except Exception:
            print("ERROR Se detectó una exception en delete_response")
            return -1
            
    def get_token(self):
        
        self.headers = {'Authorization': f'Basic {b64encode(self.basic_auth).decode()}'}
        self.headers['Authorization'] = f'Bearer {self.get_response(self.login_url, self.headers)["data"]["token"]}'

    def get_agents(self):
        url = self.base_url + '/agents'
        self.allAgents = self.get_response(url, self.headers)
        return self.allAgents
    
    def get_vul_by_crit(self, severity):
        total_vulnerabilities = 0
        url_start = "/vulnerability/"
        url_end = "/summary/severity"
        url_mid = ""
        
        for i in range(1, jsonApi["data"]["total_affected_items"]):
            url_mid = jsonApi["data"]["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            num_crit = self.get_response(url, self.headers)['data']['severity'].get(severity)
            if( num_crit is not None):
                total_vulnerabilities += num_crit
        return total_vulnerabilities
    
    def get_vul_by_key(self, keyWord, limite = 10):
        url_start = "/vulnerability/"
        url_end = f"?pretty=true&search={keyWord}&select=name,condition,status,severity,cve&limit={limite}"
        url_mid = ""
        
        for i in range(1, jsonApi["data"]["total_affected_items"]):
            url_mid = jsonApi["data"]["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            
            response = self.get_response(url, self.headers)['data']
            print(response)
        
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
        response = self.delete_response(url, self.headers)['data']
        return response
    
    ''' Punto 6 '''
    def get_top_agents(self):
        url_start = "/vulnerability/"
        url_end = "/summary/severity"
        url_mid = ""
        vul_array = []
        
        for i in range(1, jsonApi["data"]["total_affected_items"]):
            url_mid = jsonApi["data"]["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            num_vul = self.get_response(url, self.headers)
            vul_array.append(0)
            if (num_vul != -1 and bool(num_vul['data']['severity'])):
                for element in num_vul['data']['severity'].values():
                    vul_array[i-1] += int(element)
            
        vul_array = np.array(vul_array)
        index = (-vul_array).argsort()
        top = {}
        for i in range(10):
            top[jsonApi["data"]["affected_items"][index[i] + 1]['id']] = {
                'name': jsonApi["data"]["affected_items"][index[i] + 1]['name'], 
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
#print(jsonApi["data"]["affected_items"][12])

''' 1) Sacar el numero total de vulnerabilidades por severidad '''
#print(apiTest.get_vul_by_crit("High"))

''' 2) Sacar vulnerabilidades por palabra clave con limite default de 10 por agente '''
#print(apiTest.get_vul_by_key("Window"))

''' 3) '''
#print(apiTest.upgrade_agents('001,002'))
#print(apiTest.restart_agents('017'))
#print(apiTest.delete_agents('017', 'never_connected'))

''' 6) Sacar el top 10 de agentes con más vulnerabilidades '''
#print(apiTest.get_top_agents())

''' 7) Mostrar el estado del servidor de Wazuh '''
#print(json.dumps(apiTest.get_config(), indent=4, sort_keys=True))
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