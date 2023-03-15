from base64 import b64encode
import time;
import requests  
import urllib3
import os
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
from tkinter import *
from tkinter.ttk import *
import json
import numpy as np
class apiHandler:
    
    # Configuration
    endpoint = '/agents?select=lastKeepAlive&select=id&status=active'
    protocol = 'https'
    host = '' #type host ej. 192.168.0.1
    port = '55000'
    user = 'wazuh-wui'
    password = '' #type pass
    
    # Variables
    base_url = f"{protocol}://{host}:{port}"
    login_url = f"{base_url}/security/user/authenticate"
    basic_auth = f"{user}:{password}".encode()
    
    ts = None
    headers = {}
    allAgents = None

    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Functions
    def get_response(self, url, headers, verify=False):
        
        try:
            ts_actual = time.time()
            if(ts_actual - self.ts > 900):
                self.get_token()
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
            ts_actual = time.time()
            if(ts_actual - self.ts > 900):
                self.get_token()
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
            ts_actual = time.time()
            if(ts_actual - self.ts > 900):
                self.get_token()
            request_result = requests.delete(url, headers=headers, verify=verify)
        
            if request_result.status_code == 200:
                return json.loads(request_result.content.decode())
            else:
                raise Exception(f"Error obtaining response: {request_result.json()}")
        except Exception:
            print("ERROR Se detectó una exception en delete_response")
            return -1
            
    def get_token(self):
        self.ts = time.time()
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
        for i in range(1, self.allAgents['data']["total_affected_items"]):
            url_mid = self.allAgents['data']["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            num_crit = self.get_response(url, self.headers)['data']['severity'].get(severity)
            if( num_crit is not None):
                total_vulnerabilities += num_crit
        return total_vulnerabilities
    
    def get_vul_by_key(self, keyWord, limite = 10):
        url_start = "/vulnerability/"
        url_end = f"?pretty=true&search={keyWord}&select=name,condition,status,severity,cve&limit={limite}"
        url_mid = ""
        texto = ""
        #response = []
        for i in range(1, self.allAgents['data']["total_affected_items"]):
            url_mid = self.allAgents['data']["affected_items"][i]["id"]
            url = self.base_url + url_start + url_mid + url_end
            response = {}
            y = ""
            aux = len(self.get_response(url, self.headers)['data']['affected_items'])
            if aux > 0:
                response = (self.get_response(url, self.headers)['data']["affected_items"])
                y = json.dumps(response)
                y = y.replace(":"," =")
                y = y.replace("{"," ")
                y = y.replace("}"," ")
                y = y.replace("\'"," ")
                y = y.replace(",","\n")
            texto += f"User id {url_mid} has:\n\t{aux} vulnerabilities\n\t{y}\n\n"
            print(response)
        return texto
    
    def get_vul_by_key2(self, keyWord, limite = 10):
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
        
    def upgrade_agents(self, agents):
        url = self.base_url + "/agents/upgrade?agents_list=" + agents
        response = self.put_response(url, self.headers)['data']
        return response
    
    def restart_agents(self, agents):
        url = self.base_url + "/agents/restart?agents_list=" + agents
        response = self.put_response(url, self.headers)['data']
        return response
    
    def delete_agents(self, agents, status="never_connected", older_than = '7d'):
        url = self.base_url + "/agents?agents_list=" + agents + '&status=' + status + '&older_than=' + older_than
        response = self.put_response(url, self.headers)['data']
        return response
    
    def get_common_agents(self, keyWord, limite = 10):
        response = self.get_vul_by_key2(keyWord, limite)
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
#print(jsonApi["data"]["affected_items"][12])
print("Todo va bien")

''' 1) Sacar el numero total de vulnerabilidades por severidad '''
#print(apiTest.get_vul_by_crit("Low"))

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

'''Menu en barra del top'''
def menuBar(ventana):
    menubar = Menu(ventana)
    ventana.config(menu=menubar)

    def close_window():
        ventana.destroy()

    filemenu = Menu(menubar, tearoff=0)
    filemenu.add_command(label="Nuevo")
    filemenu.add_command(label="Abrir")
    filemenu.add_command(label="Guardar")
    filemenu.add_separator()
    filemenu.add_command(label="Salir", command=close_window)

    editmenu = Menu(menubar, tearoff=0)
    editmenu.add_command(label="Cortar")
    editmenu.add_command(label="Copiar")
    editmenu.add_command(label="Pegar")

    helpmenu = Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Ayuda")
    helpmenu.add_separator()
    helpmenu.add_command(label="Acerca de...")

    menubar.add_cascade(label="Archivo", menu=filemenu)
    menubar.add_cascade(label="Editar", menu=editmenu)
    menubar.add_cascade(label="Ayuda", menu=helpmenu)

'''Scrolls de proyecto final JoshuaToken copy.ipynb'''
def scrolls(pantalla, columna):
    scrollbar = ttk.Scrollbar(orient = tk.VERTICAL, command = pantalla.yview)
    pantalla.config(yscrollcommand = scrollbar.set)
    scrollbar.grid(row=5, column = columna, ipady=276)

'''Info a mostrar en la tercer pantalla'''
def get_Info( pantalla, param_info, ):
    pantalla.configure( state = "normal")
    pantalla.delete('1.0', tk.END)
    param_info = param_info.lower()
    if(param_info == "configuration"): 
        json_string = json.dumps(apiTest.get_config(), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f"Information about {param_info}\n{json_string}")
        return 
    if(param_info == "logs"): 
        json_string = json.dumps(apiTest.get_logs(), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f"Information about {param_info}\n{json_string}")
        return 
    if(param_info == "sumary"): 
        json_string = json.dumps(apiTest.get_resume(), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f"Information about {param_info}\n{json_string}")
        return 
    if(param_info == "groups"): 
        json_string = json.dumps(apiTest.get_groups(), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f"Information about {param_info}\n{json_string}")
        return 
    if(param_info == "status"): 
        json_string = json.dumps(apiTest.get_tasks_status(), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f"Information about {param_info}\n{json_string}")
        return 
    pantalla.configure( state = "disabled")

def get_Info_Server( pantalla, param_info, agent):
    pantalla.configure( state = "normal")
    pantalla.delete('1.0', tk.END)
    param_info = param_info.lower()
    json_string = json.dumps(apiTest.get_sysCollector(agent, param_info), skipkeys = True, allow_nan = True, indent = 4)
    pantalla.insert(tk.END, f"Information about {param_info}\n{json_string}")
    pantalla.configure( state = "disabled")

'''Función botón acción sobre agente'''
def activty_Agent(pantalla, param_accion_agente, palabra):
    pantalla.configure(state="normal")
    pantalla.delete('1.0', tk.END)
    param_accion_agente = param_accion_agente.lower()
    if(param_accion_agente=="update"): 
        json_string = json.dumps(apiTest.upgrade_agents(palabra), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f" {param_accion_agente} Agent...\n{json_string}")
        return apiTest.upgrade_agents(palabra)
    
    if(param_accion_agente=="delete"): 
        json_string = json.dumps(apiTest.delete_agents(palabra), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f" {param_accion_agente} Agent...\n{json_string}")
        return apiTest.delete_agents(palabra)
    
    if(param_accion_agente=="restart"): 
        json_string = json.dumps(apiTest.restart_agents(palabra), skipkeys = True, allow_nan = True, indent = 4)
        pantalla.insert(tk.END, f" {param_accion_agente} Agent...\n{json_string}")
        return apiTest.restart_agents(palabra)
    
    pantalla.configure( state = "disabled")

'''Función para mostrar las vulneranilidades por nivel de riesgo'''
def get_Vulnerabilities(pantalla, param_riesgo, dicc):
    pantalla.configure(state = "normal")
    pantalla.delete('1.0', tk.END)
    pantalla.insert(tk.END, f"The total number of {param_riesgo} vulnerabilities is: {dicc.get(param_riesgo)}")
    pantalla.configure( state = "disabled")

'''Función botón lista agentes'''
def get_AgentList(pantalla,palabra):
    pantalla.configure(state="normal")
    pantalla.delete('1.0', tk.END)
    common = apiTest.get_common_agents(palabra)
    pantalla.insert(tk.END, f"Printing all Agents with Windows\nvulnerabilities in common:\n\n{common}")
    pantalla.configure(state="disabled")

'''Función botón TOP 10 vulnerabillidades'''
def get_T10Agents(pantalla):
    pantalla.configure(state="normal")
    pantalla.delete('1.0', tk.END)
    pantalla.insert(tk.END, f"Printing Top 10 vulnerable agents...\n")
    t10Agents = apiTest.get_top_agents()
    t10Agents = str(t10Agents)
    t10Agents = t10Agents.replace("(","")
    t10Agents = t10Agents.replace(")","")
    t10Agents = t10Agents.replace("{","")
    t10Agents = t10Agents.replace("}","")
    t10Agents = t10Agents.replace(":","")
    t10Agents = t10Agents.replace("'","")
    t10Agents = t10Agents.replace(",","\n")
    pantalla.insert(tk.END, f"\n{t10Agents}")
    pantalla.configure(state="disabled")

'''Función botón TOP 10 vulnerabillidades'''
def get_T10Vulnerabilities(pantalla1):
    pantalla1.configure(state="normal")
    pantalla1.delete('1.0', tk.END)
    tuplle = apiTest.get_top_10_vul()
    tuplle = str(tuplle)
    tuplle = tuplle.replace("[","")
    tuplle = tuplle.replace("]","")
    tuplle = tuplle.replace("(","")
    tuplle = tuplle.replace(")","")
    tuplle = tuplle.replace(",","\n")
    pantalla1.insert(tk.END, f"Printing Top 10 Vulnerabilities...\n\n{str(tuplle)}")
    pantalla1.configure(state="disabled")

'''#Función botón buscar vulnerabilidades'''
def search_Vulnerabilities( pantalla1, palabra ):
    pantalla1.configure(state="normal")
    pantalla1.delete('1.0', tk.END)
    pantalla1.insert(tk.END, f"Searching vulnerabilities by {palabra}:\n")
    pantalla1.insert(tk.END, apiTest.get_vul_by_key(palabra))
    pantalla1.configure(state="disabled")

"Nos devuelve el numero de vulnerabilidades"
def get_arr_vul_by_level(lista_riesgo):
    arr_vul_by_level = {}
    for i in lista_riesgo:
        arr_vul_by_level.update({i:apiTest.get_vul_by_crit(i)})
    return arr_vul_by_level



