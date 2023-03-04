#from wazuhApi import *
from main import *
from base64 import b64encode
import json
import requests  
import urllib3
import os
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
from tkinter import *
import pprint
from tkinter.ttk import *
import json

''' Sacar el numero total de vulnerabilidades por severidad '''
#print(json.dumps(apiTest.get_vul_by_crit("High"), indent=4, sort_keys=True))

''' Sacar vulnerabilidades por palabra clave con limite default de 10 por agente '''
#print(json.dumps(apiTest.get_vul_by_key("Adobe"), indent=4, sort_keys=True))

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

'''Pruebas de DanyToken.ipynb'''
def high(listbox):
    with open('JsonPrueba.json') as file:
        data = json.load(file)
        JP = (json.dumps(data, indent=4, sort_keys=True))
    datos_diccionario = json.loads(JP)
    value = datos_diccionario["data"]["affected_items"]
    listbox.insert(
        tk.END, *(
            f'ID: {value[i]["id"]}, \n Last Pick: {value[i]["lastKeepAlive"]}' 
            for i in range(len(value))
        )
    )

'''Scrolls de proyecto final JoshuaToken copy.ipynb'''
def scrolls(pantalla, columna):
    scrollbar = ttk.Scrollbar(orient = tk.VERTICAL, command = pantalla.yview)
    pantalla.config(yscrollcommand = scrollbar.set)
    scrollbar.grid(row=5, column = columna, ipady=276)

'''Info a mostrar en la tercer pantalla'''
def get_Info(pantalla, param_info ):
    pantalla.configure( state = "normal")
    pantalla.delete('1.0', tk.END)
    for i in range(2000):
        pantalla.insert( tk.END, f"Printing {param_info} Agents...{i}\n")
    pantalla.configure( state = "disabled")

'''Función botón acción sobre agente'''
def activty_Agent(pantalla, param_accion_agente):
    pantalla.configure(state="normal")
    pantalla.delete('1.0', tk.END)
    pantalla.insert(tk.END, f" {param_accion_agente} Agent...")
    pantalla.configure( state = "disabled")

'''Función para mostrar las vulneranilidades por nivel de riesgo'''
def get_Vulnerabilities(pantalla, param_riesgo):
    pantalla.configure(state = "normal")
    pantalla.delete('1.0', tk.END)
    pantalla.insert(tk.END, f"Printing {param_riesgo} vulnerabilities...")
    pantalla.configure( state = "disabled")

'''Función botón lista agentes'''
def get_AgentList(pantalla):
    pantalla.configure(state="normal")
    pantalla.delete('1.0', tk.END)
    pantalla.insert(tk.END,"Printing ALL Agents...")
    pantalla.configure(state="disabled")

'''Función botón TOP 10 vulnerabillidades'''
def get_T10Agents(pantalla):
    pantalla.configure(state="normal")
    pantalla.delete('1.0', tk.END)
    pantalla.insert(tk.END,"Printing Top 10 vulnerable agents...")
    pantalla.configure(state="disabled")

'''Función botón TOP 10 vulnerabillidades'''
def get_T10Vulnerabilities(pantalla1):
    pantalla1.configure(state="normal")
    pantalla1.delete('1.0', tk.END)
    pantalla1.insert(tk.END,"Printing Top 10 Vulnerabilities...")
    pantalla1.configure(state="disabled")

'''#Función botón buscar vulnerabilidades'''
def search_Vulnerabilities(pantalla1):
    pantalla1.configure(state="normal")
    pantalla1.delete('1.0', tk.END)
    pantalla1.insert(tk.END,"Searching...")
    pantalla1.configure(state="disabled")






