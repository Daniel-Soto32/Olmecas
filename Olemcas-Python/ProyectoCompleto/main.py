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

def high(listbox):
    #print("Hello world!")
    #listbox = tk.Listbox(font=fontStyle_Text)
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
    print("Se ejecutó High")