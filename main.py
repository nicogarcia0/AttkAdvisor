import requests
from scapy.all import *
import json
import os
icmpCount = 0
arpCount = 0
dhcpCount = 0
token = ""
id = ""
icmpIPs = []
icmpMACs = []
icmpIPST = ""
icmpMACST = ""
if(os.path.isfile("config.json")):
    with open ("config.json", "r") as config_json:
        config = json.load(config_json)
        token = config["token"]
        id = config["id"]
        print('Iniciando sniffing')
else:
    print('Debe crear la configuracion inicial del script.')
    token = input("Introduce el token de tu bot: ")
    id = input("Introduce el ID del chat al que quieres que se envien las alertas: ")
    print('Escribiendo configuracion...')
    config = {
        "token": token,
        "id": id
    }
    with open ("config.json", "w") as config_json:
        json.dump(config, config_json)
    print('Configuracion guardada, iniciando sniffing')





# Funcion bot telegram
def sendMessage(alertMessage, token, id):
    send_text = 'https://api.telegram.org/bot' + token + '/sendMessage?chat_id=' + id + '&parse_mode=Markdown&text=' + alertMessage
    requests.get(send_text)
    print('Alerta enviada: ' + alertMessage)

# Alerta paquetes ARP (Capa 2)
def arpAlert(pkt):
    global arpCount
    arpCount = arpCount + 1
    print(arpCount)
    if (arpCount >= 15):
        print('Multiples paquetes ARP, posible ataque') 
        sendMessage('Multiples paquetes ARP, posible ataque.', token, id)
        arpCount = 0
    

# Alerta paquetes ICMP (Capa 3)
def icmpAlert(pkt):
    if(pkt[ICMP].type == 8):
        global icmpCount
        global icmpIPs
        global icmpMACs
        icmpCount = icmpCount + 1
        print(icmpCount)
        icmpIP = pkt[0].getlayer(IP).src
        icmpMAC = pkt[0].getlayer(Ether).src
        icmpIPs.append(icmpIP)
        icmpMACs.append(icmpMAC)
        if (icmpCount >= 15):
            print('Multiples paquetes ICMP, posible ataque')
            icmpIPST = '\n'.join(str(e) for e in icmpIPs)
            icmpMACST = '\n'.join(str(e) for e in icmpMACs)
            sendMessage('Multiples paquetes ICMP, posible ataque. IPs: \n' + icmpIPST + '\n MACs: \n' + icmpMACST, token, id)
            icmpIPs = []
            icmpMACs = []
            icmpCount = 0

def dhcpAlert(pkt):
    if(pkt[DHCP].options[0][1] == 2):
        global dhcpCount
        dhcpCount = dhcpCount + 1
        print(dhcpCount)
        if (dhcpCount >= 5):
            print('Multiples dhcp offer detectados, posible ataque')
            sendMessage('Multiples paquetes de oferta de DHCP detectados, revisar la red.', token, id)
            dhcpCount = 0

# Bucle de ejecucion del sniffer

while True:
    sniff(filter="icmp", prn=icmpAlert)
    sniff(filter="arp" , prn=arpAlert)
    sniff(filter="dhcp", prn=dhcpAlert)
