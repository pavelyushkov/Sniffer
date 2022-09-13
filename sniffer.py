import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn = process_sniff_packet)
    
def process_sniff_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        method = str(packet[http.HTTPRequest].Method)
        keywords = ["UDP", "POST", "GET", "TCP", "ARP"]
        for keyword in keywords:
            if keyword in method: 
                print("Получатель: ", packet[scapy.IP].src, ", Отправитель: ", packet[scapy.IP].dst, ", Метод: ", method[2:-1])
                print("Сайт: http://", str((packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path))[2:-1], "\n")
            
sniff("Ethernet")

