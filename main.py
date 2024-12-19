import argparse
import re
import subprocess
from time import sleep
from scapy.all import Ether, srp, ARP
from _imports_ import banner

parser = argparse.ArgumentParser()
ip_help = "Destination IP Address. E.g. 192.168.1.1"

parser.add_argument("-ip", type=str, required=True, help=ip_help)
args = parser.parse_args()

class ScanSpecificAdd:
    def __init__(self, ip):

        try:
            arp = ARP(pdst=ip) 
            ether = Ether(dst="ff:ff:ff:ff:ff:ff") 
            packet = ether/arp 
            result = srp(packet, timeout=3)[1]
        except Exception as e:
            print(f"Error scanning subnet {ip}: Network timeout or no response")
            return
        for sent, received in result:
            print(f"IP: {received.psrc} MAC: {received.hwsrc}")

class ScanSpecificSubnet:
    def __init__(self, ip):
        try :
            arp = ARP(pdst=ip) 
            ether = Ether(dst="ff:ff:ff:ff:ff:ff") 
            packet = ether/arp 

            results = srp(packet, timeout=3)[0] 
        except Exception as e:
            print(f"Error scanning subnet {ip}: Network timeout or no response")
            return
        clients = []
        for sent, received in results:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        print(clients)

if __name__ == "__main__":
    banner()
    ListedAddress = re.split(r"[.|/]", args.ip) 

    for address in ListedAddress:
        if int(address) in range(0,256) and len(ListedAddress) == 4 or len(ListedAddress) == 5:
            continue
        else:
            print("Follow the IP Address format ; 192.168.1.1 for single IP\n or 192.168.1.0/24 for subnet")
            sleep(3)
            exit()

    

   

