import time
from scapy.all import sniff, IP
import pandas as pd
from collections import defaultdict

banner = r"""
        ______
     .-'      `-.
    /            \
   |              |
   |,  .-.  .-.  ,|
   | )(_o/  \o_)( |
   |/     /\     \|
   (_     ^^     _)
    \__|IIIIII|__/
     | \IIIIII/ |
     \          /
      `--------`

██████╗  █████╗ ██████╗ ████████╗██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
██████╔╝███████║██████╔╝   ██║   ███████║
██╔═══╝ ██╔══██║██╔══██╗   ██║   ██╔══██║
██║     ██║  ██║██║  ██║   ██║   ██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
                                         
"""
# Pipe the banner output to lolcat for colorized text
os.system(f'echo "{banner}" | lolcat')

print(banner)



THRESHOLD = 100  
TIME_WINDOW = 10  
BLOCKLIST = set()  


ip_request_count = defaultdict(int)
start_time = time.time()

def detect_dos(packet):
    global ip_request_count, start_time

    if IP in packet:
        ip_src = packet[IP].src

        
        if time.time() - start_time > TIME_WINDOW:
            ip_request_count.clear()
            start_time = time.time()

       
        ip_request_count[ip_src] += 1

       
        if ip_request_count[ip_src] > THRESHOLD:
            if ip_src not in BLOCKLIST:
                print(f"[!] DOS Detected from IP: {ip_src}")
                BLOCKLIST.add(ip_src)
                block_ip(ip_src)  
                log_attack(ip_src)  

def block_ip(ip):
    """Block the IP using system firewall."""
    import platform
    system = platform.system()

    if system == "Linux":
        
        import os
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        print(f"[+] Blocked IP {ip} on Linux.")
    elif system == "Windows":
       
        print(f"[+] Blocking IP {ip} on Windows is not implemented yet.")
    else:
        print(f"[-] Unsupported OS: {system}")

def log_attack(ip):
    """Log the detected attack to a CSV file."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "requests": ip_request_count[ip]
    }
    df = pd.DataFrame([log_entry])
    df.to_csv("dos_log.csv", mode="a", header=False, index=False)
    print(f"[+] Logged attack from {ip}.")

def start_monitoring():
    print("[*] Starting DOS Detection System...")
    print(f"[*] Monitoring network traffic (Threshold: {THRESHOLD} requests/{TIME_WINDOW} sec)...")
    sniff(prn=detect_dos, store=False)

if __name__ == "__main__":
    start_monitoring()
