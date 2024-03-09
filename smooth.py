from scapy.all import ARP, Ether, srp
import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

init(autoreset=True)

ports_info = {
    21: "FTP - File Transfer Protocol",
    22: "SSH - Secure Shell",
    23: "Telnet - Unencrypted text communications",
    25: "SMTP - Simple Mail Transfer Protocol",
    53: "DNS - Domain Name System",
    80: "HTTP - Hypertext Transfer Protocol",
    110: "POP3 - Post Office Protocol version 3",
    139: "NetBIOS - Network Basic Input/Output System",
    445: "SMB - Server Message Block",
    443: "HTTPS - HTTP Secure",
    3306: "MySQL - Database Server",
    3389: "RDP - Remote Desktop Protocol"
}

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror: 
        return None

def scan_ip(ip, ports):
    hostname = get_hostname(ip)
    hostname_info = f" ({hostname})" if hostname else ""
    try:
        socket.setdefaulttimeout(0.5)
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex((ip, port))
                if result == 0:
                    description = ports_info.get(port, "Unknown service")
                    print(f"{Fore.GREEN}{ip}{hostname_info}:{Fore.YELLOW}{port} {Fore.CYAN}{description}")
    except Exception as e:
        print(f"{Fore.RED}Error scanning {ip}: {e}")

def arp_scan(target_ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
    result = srp(packet, timeout=2, verbose=False)[0]
    clients = []
    for sent, received in result:
        clients.append(received.psrc)
    return clients

target_ip = "192.168.1.1/24"
ports = [21, 22, 23, 25, 53, 80, 110, 139, 445, 443, 3306, 3389]

print(f"{Fore.BLUE}Scanning network for devices...")
active_ips = arp_scan(target_ip)
print(f"{Fore.GREEN}Found {len(active_ips)} devices.")

print(f"{Fore.BLUE}Scanning for open ports...")
with ThreadPoolExecutor(max_workers=10) as executor:
    for ip in active_ips:
        executor.submit(scan_ip, ip, ports)
