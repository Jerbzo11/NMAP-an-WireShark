import socket
from urllib.parse import urlparse
from scapy.all import *

def get_ip_from_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(':')[0] if ':' in parsed_url.netloc else parsed_url.netloc
    ip = socket.gethostbyname(domain)
    return ip

def website_scan(url, ports):
    target_ip = get_ip_from_url(url)
    print(f"Scanning {url} ({target_ip})...")
    
    for port in ports:
        # Craft a TCP SYN packet to the target IP and port
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Send the packet and wait for a response
        response = sr1(packet, timeout=1, verbose=0)
        
        # Check if a response was received
        if response is not None:
            # Analyze the response packet
            if response.haslayer(TCP):
                # Check the TCP flags to determine the state of the port
                if response[TCP].flags == 0x12:
                    print(f"Port {port} is open")
                else:
                    print(f"Port {port} is closed")
            else:
                print(f"Unable to determine state of port {port}")
        else:
            print(f"No response received for port {port}")

# Example usage
url = input("Enter URL: ")
ports_to_scan = [80, 443, 8080]  # Ports to scan

website_scan(url, ports_to_scan)
