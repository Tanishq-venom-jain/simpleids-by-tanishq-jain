from scapy.all import *
import os
import logging
import configparser
import smtplib
from email.mime.text import MIMEText
import requests
from collections import defaultdict
import time
import argparse
import subprocess  # Import subprocess module for non-blocking execution

# Banner for Simple IDS by Tanishq Jain
print("""
     ____  _     _ _ _ _____ _      
    |  _ \| |__ (_) | |_   _| |     
    | | | | '_ \| | | | | | | |     
    | |_| | | | | | | | | | | |     
    |____/|_| |_|_|_| |_| |_|     
                                  
Simple IDS by Tanishq Jain
""")

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')
sniffing_filter = config['DEFAULT']['SniffingFilter']
blocked_ips_file_path = config['DEFAULT']['BlockedIPsFilePath']

# Set up logging
logging.basicConfig(filename='syn_flood.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Fill in your email credentials
email_sender = 'your_email@gmail.com'
email_password = 'your_email_password'  # Replace with your actual email password

# Fill in your Telegram credentials
telegram_bot_token = 'YOUR_TELEGRAM_BOT_TOKEN'
telegram_chat_id = 'YOUR_CHAT_ID'

blocked_ips = set()  # Set to keep track of blocked IPs
syn_count = defaultdict(int)  # Dictionary to keep track of SYN packets
traffic = defaultdict(int)  # Dictionary to keep track of traffic
THRESHOLD = 100  # Threshold for SYN packets
BLOCK_DURATION = 300  # Block duration in seconds for Slowloris attack
SLOWLORIS_THRESHOLD = 20  # Threshold for Slowloris attack

# Function to send an email alert
def send_alert(src_ip, attack_type):
    msg = MIMEText(f"Attack detected from {src_ip}! Type: {attack_type}")
    msg['Subject'] = 'Attack Alert'
    msg['From'] = email_sender
    msg['To'] = email_sender

    with smtplib.SMTP('smtp.gmail.com', 587) as s:
        s.starttls()
        s.login(email_sender, email_password)
        s.send_message(msg)

# Function to send a Telegram alert
def send_telegram_alert(src_ip, attack_type):
    url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage'
    text = f'Attack detected from {src_ip}! Type: {attack_type}'
    payload = {'chat_id': telegram_chat_id, 'text': text}
    response = requests.post(url, data=payload)
    if response.status_code != 200:
        logging.error(f'Failed to send Telegram alert: {response.content}')

slowloris_connections = defaultdict(int)  # Dictionary to keep track of Slowloris connections
arp_cache = {}  # Dictionary to keep track of ARP cache
dns_queries = defaultdict(set)  # Dictionary to keep track of DNS queries

# Function to detect Slowloris attack
def detect_slowloris(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 2:  # TCP packet with SYN flag
        src_ip = packet[IP].src
        if src_ip in slowloris_connections:
            slowloris_connections[src_ip] += 1
            if slowloris_connections[src_ip] > SLOWLORIS_THRESHOLD:
                logging.info(f"Slowloris attack detected from {src_ip}! Blocking IP...")
                block_ip(src_ip)
                print(f"Slowloris attack detected from {src_ip}! Blocking IP...")
                send_alert(src_ip, 'Slowloris')
                send_telegram_alert(src_ip, 'Slowloris')
                slowloris_connections.pop(src_ip)  # Reset the counter after blocking

# Function to detect SYN/ACK attack (DoS)
def detect_syn_ack_attack(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 18:  # TCP packet with SYN/ACK flags set
        src_ip = packet[IP].src
        if src_ip not in blocked_ips:
            logging.info(f"SYN/ACK attack detected from {src_ip}! Blocking IP...")
            block_ip(src_ip)
            print(f"SYN/ACK attack detected from {src_ip}! Blocking IP...")
            send_alert(src_ip, 'SYN/ACK')
            send_telegram_alert(src_ip, 'SYN/ACK')

# Function to detect UDP flood (DoS)
def detect_udp_flood(packet):
    if packet.haslayer(UDP):
        src_ip = packet[IP].src
        if src_ip not in blocked_ips:
            logging.info(f"UDP flood attack detected from {src_ip}! Blocking IP...")
            block_ip(src_ip)
            print(f"UDP flood attack detected from {src_ip}! Blocking IP...")
            send_alert(src_ip, 'UDP Flood')
            send_telegram_alert(src_ip, 'UDP Flood')

# Function to detect ARP Spoofing (MitM)
def detect_arp_spoofing(packet):
    if packet.haslayer(ARP):
        src_mac = packet[ARP].hwsrc
        src_ip = packet[ARP].psrc
        if src_ip not in arp_cache:
            arp_cache[src_ip] = src_mac
        elif arp_cache[src_ip] != src_mac:
            logging.info(f"ARP Spoofing attack detected from {src_ip}! Blocking IP...")
            block_ip(src_ip)
            print(f"ARP Spoofing attack detected from {src_ip}! Blocking IP...")
            send_alert(src_ip, 'ARP Spoofing')
            send_telegram_alert(src_ip, 'ARP Spoofing')

# Function to detect DNS Spoofing (MitM)
def detect_dns_spoofing(packet):
    if packet.haslayer(DNSQR):
        src_ip = packet[IP].src
        query = packet[DNSQR].qname.decode('utf-8')
        if src_ip not in dns_queries:
            dns_queries[src_ip] = set()
        if query not in dns_queries[src_ip]:
            dns_queries[src_ip].add(query)
        else:
            logging.info(f"DNS Spoofing attack detected from {src_ip}! Blocking IP...")
            block_ip(src_ip)
            print(f"DNS Spoofing attack detected from {src_ip}! Blocking IP...")
            send_alert(src_ip, 'DNS Spoofing')
            send_telegram_alert(src_ip, 'DNS Spoofing')

# Function to display packet information
def display_packet_info(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Incoming TCP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Incoming UDP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        elif ICMP in packet:
            print(f"Incoming ICMP packet: {src_ip} -> {dst_ip}")
    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        print(f"Incoming ARP packet: {src_ip} -> {dst_ip}")

# Function to unblock an IP address
def unblock_ip(selected_ip):
    if selected_ip in blocked_ips:
        logging.info(f"Unblocking IP: {selected_ip}")
        os.system(f"iptables -D INPUT -s {selected_ip} -j DROP")  # Unblock IP
        print(f"Unblocked IP: {selected_ip}")
        update_blocked_ips_file()
        blocked_ips.remove(selected_ip)  # Remove the IP from the set of blocked IPs

# Function to block an IP address
def block_ip(ip_address):
    subprocess.Popen(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])  # Non-blocking execution

    # Add IP to set of blocked IPs
    blocked_ips.add(ip_address)
    update_blocked_ips_file()

    # Write the IP address to the file
    with open(blocked_ips_file_path, "a") as file:
        file.write(f"{ip_address}\n")

# Function to update the blocked IPs file
def update_blocked_ips_file():
    with open(blocked_ips_file_path, "w") as file:  # Open the file in write mode
        for ip in blocked_ips:
            file.write(f"{ip}\n")  # Write the remaining IP addresses to the file

# Function to start sniffing
def start_sniffing(background=False):
    try:
        print("Starting the IDS. Press Ctrl+C to exit.")
        while True:
            sniff(filter=sniffing_filter, prn=detect_slowloris, timeout=1)
            sniff(filter=sniffing_filter, prn=detect_syn_ack_attack, timeout=1)
            sniff(filter=sniffing_filter, prn=detect_udp_flood, timeout=1)
            sniff(filter="arp", prn=detect_arp_spoofing, timeout=1)
            sniff(filter="udp and port 53", prn=detect_dns_spoofing, timeout=1)
            if not background:
                sniff(filter=sniffing_filter, prn=display_packet_info, store=0)
    except KeyboardInterrupt:
        print("Exiting the IDS.")

def parse_args():
    parser = argparse.ArgumentParser(description='Network IDS for SYN Flood, Slowloris, and more.')
    parser.add_argument('--start', action='store_true', help='Start the network IDS')
    parser.add_argument('--unblock', type=str, metavar='IP', help='Unblock the specified IP address')
    parser.add_argument('--background', action='store_true', help='Run the IDS in the background (suppress packet display)')
    parser.add_argument('--helpme', action='help', help='Show this help message and exit')
    return parser.parse_args()

# Main function
def main():
    args = parse_args()

    if args.start:
        start_sniffing(background=args.background)
    elif args.unblock:
        unblock_ip(args.unblock)

if __name__ == "__main__":
    main()
