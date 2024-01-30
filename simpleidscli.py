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
import subprocess

# Banner for Simple IDS by Tanishq Jain
print("""
  ________  ___  _____ ______   ________  ___       _______           ___  ________  ________                                                    
|\   ____\|\  \|\   _ \  _   \|\   __  \|\  \     |\  ___ \         |\  \|\   ___ \|\   ____\                                                   
\ \  \___|\ \  \ \  \\\__\ \  \ \  \|\  \ \  \    \ \   __/|        \ \  \ \  \_|\ \ \  \___|_                                                  
 \ \_____  \ \  \ \  \\|__| \  \ \   ____\ \  \    \ \  \_|/__       \ \  \ \  \ \\ \ \_____  \                                                 
  \|____|\  \ \  \ \  \    \ \  \ \  \___|\ \  \____\ \  \_|\ \       \ \  \ \  \_\\ \|____|\  \                                                
    ____\_\  \ \__\ \__\    \ \__\ \__\    \ \_______\ \_______\       \ \__\ \_______\____\_\  \                                               
   |\_________\|__|\|__|     \|__|\|__|     \|_______|\|_______|        \|__|\|_______|\_________\                                              
 _____________|___    ___      _________  ________  ________   ___  ________  ___  ___\|_________|            ___  ________  ___  ________      
|\   __  \    |\  \  /  /|    |\___   ___|\   __  \|\   ___  \|\  \|\   ____\|\  \|\  \|\   __  \            |\  \|\   __  \|\  \|\   ___  \    
\ \  \|\ /_   \ \  \/  / /    \|___ \  \_\ \  \|\  \ \  \\ \  \ \  \ \  \___|\ \  \\\  \ \  \|\  \           \ \  \ \  \|\  \ \  \ \  \\ \  \   
 \ \   __  \   \ \    / /          \ \  \ \ \   __  \ \  \\ \  \ \  \ \_____  \ \   __  \ \  \\\  \        __ \ \  \ \   __  \ \  \ \  \\ \  \  
  \ \  \|\  \   \/  /  /            \ \  \ \ \  \ \  \ \  \\ \  \ \  \|____|\  \ \  \ \  \ \  \\\  \      |\  \\_\  \ \  \ \  \ \  \ \  \\ \  \ 
   \ \_______\__/  / /               \ \__\ \ \__\ \__\ \__\\ \__\ \__\____\_\  \ \__\ \__\ \_____  \     \ \________\ \__\ \__\ \__\ \__\\ \__\
    \|_______|\___/ /                 \|__|  \|__|\|__|\|__| \|__|\|__|\_________\|__|\|__|\|___| \__\     \|________|\|__|\|__\|__|\|__| \|__|
             \|___/                                                  \|_________|               \|__|                                          
                                                                                                                                                
                                                                                                                                                
Simple IDS by Tanishq Jain
""")

def update_config_with_api_keys():
    # Update NVD API credentials
    config['DEFAULT']['NvdApiKey'] = input("Enter your NVD API key: ")

    # Update GitHub API credentials
    config['DEFAULT']['GitHubApiToken'] = input("Enter your GitHub API token: ")

    with open('config.ini', 'w') as config_file:
        config.write(config_file)

def read_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config

def load_credentials():
    config = read_config()

    sniffing_filter = config['DEFAULT']['SniffingFilter']
    blocked_ips_file_path = config['DEFAULT']['BlockedIPsFilePath']

    # Set up logging
    logging.basicConfig(filename='syn_flood.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    # Email credentials
    email_sender = config['DEFAULT']['EmailSender']
    email_password = config['DEFAULT']['EmailPassword']

    # Telegram credentials
    telegram_bot_token = config['DEFAULT']['TelegramBotToken']
    telegram_chat_id = config['DEFAULT']['TelegramChatID']

    # NVD API credentials
    nvd_api_key = config['DEFAULT']['NvdApiKey']

    # GitHub API credentials
    github_api_token = config['DEFAULT']['GitHubApiToken']

    return sniffing_filter, blocked_ips_file_path, email_sender, email_password, telegram_bot_token, telegram_chat_id, nvd_api_key, github_api_token

# Load configuration
config = read_config()
sniffing_filter, blocked_ips_file_path, email_sender, email_password, telegram_bot_token, telegram_chat_id, nvd_api_key, github_api_token = load_credentials()

blocked_ips = set()  # Set to keep track of blocked IPs
syn_count = defaultdict(int)  # Dictionary to keep track of SYN packets
traffic = defaultdict(int)  # Dictionary to keep track of traffic
THRESHOLD = 100  # Threshold for SYN packets
BLOCK_DURATION = 300  # Block duration in seconds for Slowloris attack
SLOWLORIS_THRESHOLD = 20  # Threshold for Slowloris attack

# Web Data Retriever
def retrieve_nvd_data(api_key):
    # Implement your NVD data retrieval logic
    # This is just a placeholder, replace it with the actual logic
    return [{'source_ip': 'malicious_ip_1', 'description': 'Malicious activity'}, {'source_ip': 'malicious_ip_2', 'description': 'Another malicious activity'}]

def retrieve_github_data(api_token, username, repository):
    # Implement your GitHub data retrieval logic
    # This is just a placeholder, replace it with the actual logic
    return [{'user': {'ip': 'malicious_ip_3'}, 'title': 'Malicious issue'}, {'user': {'ip': 'malicious_ip_4'}, 'title': 'Another malicious issue'}]

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

# Function to block an IP address based on malicious intent
def block_malicious_ip(ip):
    # Add your logic to block the malicious IP address
    blocked_ips.add(ip)
    logging.info(f'Blocked malicious IP: {ip}')

# Function to unblock an IP address
def unblock_ip(ip):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        logging.info(f'Unblocked IP: {ip}')
    else:
        logging.warning(f'IP not found in the blocked list: {ip}')

# Function to detect Slowloris attack
def detect_slowloris(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        src_port = pkt[TCP].sport
        if src_ip not in blocked_ips and pkt[TCP].flags == 2:
            syn_count[src_ip] += 1
            if syn_count[src_ip] > SLOWLORIS_THRESHOLD:
                send_alert(src_ip, 'Slowloris')
                send_telegram_alert(src_ip, 'Slowloris')
                block_ip(src_ip)
                block_malicious_ip(src_ip)  # Block based on malicious intent
                time.sleep(BLOCK_DURATION)
                unblock_ip(src_ip)
                syn_count[src_ip] = 0

# Function to detect SYN/ACK attack
def detect_syn_ack_attack(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        src_port = pkt[TCP].sport
        if src_ip not in blocked_ips and pkt[TCP].flags == 18:
            syn_count[src_ip] += 1
            if syn_count[src_ip] > THRESHOLD:
                send_alert(src_ip, 'SYN/ACK Flood')
                send_telegram_alert(src_ip, 'SYN/ACK Flood')
                block_ip(src_ip)
                block_malicious_ip(src_ip)  # Block based on malicious intent
                time.sleep(BLOCK_DURATION)
                unblock_ip(src_ip)
                syn_count[src_ip] = 0

# Function to detect UDP flood
def detect_udp_flood(pkt):
    if IP in pkt and UDP in pkt:
        src_ip = pkt[IP].src
        src_port = pkt[UDP].sport
        traffic[src_ip] += 1
        if src_ip not in blocked_ips and traffic[src_ip] > THRESHOLD:
            send_alert(src_ip, 'UDP Flood')
            send_telegram_alert(src_ip, 'UDP Flood')
            block_ip(src_ip)
            block_malicious_ip(src_ip)  # Block based on malicious intent
            time.sleep(BLOCK_DURATION)
            unblock_ip(src_ip)
            traffic[src_ip] = 0

# Function to display packet information
def display_packet_info(pkt):
    if IP in pkt:
        print(f"Packet from {pkt[IP].src} to {pkt[IP].dst}")

# Function to detect ARP spoofing
def detect_arp_spoofing(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        if src_ip != pkt[ARP].pdst:
            logging.warning(f"Possible ARP spoofing: IP {src_ip} with MAC {src_mac} is claiming {pkt[ARP].pdst}'s IP")

# Function to detect DNS spoofing
def detect_dns_spoofing(pkt):
    if IP in pkt and UDP in pkt and DNSQR in pkt:
        src_ip = pkt[IP].src
        src_port = pkt[UDP].sport
        qname = pkt[DNSQR].qname.decode('utf-8')
        if src_ip not in blocked_ips and qname not in legitimate_dns_queries:
            send_alert(src_ip, 'DNS Spoofing')
            send_telegram_alert(src_ip, 'DNS Spoofing')
            block_ip(src_ip)
            block_malicious_ip(src_ip)  # Block based on malicious intent
            time.sleep(BLOCK_DURATION)
            unblock_ip(src_ip)
            legitimate_dns_queries.add(qname)

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
