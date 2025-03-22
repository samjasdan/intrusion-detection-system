import time
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Thresholds
PORT_SCAN_THRESHOLD = 10  # More than 10 ports scanned in 5 seconds
FLOOD_THRESHOLD = 100  # More than 100 packets from the same IP in 5 seconds

# Data structures to track suspicious activity
port_scans = {}
flood_attempts = {}


def detect_intrusion(packet):
    if not packet.haslayer(IP):
        return  # Ignore non-IP packets

    src_ip = packet[IP].src
    timestamp = time.time()

    # Track port scans
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        dest_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport

        if src_ip not in port_scans:
            port_scans[src_ip] = []

        port_scans[src_ip].append((dest_port, timestamp))

        # Remove old entries (keep only last 5 seconds of data)
        port_scans[src_ip] = [entry for entry in port_scans[src_ip] if timestamp - entry[1] <= 5]

        if len(set(p[0] for p in port_scans[src_ip])) > PORT_SCAN_THRESHOLD:
            print(f"[ALERT] Port scan detected from {src_ip}!")
            del port_scans[src_ip]  # Clear after aler

    # Track flood attacks
    if src_ip not in flood_attempts:
        flood_attempts[src_ip] = []

    flood_attempts[src_ip].append(timestamp)
    flood_attempts[src_ip] = [t for t in flood_attempts[src_ip] if timestamp - t <= 5]

    if len(flood_attempts[src_ip]) > FLOOD_THRESHOLD:
        print(f"[ALERT] Potential DDoS attack from {src_ip}!")
        del flood_attempts[src_ip]  # Clear after alert


# Sniff network traffic
print("Starting Intrusion Detection System...")
sniff(filter="ip", prn=detect_intrusion, store=0)
