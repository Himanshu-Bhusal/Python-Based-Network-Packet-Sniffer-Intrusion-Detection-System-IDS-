import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, ARP

class NetworkIDS:
    def __init__(self):
        self.alerts = []
        self.total_packets = 0  # <--- Added
        self.syn_tracker = defaultdict(list)
        self.port_scan_tracker = defaultdict(dict)
        self.mac_ip_table = {}
        
    def log_alert(self, alert_type, severity, source, description):
        alert = {
            "timestamp": time.strftime("%H:%M:%S"),
            "type": alert_type,
            "severity": severity,
            "source": source,
            "description": description
        }
        self.alerts.append(alert)
        # Keep only the latest 100 alerts in memory
        if len(self.alerts) > 100:
            self.alerts.pop(0)
        print(f"[{alert['severity']}] {alert['type']} from {alert['source']}: {alert['description']}")

    def process_packet(self, packet):
        self.total_packets += 1  # <--- Increment on every packet
        current_time = time.time()
        # ... rest of your packet code remains the same ...

        # 1. ARP Spoofing Detection
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            if arp_layer.op == 2:  # ARP Response
                src_ip = arp_layer.psrc
                src_mac = arp_layer.hwsrc
                if src_ip in self.mac_ip_table and self.mac_ip_table[src_ip] != src_mac:
                    self.log_alert(
                        "ARP Spoofing Detected",
                        "CRITICAL",
                        src_ip,
                        f"MAC mismatch for {src_ip}! Expected {self.mac_ip_table[src_ip]}, got {src_mac}"
                    )
                else:
                    self.mac_ip_table[src_ip] = src_mac

        # 2. IP Traffic Analysis
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            tcp_layer = packet[TCP]

            # SYN Flood Detection (Flags == 2 means SYN-only flag)
            if tcp_layer.flags == 2:
                self.syn_tracker[ip_src].append(current_time)
                # Filter timestamps to last 3 seconds
                self.syn_tracker[ip_src] = [t for t in self.syn_tracker[ip_src] if current_time - t <= 3]
                
                if len(self.syn_tracker[ip_src]) > 20:
                    self.log_alert(
                        "SYN Flood Attack",
                        "HIGH",
                        ip_src,
                        f"High rate of SYN packets: {len(self.syn_tracker[ip_src])} req/3s"
                    )

            # Port Scan Detection (Tracks connections to distinct ports within 5 seconds)
            dst_port = tcp_layer.dport
            self.port_scan_tracker[ip_src][dst_port] = current_time
            # Clean old entries
            self.port_scan_tracker[ip_src] = {
                p: t for p, t in self.port_scan_tracker[ip_src].items() if current_time - t <= 5
            }
            
            if len(self.port_scan_tracker[ip_src]) >= 15:
                self.log_alert(
                    "Port Scan Detected",
                    "MEDIUM",
                    ip_src,
                    f"Scanned {len(self.port_scan_tracker[ip_src])} unique ports in 5 seconds"
                )

    def start_sniffing(self, interface=None):
        # Starts packet sniffing continuously
        sniff(iface=interface, prn=self.process_packet, store=False)