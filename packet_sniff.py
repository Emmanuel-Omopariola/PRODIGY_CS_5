import customtkinter as ctk
from scapy.all import sniff, IP, ARP, Ether, srp
from threading import Thread
import socket
from scapy.layers.inet import TCP, UDP
import queue
import time
import whois
import requests
import ipaddress

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PacketSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Packet Sniffer")
        self.geometry("850x700")

        self.target_ip = None
        self.sniffing = False
        self.packet_queue = queue.Queue()

        self.url_entry = ctk.CTkEntry(self, placeholder_text="Enter domain (e.g. google.com)", width=300)
        self.url_entry.pack(pady=10)

        self.start_btn = ctk.CTkButton(self, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(pady=10)

        self.stop_btn = ctk.CTkButton(self, text="Stop Sniffing", command=self.stop_sniffing, state="disabled")
        self.stop_btn.pack(pady=10)

        self.output = ctk.CTkTextbox(self, width=800, height=500)
        self.output.pack(pady=10)

    def start_sniffing(self):
        domain = self.url_entry.get().strip()
        if not domain:
            self.output.insert("end", "[!] Please enter a valid domain.\n")
            return

        try:
            self.target_ip = socket.gethostbyname(domain)
            self.output.insert("end", f"[+] Resolved {domain} to {self.target_ip}\n\n")
        except Exception as e:
            self.output.insert("end", f"[!] Could not resolve domain: {e}\n")
            return

        # WHOIS Info
        try:
            self.output.insert("end", "[ WHOIS INFO ]\n")
            domain_info = whois.whois(domain)
            self.output.insert("end", f"Domain Name: {domain_info.domain_name}\n")
            self.output.insert("end", f"Registrar: {domain_info.registrar}\n")
            self.output.insert("end", f"Created On: {domain_info.creation_date}\n")
            self.output.insert("end", f"Organization: {domain_info.org}\n")
            self.output.insert("end", f"Country: {domain_info.country}\n")
        except Exception as e:
            self.output.insert("end", f"[!] WHOIS lookup failed: {e}\n")

        # Geolocation Info
        try:
            res = requests.get(f"http://ip-api.com/json/{self.target_ip}").json()
            if res['status'] == 'success':
                self.output.insert("end", "\n[ GEOLOCATION INFO ]\n")
                self.output.insert("end", f"ISP: {res['isp']}\n")
                self.output.insert("end", f"City: {res['city']}, Region: {res['regionName']}\n")
                self.output.insert("end", f"Country: {res['country']}\n")
                self.output.insert("end", f"Coordinates: {res['lat']}, {res['lon']}\n")
            else:
                self.output.insert("end", "[!] Could not get geolocation info.\n")
        except Exception as e:
            self.output.insert("end", f"[!] Geolocation lookup failed: {e}\n")

        # Reverse DNS
        try:
            reverse_dns = socket.gethostbyaddr(self.target_ip)[0]
            self.output.insert("end", f"\n[ REVERSE DNS ]\nHostname: {reverse_dns}\n")
        except Exception:
            self.output.insert("end", "\n[ REVERSE DNS ]\nHostname: Not found\n")

        # IP Classification
        ip_obj = ipaddress.ip_address(self.target_ip)
        self.output.insert("end", "\n[ IP INFO ]\n")
        if ip_obj.is_private:
            self.output.insert("end", "IP Type: Private\n")
        elif ip_obj.is_reserved:
            self.output.insert("end", "IP Type: Reserved\n")
        else:
            self.output.insert("end", "IP Type: Public\n")

        # MAC address discovery (same LAN)
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target_ip)
            ans, _ = srp(pkt, timeout=2, verbose=False)
            if ans:
                mac = ans[0][1].hwsrc
                self.output.insert("end", f"Target MAC Address: {mac}\n")
            else:
                self.output.insert("end", "Target MAC Address: Not found (outside LAN)\n")
        except Exception:
            self.output.insert("end", "MAC discovery failed.\n")

        self.output.insert("end", "\n[*] Starting packet sniffing...\n\n")
        self.output.see("end")

        self.sniffing = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        Thread(target=self.sniff_packets, daemon=True).start()
        self.update_output()

    def stop_sniffing(self):
        self.sniffing = False
        self.output.insert("end", "[*] Stopped sniffing.\n")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
        size = len(packet)

        if self.target_ip not in [src_ip, dst_ip]:
            return

        info = f"{src_ip} → {dst_ip} | Protocol: {proto_name} | Size: {size} bytes"

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            info += f" | TCP {sport}→{dport}"

            # Optional: Scan HTTP header (very simple check)
            if dport == 80 or dport == 443:
                payload = bytes(packet[TCP].payload)
                if payload:
                    try:
                        http_line = payload.decode(errors='ignore').split("\r\n")[0]
                        info += f" | HTTP: {http_line}"
                    except:
                        pass

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            info += f" | UDP {sport}→{dport}"

        self.packet_queue.put(info + "\n")

    def update_output(self):
        while not self.packet_queue.empty():
            packet_info = self.packet_queue.get()
            self.output.insert("end", packet_info)
            self.output.see("end")

        if self.sniffing:
            self.after(100, self.update_output)

if __name__ == "__main__":
    app = PacketSnifferApp()
    app.mainloop()
