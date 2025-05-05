# Network Packet Sniffer (Mini GUI)

A modern Python GUI tool that lets you sniff and analyze network packets for a specific domain using `Scapy`, with enriched details from `WHOIS` and `IP Geolocation`.

## Features
- 🌐 **Domain Resolver**: Converts domain to IP.
- 📄 **WHOIS Lookup**: Displays domain registrar and organization.
- 🌍 **Geolocation Info**: Shows ISP, city, country, and coordinates.
- 🧠 **IP Classification**: Tells if it's private, loopback, or public.
- 🔁 **Reverse DNS**: Attempts to get hostname from IP.
- 🕵️‍♂️ **Live Packet Sniffing**: Captures and shows TCP/UDP/IP packet info.
- 🖥️ **Modern GUI**: Built with `CustomTkinter` in dark mode.

## Requirements

Install the necessary libraries with:

```bash
pip install scapy customtkinter requests python-whois
````
To run


```bash
python packet_sniff.py
````
