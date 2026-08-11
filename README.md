# 🛡️ Real-Time Network Intrusion Detection System (IDS)

A lightweight, multi-threaded Network Intrusion Detection System (IDS) built with Python, Scapy, and Flask. This tool continuously captures raw network packets, inspects traffic headers for malicious patterns, and streams live security alerts to a web dashboard.

---

## 🚀 Features

* **Live Packet Capture:** Uses low-level socket sniffing via Scapy to inspect network interfaces in real time.
* **Automated Threat Detection:**
  * **Port Scanning:** Detects multi-port connection attempts across custom time windows.
  * **TCP SYN Floods:** Flags anomalous bursts of single-flag SYN requests indicating Denial of Service (DoS) attempts.
  * **ARP Spoofing:** Monitors MAC-to-IP mappings to alert on ARP cache poisoning attempts.
* **Web Security Operations Center (SOC) Dashboard:** Real-time web panel serving live security events via periodic background polling.
* **Multi-Threaded Architecture:** Decouples heavy packet analysis from web server rendering using background execution loops.

---

## 🛠️ Tech Stack

* **Language:** Python 3
* **Packet Capture & Analysis:** Scapy
* **Web Backend:** Flask (REST API & Web Server)
* **Frontend:** HTML5, CSS3, Vanilla JavaScript (Fetch API)

---

## 📦 Project Structure

```text
packet_ids/
│
├── app.py                 # Flask server & background sniffer thread
├── ids_engine.py          # Threat detection rules & packet processing engine
├── .gitignore             # Git exclusion rule file
├── README.md              # Project documentation
└── templates/
    └── index.html         # Live security dashboard
