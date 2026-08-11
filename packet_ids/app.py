import threading
from flask import Flask, render_template, jsonify
from scapy.all import conf
from ids_engine import NetworkIDS

app = Flask(__name__)
ids = NetworkIDS()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/alerts")
def get_alerts():
    # Print to terminal when browser requests data
    print(f"[*] Web dashboard polled alerts. Total in memory: {len(ids.alerts)}")
    return jsonify(ids.alerts)

def run_ids():
    print(f"[*] Sniffer active on: {conf.iface}")
    ids.start_sniffing(interface=conf.iface)

if __name__ == "__main__":
    ids_thread = threading.Thread(target=run_ids, daemon=True)
    ids_thread.start()
    
    # Ensure debug=False so Flask doesn't spawn duplicate process copies
    app.run(host="0.0.0.0", port=5000, debug=False)