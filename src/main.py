from scapy.all import sniff
import yaml
RULES_FILE = "rules.yaml"

def load_rules():
    try:
        with open(RULES_FILE) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {"drop_ports": [23], "allow_subnet": "192.168.0.0/16"}

def handle(pkt):
    rules = load_rules()
    dport = getattr(getattr(pkt, 'dport', None), 'real', getattr(pkt, 'dport', None))
    if dport in (rules.get("drop_ports") or []):
        print(f"[DROP] dport={dport} {pkt.summary()}")
        return
    print(f"[PASS] {pkt.summary()}")

if __name__ == "__main__":
    print("listening… ctrl+c to stop")
    sniff(prn=handle, store=False)
