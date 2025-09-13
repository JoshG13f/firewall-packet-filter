#
# Custom firewall and packet filter
# Josh Gordon
# CS3700 Networking
#
# src/main.py
from scapy.all import sniff, TCP, UDP, IP, IPv6
import yaml, ipaddress, argparse

DEFAULT_RULES = {"drop_ports": [23, 445], "allow_subnet": "0.0.0.0/0"}

def load_rules(path: str):
    try:
        with open(path, "r") as f:
            rules = yaml.safe_load(f) or {}
            return {**DEFAULT_RULES, **rules}
    except FileNotFoundError:
        return DEFAULT_RULES

def in_subnet(pkt, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return True  # bad CIDR? just allow
    ip = None
    if IP in pkt:
        ip = ipaddress.ip_address(pkt[IP].src)
    elif IPv6 in pkt:
        ip = ipaddress.ip_address(pkt[IPv6].src)
    return (ip in net) if ip else True

def describe(pkt):
    if TCP in pkt:
        l4 = pkt[TCP]; proto = "TCP"; dport = l4.dport
    elif UDP in pkt:
        l4 = pkt[UDP]; proto = "UDP"; dport = l4.dport
    else:
        return ("OTHER", None, pkt.summary())
    dst = None
    if IP in pkt:    dst = pkt[IP].dst
    elif IPv6 in pkt: dst = pkt[IPv6].dst
    return (proto, dport, f"{proto} dport={dport} dst={dst}")

def main():
    ap = argparse.ArgumentParser(description="Simple packet filter demo")
    ap.add_argument("--rules", default="rules.yaml")
    ap.add_argument("--iface", default=None, help="Interface to sniff (e.g., lo, eth0). Default: auto")
    ap.add_argument("--bpf",   default="tcp or udp", help="BPF filter")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    drops = set(rules.get("drop_ports") or [])
    allow_net = rules.get("allow_subnet") or "0.0.0.0/0"

    print(f"[rules] drop_ports={sorted(drops)} allow_subnet={allow_net}")
    print(f"[sniff] iface={args.iface or 'auto'} bpf='{args.bpf}' (Ctrl+C to stop)")

    def handle(pkt):
        proto, dport, desc = describe(pkt)
        if dport is None:
            return  # non-TCP/UDP; ignore
        if not in_subnet(pkt, allow_net):
            print(f"[DROP] out-of-subnet {desc}")
            return
        if dport in drops:
            print(f"[DROP] {desc}")
        else:
            print(f"[PASS] {desc}")

    sniff(iface=args.iface, filter=args.bpf, prn=handle, store=False)

if __name__ == "__main__":
    main()
