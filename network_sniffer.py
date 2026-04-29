"""
CodeAlpha Cybersecurity Internship — Task 1
Basic Network Sniffer
Author: [Your Name]
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


# ─────────────────────────────────────────────
# PACKET ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyze_packet(packet):
    """Analyze and display information from a captured packet."""

    timestamp = datetime.now().strftime("%H:%M:%S")

    # Only process packets with an IP layer
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst
    protocol = ip_layer.proto

    print("\n" + "=" * 60)
    print(f"   Time      : {timestamp}")
    print(f"   Source IP  : {src_ip}")
    print(f"   Dest IP    : {dst_ip}")

    # ── TCP ──────────────────────────────────
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"  Protocol  : TCP")
        print(f"  Src Port  : {tcp.sport}")
        print(f"  Dst Port  : {tcp.dport}")

        # Identify common services by port
        service = identify_service(tcp.dport) or identify_service(tcp.sport)
        if service:
            print(f" Service   : {service}")

    # ── UDP ──────────────────────────────────
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"   Protocol  : UDP")
        print(f"   Src Port  : {udp.sport}")
        print(f"   Dst Port  : {udp.dport}")

    # ── ICMP (ping) ───────────────────────────
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
        icmp_name  = icmp_types.get(icmp.type, f"Type {icmp.type}")
        print(f"   Protocol  : ICMP ({icmp_name})")

    # ── Other protocols ───────────────────────
    else:
        print(f"   Protocol  : Other (proto={protocol})")

    # ── Payload preview ───────────────────────
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        try:
            decoded = raw_data.decode("utf-8", errors="replace")
            preview = decoded[:80].replace("\n", " ").replace("\r", "")
            print(f"   Payload   : {preview}...")
        except Exception:
            print(f"   Payload   : (binary data, {len(raw_data)} bytes)")


# ─────────────────────────────────────────────
# SERVICE IDENTIFIER
# ─────────────────────────────────────────────

def identify_service(port):
    """Return a human-readable service name for common ports."""
    services = {
        80:   "HTTP",
        443:  "HTTPS",
        21:   "FTP",
        22:   "SSH",
        23:   "Telnet",
        25:   "SMTP",
        53:   "DNS",
        110:  "POP3",
        143:  "IMAP",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Alt",
    }
    return services.get(port)


# ─────────────────────────────────────────────
# MAIN — START SNIFFING
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("    CodeAlpha — Basic Network Sniffer")
    print("     Run as Administrator / root")
    print("=" * 60)

    packet_count = int(input("\nHow many packets to capture? (e.g. 20): ").strip())
    filter_proto = input("Filter by protocol? (tcp / udp / icmp / leave blank for all): ").strip().lower()

    bpf_filter = filter_proto if filter_proto in ("tcp", "udp", "icmp") else None

    print(f"\n Sniffing {packet_count} packets"
          + (f" [{bpf_filter.upper()}]" if bpf_filter else " [ALL]")
          + "... Press Ctrl+C to stop early.\n")

    sniff(
        prn=analyze_packet,
        count=packet_count,
        filter=bpf_filter,
        store=False
    )

    print("\n" + "=" * 60)
    print("  Capture complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
