from scapy.all import rdpcap, IP, TCP, UDP, DNS

def analyze_pcap(filepath):
    """Analyzes a PCAP file using Scapy."""
    try:
        # Read the pcap file
        packets = rdpcap(filepath)
        
        unique_ips = set()
        protocols = {"TCP": 0, "UDP": 0, "DNS": 0, "Other": 0}
        total_packets = len(packets)
        
        for pkt in packets:
            # Extract IPs
            if IP in pkt:
                unique_ips.add(pkt[IP].src)
                unique_ips.add(pkt[IP].dst)
                
            # Count protocols
            if DNS in pkt:
                protocols["DNS"] += 1
            elif TCP in pkt:
                protocols["TCP"] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
            else:
                protocols["Other"] += 1

        return {
            "Total Packets": total_packets,
            "Unique IP Addresses": len(unique_ips),
            "Protocol Breakdown": protocols,
            "Top IPs": list(unique_ips)[:5] # Just show the first 5 IPs
        }
    except Exception as e:
        return {"Error": str(e)}