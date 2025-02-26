from collections import defaultdict

from scapy.all import IP


def analyze_flows(packets):
    flows = defaultdict(list)
    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            packet_id = packet[IP].id

            flow_key = (ip_src, ip_dst, packet_id)
            flows[flow_key].append(packet)

    return flows


def detect_duplicates(flows):
    duplicates = []
    for flow_key, packets in flows.items():
        if len(packets) > 1:
            first_pkt = packets[0]
            last_pkt = packets[-1]
            if (
                first_pkt.haslayer(IP) and
                last_pkt.haslayer(IP) and
                first_pkt[IP].src == last_pkt[IP].src
            ):
                duplicates.append(flow_key)

    return duplicates


def detect_routing_loops(flows):
    loops = []
    for flow_key, packets in flows.items():
        if len(packets) >= 2:  # Убедимся, что есть хотя бы два пакета в потоке
            ttl_values = []  # Список TTL значений
            for pkt in packets:
                if IP in pkt:  # Проверим, является ли пакет IP-пакетом
                    ttl = pkt[IP].ttl  # Извлекаем значение TTL
                    ttl_values.append(ttl)

            if len(set(ttl_values)) == 1:  # Все TTL одинаковы?
                loops.append(flow_key)

    return loops


def print_results(results):
    for key, value in results.items():
        print(f"Flow Key: {key}")
        for pkt in value:
            print(
                f"\t{
                    pkt['ip_info']['ip_src']}:{
                    pkt['ip_info']['ip_dst']} -> {
                    pkt['ether_info']['ether_src']}:{
                    pkt['ether_info']['ether_dst']}")
