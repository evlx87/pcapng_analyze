from scapy.all import rdpcap, Ether, IP, ICMP, ARP
from datetime import datetime

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    icmp_requests = []
    icmp_replies = []
    arp_requests = []
    arp_replies = []
    other_packets = []
    mac_dict = {}

    for packet in packets:
        if Ether in packet:
            eth_src = packet[Ether].src
            eth_dst = packet[Ether].dst

            if eth_src not in mac_dict:
                mac_dict[eth_src] = []
            mac_dict[eth_src].append(packet)

            if eth_dst not in mac_dict:
                mac_dict[eth_dst] = []
            mac_dict[eth_dst].append(packet)

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            if ICMP in packet:
                icmp_type = packet[ICMP].type
                icmp_id = packet[ICMP].id
                icmp_seq = packet[ICMP].seq

                if icmp_type == 8:  # Echo request
                    timestamp = int(packet.time)
                    dt_object = datetime.fromtimestamp(timestamp)
                    icmp_requests.append((ip_src, eth_src, eth_dst, dt_object, icmp_id, icmp_seq))
                    print(f"ICMP Запрос: {ip_src} -> {ip_dst}, ID={icmp_id}, Seq={icmp_seq}, Время={dt_object}")

                elif icmp_type == 0:  # Echo reply
                    timestamp = packet.time
                    dt_object = datetime.fromtimestamp(timestamp)
                    icmp_replies.append((ip_src, eth_src, eth_dst, dt_object, icmp_id, icmp_seq))
                    print(f"ICMP Ответ: {ip_src} -> {ip_dst}, ID={icmp_id}, Seq={icmp_seq}, Время={dt_object}")

                else:
                    other_packets.append(packet)

            elif ARP in packet:
                if packet[ARP].op == 1:
                    arp_requests.append((ip_src, eth_src, eth_dst))
                    print(f"ARP Запрос: {ip_src} ищет {ip_dst}")
                elif packet[ARP].op == 2:
                    arp_replies.append((ip_src, eth_src, eth_dst))
                    print(f"ARP Ответ: {ip_src} отвечает {ip_dst}")
            else:
                other_packets.append(packet)

    # Проверка отсутствующих ответов на ICMP
    request_ids = {(req[4], req[5]): req for req in icmp_requests}
    for reply in icmp_replies:
        reply_key = (reply[4], reply[5])
        request_ids.pop(reply_key, None)  # Удалить найденный ответ

    if request_ids:
        print("\nНет ответов на следующие ICMP Echo Requests:")
        for req in request_ids.values():
            print(f"Запрос не получил ответ: {req[0]} (MAC: {req[1]}), отправленный в {req[3]}")

    # Анализ обнаруженных ARP сообщений
    print("\nСтатистика ARP:")
    print(f"Запросы ARP: {len(arp_requests)}, Ответы ARP: {len(arp_replies)}")

    # Подсчет всех пакетов в файле
    print(f"\nОбщее количество пакетов в файле: {len(packets)}")
    print(f"Количество ICMP пакетов: {len(icmp_requests) + len(icmp_replies)}")
    print(f"Количество ARP пакетов: {len(arp_requests) + len(arp_replies)}")
    print(f"Количество других пакетов: {len(other_packets)}")

    # Анализ MAC-адресов
    print("\nАнализ MAC-адресов:")
    for mac, packets in mac_dict.items():
        print(f"MAC: {mac}")
        for packet in packets:
            print(f"  Packet: {packet}")

if __name__ == "__main__":
    analyze_pcap('test.pcapng')  # Обязательно замените на имя вашего файла


