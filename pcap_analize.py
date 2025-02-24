from scapy.all import rdpcap, Ether, IP, ICMP, ARP
from datetime import datetime


def add_packet_to_dict(packet_dict, key, packet):
    """Добавляет пакет в словарь, если ключ еще не существует."""
    if key not in packet_dict:
        packet_dict[key] = []
    packet_dict[key].append(packet)


def process_icmp(packet, mac_src, mac_dst):
    """Обрабатывает ICMP пакеты и выводит информацию о них."""
    icmp_type = packet[ICMP].type
    icmp_id = packet[ICMP].id
    icmp_seq = packet[ICMP].seq
    timestamp = float(packet.time)
    dt_object = datetime.fromtimestamp(timestamp)

    if icmp_type == 8:  # Echo request
        print(
            f"ICMP Запрос: {
                packet[IP].src} -> {
                packet[IP].dst}, ID={icmp_id}, Seq={icmp_seq}, Время={dt_object}")
        return (packet[IP].src, mac_src, mac_dst, dt_object, icmp_id, icmp_seq)
    elif icmp_type == 0:  # Echo reply
        print(
            f"ICMP Ответ: {
                packet[IP].src} -> {
                packet[IP].dst}, ID={icmp_id}, Seq={icmp_seq}, Время={dt_object}")
        return (packet[IP].src, mac_src, mac_dst, dt_object, icmp_id, icmp_seq)


def process_arp(packet):
    """Обрабатывает ARP пакеты и выводит информацию о них."""
    if packet[ARP].op == 1:  # ARP request
        print(f"ARP Запрос: {packet[IP].src} ищет {packet[IP].dst}")
    elif packet[ARP].op == 2:  # ARP reply
        print(f"ARP Ответ: {packet[IP].src} отвечает {packet[IP].dst}")


def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    icmp_requests = []
    icmp_replies = []
    arp_requests = []
    arp_replies = []
    mac_dict = {}
    ip_dict = {}

    for packet in packets:
        if Ether in packet:
            eth_src = packet[Ether].src
            eth_dst = packet[Ether].dst
            add_packet_to_dict(mac_dict, eth_src, packet)
            add_packet_to_dict(mac_dict, eth_dst, packet)

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            add_packet_to_dict(ip_dict, ip_src, packet)
            add_packet_to_dict(ip_dict, ip_dst, packet)

            # Обработка ICMP пакетов
            if ICMP in packet:
                result = process_icmp(packet, eth_src, eth_dst)
                if result:
                    if result in icmp_requests:
                        icmp_replies.append(result)
                    else:
                        icmp_requests.append(result)

            # Обработка ARP пакетов
            elif ARP in packet:
                process_arp(packet)

    # Проверка отсутствующих ответов на ICMP
    request_ids = {(req[4], req[5]): req for req in icmp_requests}
    for reply in icmp_replies:
        reply_key = (reply[4], reply[5])
        request_ids.pop(reply_key, None)  # Удалить найденный ответ

    if request_ids:
        print("\nНет ответов на следующие ICMP Echo Requests:")
        for req in request_ids.values():
            print(
                f"Запрос не получил ответ: {
                    req[0]} (MAC: {
                    req[1]}), отправленный в {
                    req[3]}")

    # Подсчет всех пакетов в файле
    print(f"\nОбщее количество пакетов в файле: {len(packets)}")
    print(
        f"ICMP пакеты: {
            len(icmp_requests)}, ARP пакеты: {
            len(arp_requests)}, другие пакеты: {
                len(packets) -
                len(icmp_requests) -
            len(arp_requests)}")

    # Анализ MAC-адресов
    print("\nАнализ MAC-адресов:")
    for mac, packets in mac_dict.items():
        print(f"MAC: {mac}")
        for packet in packets:
            print(f"  Пакет: {packet.summary()}")

    # Анализ IP-адресов
    print("\nАнализ IP-адресов:")
    for ip, packets in ip_dict.items():
        print(f"IP: {ip}")
        for packet in packets:
            print(f"  Пакет: {packet.summary()}")


if __name__ == "__main__":
    analyze_pcap('test.pcapng')  # Обязательно замените на имя вашего файла
