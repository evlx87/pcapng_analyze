"""
pcap_analyze.py - анализатор pcap файлов для ICMP и ARP пакетов.

Этот скрипт анализирует pcap файлы и выводит информацию о ICMP и ARP пакетов.
"""
from datetime import datetime

from scapy.all import rdpcap, Ether, IP, ICMP, ARP


def add_packet_to_dict(address_dict, address, packet):
    """
    Добавляет пакет в словарь адресов.

    Параметры:
    address_dict (dict): Словарь, в который добавляются пакеты.
    address (str): Адрес (MAC или IP), по которому добавляется пакет.
    packet (scapy.layers.InPacket): Пакет, который нужно добавить.
    """
    if address not in address_dict:
        address_dict[address] = []
    address_dict[address].append(packet)


def handle_icmp(packet, icmp_requests, icmp_replies):
    """
    Обрабатывает ICMP пакеты и добавляет их в соответствующие словари.

    Параметры:
    packet (scapy.layers.InPacket): Пакет, который нужно обработать.
    icmp_requests (dict): Словарь для хранения ICMP запросов.
    icmp_replies (dict): Словарь для хранения ICMP ответов.
    """
    if ICMP in packet:
        icmp_id = packet[ICMP].id
        icmp_seq = packet[ICMP].seq
        timestamp = float(packet.time)
        dt_object = datetime.fromtimestamp(timestamp)

        key = (icmp_id, icmp_seq)

        if packet[ICMP].type == 8:  # ICMP Echo Request
            print(
                f"ICMP Запрос: {
                    packet[IP].src} -> {
                    packet[IP].dst}, ID={icmp_id}, " f"Seq={icmp_seq}, Время={dt_object}")
            icmp_requests[key] = (
                packet[IP].src,
                packet[Ether].src,
                packet[Ether].dst,
                dt_object)
        elif packet[ICMP].type == 0:  # ICMP Echo Reply
            print(
                f"ICMP Ответ: {
                    packet[IP].src} -> {
                    packet[IP].dst}, ID={icmp_id}, " f"Seq={icmp_seq}, Время={dt_object}")
            icmp_replies[key] = (
                packet[IP].src,
                packet[Ether].src,
                packet[Ether].dst,
                dt_object)


def process_arp(packet):
    """
    Обрабатывает ARP пакеты и выводит информацию о них.

    Параметры:
    packet (scapy.layers.InPacket): ARP пакет, который нужно обработать.
    """
    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc
    dst_ip = packet[ARP].pdst
    dst_mac = packet[ARP].hwdst
    arp_op = packet[ARP].op  # Операция: 1 (запрос) или 2 (ответ)

    if arp_op == 1:  # ARP Request
        print(f"ARP Запрос: {src_mac} ({src_ip}) запрашивает адрес {dst_ip}")
    elif arp_op == 2:  # ARP Reply
        print(
            f"ARP Ответ: {src_mac} ({src_ip}) сообщает, что {dst_ip} присвоен {src_mac}")


def handle_arp(packet):
    """
    Обрабатывает ARP пакеты. Возвращает 1, если пакет ARP, и 0 в противном случае.

    Параметры:
    packet (scapy.layers.InPacket): Пакет, который нужно проверить на наличие ARP.

    Возвращает:
    int: 1 если пакет является ARP пакетом, 0 иначе.
    """
    if ARP in packet:
        process_arp(packet)
        return 1
    return 0


def report_no_reply_requests(no_reply_requests):
    """
    Выводит сообщение для ICMP запросов, которые не получили ответ.

    Параметры:
    no_reply_requests (dict): Словарь ICMP запросов, на которые не было ответов.
    """
    if no_reply_requests:
        print("\nНет ответов на следующие ICMP Echo Requests:")
        for req_key, req_info in no_reply_requests.items():
            print(
                f"Запрос не получил ответ: {
                    req_info[0]} (MAC: {
                    req_info[1]}), отправленный в {
                    req_info[3]}")


def analyze_pcap(file_path):
    """
    Анализирует pcap файл и извлекает информацию о ICMP и ARP пакетах.

    Параметры:
    file_path (str): Путь к pcap файлу для анализа.
    """
    packets = rdpcap(file_path)

    address_dict = {}  # Общий словарь для хранения MAC и IP адресов
    icmp_requests = {}
    icmp_replies = {}
    arp_packet_count = 0

    for packet in packets:
        if Ether in packet:
            eth_src = packet[Ether].src
            eth_dst = packet[Ether].dst
            add_packet_to_dict(
                address_dict=address_dict,
                address=eth_src,
                packet=packet)
            add_packet_to_dict(
                address_dict=address_dict,
                address=eth_dst,
                packet=packet)

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            add_packet_to_dict(
                address_dict=address_dict,
                address=ip_src,
                packet=packet)
            add_packet_to_dict(
                address_dict=address_dict,
                address=ip_dst,
                packet=packet)

            # Вызовы отдельной функции для обработки ICMP
            handle_icmp(packet, icmp_requests, icmp_replies)

            # Вызов отдельной функции для обработки ARP
            arp_packet_count += handle_arp(packet)

    # Проверка отсутствующих ответов на ICMP
    no_reply_requests = {
        req_key: req_info
        for req_key, req_info in icmp_requests.items()
        if req_key not in icmp_replies
    }

    # Вывод информации о ICMP запросах без ответов
    report_no_reply_requests(no_reply_requests)

    # Подсчет всех пакетов в файле
    total_packets = len(packets)
    other_packets_count = total_packets - len(icmp_requests) - arp_packet_count

    # Вывод статистики
    print(f"\nВсего пакетов: {total_packets}")
    print(f"ICMP пакетов: {len(icmp_requests)}")
    if arp_packet_count > 0:
        print(f"ARP пакетов: {arp_packet_count}")
    print(f"Другие пакеты: {other_packets_count}")

    # Анализ адресов
    print("\nАнализ адресов:")
    for address, packets in address_dict.items():
        print(f"Адрес: {address}")
        for packet in packets:
            print(f"  Пакет: {packet.summary()}")


if __name__ == "__main__":
    analyze_pcap('test.pcapng')  # Обязательно замените на имя вашего файла
