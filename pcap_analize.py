"""
pcap_analyze.py - анализатор pcap файлов для ICMP и ARP пакетов.

Этот скрипт анализирует pcap файлы и выводит информацию о ICMP и ARP пакетов.
"""
import logging
import os
import sys
from datetime import datetime

from scapy.all import rdpcap, Ether, IP, ICMP, ARP


class TerminalColors:
    RED = "\033[1;31m"   # Красный цвет, жирный
    RESET = "\033[0m"    # Сброс цвета


# Настройка логирования
# log_filename = 'analyze_pcap.log'
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        # logging.FileHandler(log_filename),  # Логирование в
                        # файл
                        logging.StreamHandler(
                            sys.stdout)    # Логирование в консоль
                    ])


def log_with_color(level, message):
    if level == logging.WARNING:
        message = f"{TerminalColors.RED}{message}{TerminalColors.RESET}"
    logging.log(level, message)


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
                f"ICMP Запрос: { packet[IP].src} -> { packet[IP].dst}, ID={icmp_id}, "
                f"Seq={icmp_seq}, Время={dt_object}")
            icmp_requests[key] = (
                packet[IP].src,
                packet[Ether].src,
                packet[Ether].dst,
                dt_object)
        elif packet[ICMP].type == 0:  # ICMP Echo Reply
            print(
                f"ICMP Ответ: { packet[IP].src} -> { packet[IP].dst}, ID={icmp_id}, "
                f"Seq={icmp_seq}, Время={dt_object}")
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
                f"Запрос не получил ответ: {req_info[0]}(MAC: {req_info[1]}), отправленный в {req_info[3]}")


def analyze_pcap(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Файл {file_path} не найден.")
        return

    packets = rdpcap(file_path)

    icmp_requests = []
    icmp_replies = []
    arp_requests = []
    arp_replies = []
    other_packets = []
    mac_dict = {}

    observed_flows = {}  # Для записи потоков

    # Обработка каждого пакета
    for packet in packets:
        if Ether in packet:
            eth_src = packet[Ether].src
            eth_dst = packet[Ether].dst
            # Сохраняем пакеты по MAC-адресам
            mac_dict.setdefault(eth_src, []).append(packet)
            mac_dict.setdefault(eth_dst, []).append(packet)

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            packet_id = packet[IP].id
            ttl = packet[IP].ttl

            # Проверка потока пакетов
            if (ip_src, ip_dst, packet_id) not in observed_flows:
                observed_flows[(ip_src, ip_dst, packet_id)] = []

            observed_flows[(ip_src, ip_dst, packet_id)].append(
                (ttl, eth_src, eth_dst))

            if ICMP in packet:
                icmp_type = packet[ICMP].type
                icmp_id = packet[ICMP].id
                icmp_seq = packet[ICMP].seq

                if icmp_type == 8:  # Echo request
                    timestamp = int(packet.time)
                    dt_object = datetime.fromtimestamp(timestamp)
                    icmp_requests.append(
                        (ip_src, eth_src, eth_dst, dt_object, icmp_id, icmp_seq))
                    logging.info(
                        f"ICMP Запрос: {ip_src} -> {ip_dst}, ID={icmp_id}, Seq={icmp_seq}, Время={dt_object}")

                elif icmp_type == 0:  # Echo reply
                    timestamp = packet.time
                    dt_object = datetime.fromtimestamp(timestamp)
                    icmp_replies.append(
                        (ip_src, eth_src, eth_dst, dt_object, icmp_id, icmp_seq))
                    logging.info(
                        f"ICMP Ответ: {ip_src} -> {ip_dst}, ID={icmp_id}, Seq={icmp_seq}, Время={dt_object}")

            elif ARP in packet:
                if packet[ARP].op == 1:  # ARP Request
                    arp_requests.append((ip_src, eth_src, eth_dst))
                    logging.info(f"ARP Запрос: {ip_src} ищет {ip_dst}")
                elif packet[ARP].op == 2:  # ARP Reply
                    arp_replies.append((ip_src, eth_src, eth_dst))
                    logging.info(f"ARP Ответ: {ip_src} отвечает {ip_dst}")
            else:
                other_packets.append(packet)

    # Общее количество пакетов
    logging.info(f"Общее количество пакетов в файле: {len(packets)}")
    logging.info(
        f"Количество ICMP пакетов: {len(icmp_requests) + len(icmp_replies)}")
    logging.info(
        f"Количество ARP пакетов: {len(arp_requests) + len(arp_replies)}")
    logging.info(f"Количество других пакетов: {len(other_packets)}")

    # Статистика ARP
    logging.info(
        f"Статистика ARP: Запросы ARP: {len(arp_requests)}, Ответы ARP: {len(arp_replies)}")

    # Анализ MAC-адресов
    logging.info("Анализ MAC-адресов:")
    for mac, packets in mac_dict.items():
        logging.info(f"MAC: {mac} -> Количество пакетов: {len(packets)}")

    # Проверка на петлю маршрутизации
    for flow_key, tl_data in observed_flows.items():
        ip_src, ip_dst, packet_id = flow_key
        if len(tl_data) >= 2:
            # Проверяем на изменение TTL и MAC-адресов
            ttl_values = [data[0] for data in tl_data]
            mac_pairs = [(data[1], data[2]) for data in tl_data]

            if all(ttl_values[i] == ttl_values[i + 1] +
                   1 for i in range(len(ttl_values) - 1)):
                log_with_color(
                    logging.WARNING,
                    f"Поток от {ip_src} до {ip_dst} содержит повторяющиеся пакеты с тем же ID {packet_id}.")
                # Вывод MAC-адресов по строчно
                logging.warning("MAC-адреса:")
                for src_mac, dst_mac in mac_pairs:
                    logging.warning(f"  {src_mac} <-> {dst_mac}")

                # Проверка на смену местами MAC-адресов
                if all(mac_pairs[i][0] == mac_pairs[i + 1][1] and mac_pairs[i]
                       [1] == mac_pairs[i + 1][0] for i in range(len(mac_pairs) - 1)):
                    log_with_color(
                        logging.WARNING,
                        "Обнаружена петля маршрутизации между MAC-адресами.")


if __name__ == "__main__":
    analyze_pcap('test.pcapng')  # Обязательно замените на имя вашего файла
