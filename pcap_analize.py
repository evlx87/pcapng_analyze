import logging
import os
import sys
from datetime import datetime

from scapy.all import rdpcap, Ether, IP, ICMP, ARP, TCP


class TerminalColors:
    RED = "\033[1;31m"   # Красный цвет, жирный
    RESET = "\033[0m"    # Сброс цвета


# Настройка логирования
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])


def log_with_color(level, message):
    if level == logging.WARNING:
        message = f"{TerminalColors.RED}{message}{TerminalColors.RESET}"
    logging.log(level, message)


def add_packet_to_dict(address_dict, address, packet):
    if address not in address_dict:
        address_dict[address] = []
    address_dict[address].append(packet)


def handle_icmp(packet, icmp_requests, icmp_replies):
    if ICMP in packet:
        icmp_id = packet[ICMP].id
        icmp_seq = packet[ICMP].seq
        timestamp = float(packet.time)
        dt_object = datetime.fromtimestamp(timestamp)

        key = (icmp_id, icmp_seq)

        if packet[ICMP].type == 8:  # ICMP Echo Request
            logging.info(
                f"ICMP Запрос: {packet[IP].src} -> {packet[IP].dst}, ID={icmp_id}, "
                f"Seq={icmp_seq}, Время={dt_object}")
            icmp_requests[key] = (
                packet[IP].src,
                packet[Ether].src,
                packet[Ether].dst,
                dt_object)  # Включаем timestamp
        elif packet[ICMP].type == 0:  # ICMP Echo Reply
            logging.info(
                f"ICMP Ответ: {packet[IP].src} -> {packet[IP].dst}, ID={icmp_id}, "
                f"Seq={icmp_seq}, Время={dt_object}")
            icmp_replies[key] = (
                packet[IP].src,
                packet[Ether].src,
                packet[Ether].dst,
                dt_object)  # Включаем timestamp


def process_arp(packet):
    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc
    dst_ip = packet[ARP].pdst
    dst_mac = packet[ARP].hwdst
    arp_op = packet[ARP].op  # Операция: 1 (запрос) или 2 (ответ)

    if arp_op == 1:  # ARP Request
        logging.info(
            f"ARP Запрос: {src_mac} ({src_ip}) запрашивает адрес {dst_ip}")
    elif arp_op == 2:  # ARP Reply
        logging.info(
            f"ARP Ответ: {src_mac} ({src_ip}) сообщает, что {dst_ip} присвоен {src_mac}")


def handle_arp(packet):
    if ARP in packet:
        process_arp(packet)
        return 1
    return 0


def report_no_reply_requests(no_reply_requests):
    if no_reply_requests:
        logging.info("\nНет ответов на следующие ICMP Echo Requests:")
        for req_key, req_info in no_reply_requests.items():
            logging.info(
                f"Запрос не получил ответ: {
                    req_info[0]}(MAC: {
                    req_info[1]}), отправленный в {
                    req_info[3]}")


def analyze_pcap(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Файл {file_path} не найден.")
        return None, None, None

    packets = rdpcap(file_path)

    icmp_requests = {}
    icmp_replies = {}
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
            mac_dict.setdefault(eth_src, []).append(packet)
            mac_dict.setdefault(eth_dst, []).append(packet)

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            packet_id = packet[IP].id
            ttl = packet[IP].ttl

            if (ip_src, ip_dst, packet_id) not in observed_flows:
                observed_flows[(ip_src, ip_dst, packet_id)] = []

            observed_flows[(ip_src, ip_dst, packet_id)].append(
                (ttl, eth_src, eth_dst))

            if ICMP in packet:
                handle_icmp(packet, icmp_requests, icmp_replies)
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
        f"Количество ICMP пакетов: {
            len(icmp_requests) +
            len(icmp_replies)}")
    logging.info(
        f"Количество ARP пакетов: {
            len(arp_requests) +
            len(arp_replies)}")
    logging.info(f"Количество других пакетов: {len(other_packets)}")

    # Статистика ARP
    logging.info(
        f"Статистика ARP: Запросы ARP: {
            len(arp_requests)}, Ответы ARP: {
            len(arp_replies)}")

    # Анализ MAC-адресов
    logging.info("Анализ MAC-адресов:")
    for mac, packets in mac_dict.items():
        logging.info(f"MAC: {mac} -> Количество пакетов: {len(packets)}")

    return packets, observed_flows, (icmp_requests, icmp_replies,
                                     arp_requests, arp_replies, other_packets)


def check_duplicate_packets(observed_flows):
    duplicate_packets = []

    for flow_key, packets in observed_flows.items():
        ip_src, ip_dst, packet_id = flow_key

        if len(packets) > 1:
            first_ttl, first_eth_src, first_eth_dst = packets[0]
            last_ttl, last_eth_src, last_eth_dst = packets[-1]

            if first_ttl == last_ttl and first_eth_src == last_eth_src and first_eth_dst == last_eth_dst:
                duplicate_packets.append(flow_key)

    if duplicate_packets:
        log_with_color(logging.WARNING,
                       f"Обнаружены дублирующие пакеты: {duplicate_packets}")


def detect_routing_loops(observed_flows):
    routing_loops = []

    for flow_key, packets in observed_flows.items():
        ip_src, ip_dst, packet_id = flow_key

        ttl_values = [packet[0] for packet in packets]
        mac_pairs = [(packet[1], packet[2]) for packet in packets]

        if len(ttl_values) > 2 and len(set(ttl_values)) == 1:
            log_with_color(
                logging.WARNING,
                f"Обнаружена потенциальная петля маршрутизации: {flow_key}")
            routing_loops.append(flow_key)

    if routing_loops:
        log_with_color(
            logging.WARNING, f"Обнаружено {
                len(routing_loops)} потенциальных петель маршрутизации.")


def check_latency_anomalies(observed_flows):
    latency_anomalies = []

    for flow_key, packets in observed_flows.items():
        ip_src, ip_dst, packet_id = flow_key

        # Извлекаем таймстемпы, только если длина кортежа >= 4
        timestamps = [packet[3] for packet in packets if len(packet) > 3]

        # Если у нас не достаточно таймстемпов, продолжаем к следующему потоку
        if len(timestamps) < 2:
            continue

        # Рассчитываем задержки
        latencies = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        max_latency = max(latencies)
        avg_latency = sum(latencies) / len(latencies)

        if max_latency > avg_latency * 2:
            latency_anomalies.append(flow_key)

    if latency_anomalies:
        log_with_color(logging.WARNING,
                       f"Обнаружены аномальные задержки в потоках: {latency_anomalies}")


def validate_protocols(packets):
    protocol_errors = []

    for packet in packets:
        if IP in packet:
            # Получаем длину заголовка в байтах
            ip_header_length = packet[IP].ihl * 4
            expected_length = 20
            if ip_header_length != expected_length:
                protocol_errors.append(
                    f"Неверная длина заголовка IP: {ip_header_length} байт")

        if ICMP in packet:
            icmp_type = packet[ICMP].type
            if icmp_type not in [0, 8]:
                protocol_errors.append(f"Неизвестный тип ICMP: {icmp_type}")

        if ARP in packet:
            arp_operation = packet[ARP].op
            if arp_operation not in [1, 2]:
                protocol_errors.append(
                    f"Недопустимая операция ARP: {arp_operation}")

    if protocol_errors:
        log_with_color(logging.ERROR,
                       f"Обнаружены проблемы с протоколами: {protocol_errors}")


def find_anomalous_packets(packets):
    anomalous_packets = []

    for packet in packets:
        if IP in packet:
            ttl_value = packet[IP].ttl
            if ttl_value <= 0 or ttl_value > 255:
                anomalous_packets.append(
                    f"Аномальное значение TTL: {ttl_value}")

        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0xF0 != 0x00:
                anomalous_packets.append(
                    f"Подозрительный набор флагов TCP: {tcp_flags}")

    if anomalous_packets:
        log_with_color(logging.WARNING,
                       f"Обнаружены аномальные пакеты: {anomalous_packets}")


if __name__ == "__main__":
    packets, observed_flows, result_data = analyze_pcap(
        'test.pcapng')  # Обязательно замените на имя вашего файла
    # Вызываем дополнительные проверки после анализа PCAP-файла
    check_duplicate_packets(observed_flows)
    detect_routing_loops(observed_flows)
    check_latency_anomalies(observed_flows)
    validate_protocols(packets)
    find_anomalous_packets(packets)
