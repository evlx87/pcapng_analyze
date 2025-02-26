# utils/packet_utils.py
import socket

from scapy.all import IP, ICMP, TCP, Ether


def is_valid_ip_address(ip):
    """Проверка валидности IP-адреса"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# utils/packet_utils.py


def get_packet_info(packet):
    """
    Возвращает словарь с информацией о пакете.
    Если какой-то слой недоступен, возвращает None.
    """
    info = {}

    if Ether in packet:
        ether_info = {
            "ether_src": packet[Ether].src,
            "ether_dst": packet[Ether].dst
        }
        info["ether_info"] = ether_info
    else:
        info["ether_info"] = {"ether_src": "", "ether_dst": ""}

    if IP in packet:
        ip_info = {
            "ip_src": packet[IP].src,
            "ip_dst": packet[IP].dst
        }
        info["ip_info"] = ip_info
    else:
        info["ip_info"] = {"ip_src": "", "ip_dst": ""}

    if ICMP in packet:
        icmp_info = {
            "icmp_type": packet[ICMP].type,
            "icmp_id": packet[ICMP].id,
            "icmp_seq": packet[ICMP].seq
        }
        info["icmp_info"] = icmp_info
    else:
        info["icmp_info"] = {"icmp_type": -1, "icmp_id": -1, "icmp_seq": -1}

    if TCP in packet:
        tcp_info = {
            "tcp_flags": packet[TCP].flags
        }
        info["tcp_info"] = tcp_info
    else:
        info["tcp_info"] = {"tcp_flags": -1}

    return info if all(v for v in info.values()) else None
