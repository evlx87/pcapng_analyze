import logging
import os
import sys

from scapy.all import rdpcap

from utils.network_utils import analyze_flows, detect_duplicates
from utils.packet_utils import get_packet_info

# Настройка логирования
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])


def main():
    file_path = 'test.pcapng'
    if not os.path.exists(file_path):
        logging.error(f"Файл {file_path} не найден.")
        return

    packets = rdpcap(file_path)
    logging.info(f"Общее количество пакетов в файле: {len(packets)}")

    packet_infos = [get_packet_info(packet) for packet in packets]
    logging.info("Анализ пакетов:")
    for info in packet_infos:
        if info:
            logging.info(info)
        else:
            logging.warning("Некорректный пакет!")

    flows = analyze_flows(packets)
    logging.info("Потоки:")
    for key, packets in flows.items():
        logging.info(key)

    duplicates = detect_duplicates(flows)
    logging.info(f"Найдены дубликаты потоков: {duplicates}")


if __name__ == "__main__":
    main()
