import logging
import os
import sys

from scapy.all import rdpcap

from utils.network_utils import analyze_flows, detect_duplicates, detect_routing_loops
from utils.packet_utils import get_packet_info

# Настройка логирования
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])


def main(file_name):
    # Путь к файлу .pcapng
    file_path = file_name

    # Проверяем существование файла
    if not os.path.exists(file_path):
        logging.error(f"Файл {file_path} не найден.")
        return

    # Загружаем пакеты из файла
    packets = rdpcap(file_path)
    logging.info(f"Общее количество пакетов в файле: {len(packets)}")

    # Получение информации о пакетах
    packet_infos = [get_packet_info(packet) for packet in packets]
    logging.info("Анализ пакетов:")
    for info in packet_infos:
        if info:
            logging.info(info)
        else:
            logging.warning("Некорректный пакет!")

    # Анализ потоков
    flows = analyze_flows(packets)
    logging.info("Потоки:")
    for key, packets in flows.items():
        logging.info(key)

    # Поиск дубликатов потоков
    duplicates = detect_duplicates(flows)
    if duplicates:
        logging.error(f"Найдены дубликаты потоков: {duplicates}")
    else:
        logging.info("Дубликаты потоков отсутствуют.")

    # Поиск петель маршрутизации
    routing_loops = detect_routing_loops(flows)
    if routing_loops:
        logging.error(f"Найдены петли маршрутизации: {routing_loops}")
    else:
        logging.info("Петель маршрутизации не обнаружено.")


if __name__ == "__main__":
    main('test.pcapng')
