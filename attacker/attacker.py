#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Программа attacker - реализация упрощённой Prime+Probe атаки
Измеряет время доступа к памяти для обнаружения активности victim через кеш
"""

import time
import sys
import csv
from datetime import datetime
import statistics

# Параметры эксперимента
ARRAY_SIZE = 256 * 4096  # 1MB массив для probe
CACHE_LINE_SIZE = 64  # Размер cache line в байтах
NUM_SETS = 256  # Количество наборов для мониторинга
MEASUREMENTS_PER_ROUND = 100
TOTAL_ROUNDS = 600  # 600 раундов ~= 60 секунд при 0.1 сек на раунд
LOG_FILE = "/logs/attacker_activity.log"
MEASUREMENTS_FILE = "/logs/attacker_measurements.csv"


class PrimeProbeSidechannel:
    """
    Класс для реализации упрощённого Prime+Probe side-channel
    """

    def __init__(self, array_size, num_sets):
        self.array_size = array_size
        self.num_sets = num_sets
        self.stride = array_size // num_sets

        # Создаём массив для probe
        self.probe_array = bytearray(array_size)

        # Инициализируем массив
        for i in range(array_size):
            self.probe_array[i] = i % 256

        log(f"Инициализирован массив размером {array_size} байт")
        log(f"Количество наборов для мониторинга: {num_sets}")
        log(f"Шаг между наборами: {self.stride} байт")

    def prime_cache(self):
        """
        Prime фаза: заполняем кеш нашими данными
        Обращаемся ко всем мониторируемым адресам
        """
        for set_idx in range(self.num_sets):
            offset = set_idx * self.stride
            # Обращаемся к адресу, чтобы загрузить его в кеш
            _ = self.probe_array[offset]

    def probe_cache(self):
        """
        Probe фаза: измеряем время доступа к тем же адресам
        Если victim обращался к похожим адресам, наши данные вытеснены из кеша
        и время доступа будет больше
        """
        measurements = []

        for set_idx in range(self.num_sets):
            offset = set_idx * self.stride

            # Измеряем время доступа к памяти с высокой точностью
            start = time.perf_counter_ns()
            _ = self.probe_array[offset]
            end = time.perf_counter_ns()

            access_time = end - start
            measurements.append((set_idx, access_time))

        return measurements

    def run_measurement_round(self, round_num):
        """
        Выполняет один раунд измерений: Prime -> Wait -> Probe
        """
        # Фаза 1: Prime - заполняем кеш
        self.prime_cache()

        # Фаза 2: Wait - даём время victim'у поработать
        # В реальной атаке здесь может быть более сложная синхронизация
        time.sleep(0.001)  # 1ms

        # Фаза 3: Probe - измеряем время доступа
        measurements = self.probe_cache()

        # Вычисляем статистику
        times = [m[1] for m in measurements]
        avg_time = statistics.mean(times)
        max_time = max(times)
        min_time = min(times)
        stdev_time = statistics.stdev(times) if len(times) > 1 else 0

        # Определяем "подозрительные" наборы (с большим временем доступа)
        threshold = avg_time + stdev_time
        suspicious_sets = [m[0] for m in measurements if m[1] > threshold]

        return {
            'round': round_num,
            'timestamp': time.time(),
            'avg_time_ns': avg_time,
            'max_time_ns': max_time,
            'min_time_ns': min_time,
            'stdev_time_ns': stdev_time,
            'suspicious_count': len(suspicious_sets),
            'measurements': measurements
        }


def log(message):
    """Логирование с временной меткой"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_message = f"[{timestamp}] ATTACKER: {message}"
    print(log_message, flush=True)

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")
    except Exception as e:
        print(f"Ошибка записи в лог: {e}", flush=True)


def save_measurements(results):
    """Сохраняет результаты измерений в CSV файл"""
    try:
        with open(MEASUREMENTS_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Заголовок
            writer.writerow([
                'round', 'timestamp', 'avg_time_ns', 'max_time_ns',
                'min_time_ns', 'stdev_time_ns', 'suspicious_count'
            ])

            # Данные
            for result in results:
                writer.writerow([
                    result['round'],
                    result['timestamp'],
                    result['avg_time_ns'],
                    result['max_time_ns'],
                    result['min_time_ns'],
                    result['stdev_time_ns'],
                    result['suspicious_count']
                ])

        log(f"Результаты измерений сохранены в {MEASUREMENTS_FILE}")
        log(f"Всего записано раундов: {len(results)}")

    except Exception as e:
        log(f"Ошибка сохранения измерений: {e}")


def main():
    """Главная функция"""
    log("=" * 70)
    log("ATTACKER: Старт программы Prime+Probe side-channel атаки")
    log("=" * 70)

    # Небольшая задержка, чтобы victim успел запуститься
    log("Ожидание запуска victim (5 секунд)...")
    time.sleep(5)

    # Создаём объект для side-channel атаки
    sidechannel = PrimeProbeSidechannel(ARRAY_SIZE, NUM_SETS)

    log(f"Начало сбора измерений ({TOTAL_ROUNDS} раундов)")

    results = []
    start_time = time.time()

    try:
        for round_num in range(TOTAL_ROUNDS):
            result = sidechannel.run_measurement_round(round_num)
            results.append(result)

            # Логируем каждый 50-й раунд
            if round_num % 50 == 0:
                log(f"[Раунд {round_num}/{TOTAL_ROUNDS}] "
                    f"Среднее время: {result['avg_time_ns']:.0f} нс, "
                    f"Макс: {result['max_time_ns']:.0f} нс, "
                    f"Подозрительных наборов: {result['suspicious_count']}")

            # Небольшая задержка между раундами
            time.sleep(0.05)

    except KeyboardInterrupt:
        log("Получен сигнал прерывания")

    elapsed = time.time() - start_time

    log("=" * 70)
    log(f"Сбор данных завершён. Выполнено раундов: {len(results)}")
    log(f"Время работы: {elapsed:.2f} сек")
    log("=" * 70)

    # Сохраняем результаты
    save_measurements(results)

    # Вычисляем общую статистику
    if results:
        avg_times = [r['avg_time_ns'] for r in results]
        overall_avg = statistics.mean(avg_times)
        overall_stdev = statistics.stdev(avg_times) if len(avg_times) > 1 else 0

        log("ИТОГОВАЯ СТАТИСТИКА:")
        log(f"  Среднее время доступа: {overall_avg:.2f} нс")
        log(f"  Стандартное отклонение: {overall_stdev:.2f} нс")
        log(f"  Минимум: {min(avg_times):.2f} нс")
        log(f"  Максимум: {max(avg_times):.2f} нс")

        # Подсчитываем раунды с высокой активностью
        threshold = overall_avg + overall_stdev
        high_activity_rounds = sum(1 for t in avg_times if t > threshold)
        log(f"  Раундов с повышенной активностью: {high_activity_rounds} "
            f"({100.0 * high_activity_rounds / len(results):.1f}%)")

    log("=" * 70)
    log("ATTACKER: Завершение работы")
    log("=" * 70)


if __name__ == "__main__":
    main()
