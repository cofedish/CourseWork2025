#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Программа victim - имитация жертвы side-channel атаки
Создаёт детерминированные паттерны обращения к памяти,
которые могут быть обнаружены через cache side-channel
"""

import time
import sys
import random
from datetime import datetime

# Размер массива данных (должен быть достаточно большим для эффекта кеша)
ARRAY_SIZE = 256 * 512  # 128KB при байтах
STRIDE = 4096  # Шаг доступа (размер страницы)
ITERATIONS = 1000
LOG_FILE = "/logs/victim_activity.log"


class SecretProcessor:
    """Класс для имитации обработки секретных данных с характерным паттерном доступа к памяти"""

    def __init__(self, array_size, stride):
        self.array_size = array_size
        self.stride = stride
        # Создаём большой массив для работы с памятью
        self.data = bytearray(array_size)
        # Инициализируем массив случайными данными
        for i in range(array_size):
            self.data[i] = random.randint(0, 255)

        self.secret_value = 42  # Имитация секретного значения
        self.access_count = 0

    def process_secret(self, secret_byte):
        """
        Обрабатывает секретный байт с характерным паттерном доступа к памяти
        Паттерн зависит от значения секрета - это и есть side-channel!
        """
        # Вычисляем индекс на основе секретного значения
        index = (secret_byte * self.stride) % self.array_size

        # Создаём паттерн обращений к памяти
        # Атакующий может обнаружить эти обращения через кеш
        for offset in range(0, self.stride, 64):  # 64 байта - размер cache line
            idx = (index + offset) % self.array_size
            # Чтение и запись для загрузки в кеш
            self.data[idx] = (self.data[idx] + 1) % 256

        self.access_count += 1
        return index

    def simulate_workload(self, duration_seconds=30):
        """
        Имитирует рабочую нагрузку с периодической обработкой секретных данных
        """
        log(f"Запуск симуляции рабочей нагрузки на {duration_seconds} секунд")
        log(f"Размер массива: {self.array_size} байт")
        log(f"Шаг доступа (stride): {self.stride} байт")
        log(f"Начальное секретное значение: {self.secret_value}")

        start_time = time.time()
        iteration = 0

        try:
            while time.time() - start_time < duration_seconds:
                # Изменяем секретное значение каждые несколько итераций
                if iteration % 100 == 0:
                    self.secret_value = (self.secret_value + 13) % 256
                    log(f"[Итерация {iteration}] Новое секретное значение: {self.secret_value}")

                # Обрабатываем секретное значение
                accessed_index = self.process_secret(self.secret_value)

                # Периодически логируем активность
                if iteration % 50 == 0:
                    log(f"[Итерация {iteration}] Обработан секрет {self.secret_value}, "
                        f"доступ к индексу {accessed_index}, всего обращений: {self.access_count}")

                iteration += 1

                # Небольшая задержка для создания наблюдаемого паттерна
                time.sleep(0.01)

        except KeyboardInterrupt:
            log("Получен сигнал прерывания")

        elapsed = time.time() - start_time
        log(f"Симуляция завершена. Выполнено итераций: {iteration}, "
            f"время работы: {elapsed:.2f} сек, итераций/сек: {iteration / elapsed:.2f}")

        return iteration


def log(message):
    """Логирование с временной меткой"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_message = f"[{timestamp}] VICTIM: {message}"
    print(log_message, flush=True)

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")
    except Exception as e:
        print(f"Ошибка записи в лог: {e}", flush=True)


def main():
    """Главная функция"""
    log("=" * 70)
    log("VICTIM: Старт программы-жертвы side-channel атаки")
    log("=" * 70)

    # Создаём процессор секретных данных
    processor = SecretProcessor(ARRAY_SIZE, STRIDE)

    # Запускаем симуляцию рабочей нагрузки
    # В реальности это могла бы быть криптографическая операция,
    # обработка аутентификационных данных и т.д.
    duration = 60  # 60 секунд работы

    log(f"Начало симуляции обработки секретных данных ({duration} секунд)")
    iterations = processor.simulate_workload(duration)

    log("=" * 70)
    log(f"VICTIM: Завершение работы. Всего выполнено итераций: {iterations}")
    log("=" * 70)


if __name__ == "__main__":
    main()
