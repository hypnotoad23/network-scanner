NetScout — современный высокопроизводительный сетевой сканер на Python 3.12, разработанный с использованием передовых практик разработки программного обеспечения.

Основные возможности
- Быстрое ARP-сканирование: Мгновенное обнаружение активных устройств в подсети.
- Идентификация производителей: Автоматическое определение вендора (Apple, Samsung, Cisco и др.) через базу данных IEEE OUI.
- Современный стек: Использование Pydantic v2 для строгой типизации данных и Rich для красивого интерактивного интерфейса.
- Контейнеризация: Полная поддержка Docker (Multi-stage build) для запуска на любой ОС без установки Python.
- Промышленный подход: Модульная структура пакета (`src-layout`), Unit-тестирование и управление зависимостями через Poetry.

Стэк
- Language: Python 3.12
- Networking: Scapy
- Validation: Pydantic v2
- UI: Rich
- DevOps: Docker, Poetry, Pytest

Быстрый запуск (Docker)

Это самый простой способ запустить сканер, не устанавливая зависимости в систему:

Сборка образа
```bash
sudo docker build -t netscan .
```
Запуск сканирования (замените диапазон на свой)
```bash
sudo docker run -it --rm --net=host netscan 192.168.1.0/24
```
Запуск на Windows 

Для запуска сканера напрямую в ОС Windows (без Docker) выполните следующие шаги:
Установка драйвера: Скачайте и установите Npcap (https://npcap.com). 
   > Важно: При установке выберите опцию "Install Npcap in WinPcap API-compatible Mode".
Клонирование и установка:
```powershell
git clone https://github.com
cd network-scanner
python -m poetry install
python -m poetry run netscan 192.168.1.0/24
```
