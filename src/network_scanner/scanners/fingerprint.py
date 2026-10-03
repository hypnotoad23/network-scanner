from typing import Optional

TTL_LINUX_MACOS_ANDROID = 64
TTL_WINDOWS = 128
TTL_NETWORK_DEVICE = 255

MACOS_WINDOW_SIZE_THRESHOLD = 60000


def get_os_guess(ttl: Optional[int], window_size: Optional[int] = None) -> str:
    """
    Приблизительное определение ОС хоста по начальному TTL из IP-заголовка.

    TTL сам по себе не несёт прямой информации об ОС, но разные ОС используют
    разные значения TTL по умолчанию для исходящих пакетов: Linux/macOS/Android,
    а также большинство современного сетевого оборудования на embedded Linux
    (роутеры, точки доступа) — 64; Windows — 128; старое/специфичное сетевое
    оборудование (старые Cisco IOS, Solaris) — 255.

    Поскольку TTL уменьшается на 1 за каждый транзитный хоп, наблюдаемое значение
    обычно немного меньше начального — функция округляет его вверх до ближайшего
    "эталонного" значения. Метод надёжен в первую очередь в пределах одной локальной
    подсети (0-1 хопов до цели) — именно так он используется в проекте.

    Опциональный `window_size` (TCP window size из SYN-ACK, появится при добавлении
    сканирования портов) используется как дополнительное уточнение между Linux/macOS/
    Android. Сигнал слабый (современные ядра Linux тоже нередко используют большие
    значения window size) и не должен считаться основным критерием.
    """
    if ttl is None:
        return "Unknown"

    if ttl > TTL_WINDOWS:
        initial_ttl = TTL_NETWORK_DEVICE
    elif ttl > TTL_LINUX_MACOS_ANDROID:
        initial_ttl = TTL_WINDOWS
    else:
        initial_ttl = TTL_LINUX_MACOS_ANDROID

    os_guesses = {
        TTL_LINUX_MACOS_ANDROID: "Linux / Android / macOS / Network device (embedded Linux)",
        TTL_WINDOWS: "Windows",
        TTL_NETWORK_DEVICE: "Network Device (legacy Cisco IOS, Solaris, etc.)",
    }
    os_name = os_guesses.get(initial_ttl, "Unknown")

    if (
        os_name.startswith("Linux / Android / macOS")
        and window_size is not None
        and window_size > MACOS_WINDOW_SIZE_THRESHOLD
    ):
        os_name = "macOS (likely)"

    return os_name
