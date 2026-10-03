from typing import Optional

TTL_LINUX_MACOS_ANDROID = 64
TTL_WINDOWS = 128
TTL_NETWORK_DEVICE = 255


def get_os_guess(ttl: Optional[int]) -> str:
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

    Ранее здесь также учитывался TCP window size как дополнительный сигнал для
    различения Linux/macOS/Android, но эвристика оказалась ненадёжной на практике
    (embedded веб-серверы на роутерах нередко выставляют window size, совпадающий
    с типичным для macOS) и была убрана — группа TTL=64 остаётся недифференцированной.
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
    return os_guesses.get(initial_ttl, "Unknown")
