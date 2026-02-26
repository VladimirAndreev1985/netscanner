"""Internationalization module — EN/RU language support."""

import json
import os
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
CONFIG_PATH = DATA_DIR / "settings.json"

# ═══════════════════════════════════════════════════════════════
# Translation dictionaries
# ═══════════════════════════════════════════════════════════════

TRANSLATIONS = {
    "en": {
        # ─── General ───
        "app_title": "NetScanner",
        "app_subtitle": "Professional Network Scanner for Kali Linux",
        "version": "v1.0.0",
        "ready": "Ready",
        "complete": "Complete",
        "error": "Error",
        "ok": "OK",
        "yes": "Yes",
        "no": "No",
        "back": "Back",
        "quit": "Quit",
        "help": "Help",
        "navigate": "Navigate",
        "select": "Select",
        "export": "Export",
        "close": "Close",
        "loading": "Loading...",
        "not_available": "N/A",

        # ─── Scan Screen ───
        "target": "Target",
        "target_placeholder": "IP, subnet (192.168.1.0/24), or range",
        "auto_detect": "Auto-Detect",
        "scan_mode": "Scan Mode",
        "quick": "Quick",
        "normal": "Normal",
        "deep": "Deep",
        "auto_pwn": "Auto-Pwn",
        "start_scan": "START SCAN",
        "detected_subnets": "Detected Subnets",
        "detecting_interfaces": "Detecting network interfaces...",
        "no_interfaces": "No active interfaces found.",
        "found_subnets": "Found {count} subnet(s)",
        "enter_target": "Please enter a target or use Auto-Detect",
        "scan_already_running": "Scan already running!",

        "mode_quick_desc": "Quick: ARP discovery + top 100 ports. Fast network overview.",
        "mode_normal_desc": "Normal: ARP + targeted port scan + service detection + OS fingerprint.",
        "mode_deep_desc": "Deep: Full port scan + service versions + NSE scripts + fingerprinting.",
        "mode_autopwn_desc": "Auto-Pwn: Full automated pipeline: scan → fingerprint → CVE → creds → exploit search → screenshots.",

        # ─── Results Screen ───
        "results": "Results",
        "total": "Total",
        "cameras": "Cameras",
        "vulnerable": "Vulnerable",
        "compromised": "Compromised",
        "all": "All",
        "iot": "IoT",
        "routers": "Routers",
        "pcs": "PCs",
        "nvr_dvr": "NVR/DVR",
        "printers": "Printers",
        "filter": "Filter",
        "sort": "Sort",
        "rescan": "Rescan",
        "export_html": "Export HTML",
        "export_pdf": "Export PDF",
        "export_json": "Export JSON",
        "back_to_scan": "Back to Scan",
        "no_results": "No scan results yet. Run a scan first.",
        "device_details": "Device Details",

        # ─── Device Screen ───
        "device_detail": "Device Detail",
        "open_ports": "Open Ports & Services",
        "vulnerabilities": "Vulnerabilities",
        "credentials": "Credentials",
        "rtsp_streams": "RTSP Streams",
        "onvif_info": "ONVIF Info",
        "additional_info": "Additional Info",
        "deep_scan": "Deep Scan",
        "check_creds": "Check Creds",
        "grab_frame": "Grab Frame",
        "exploit_msf": "Exploit (MSF)",
        "find_poc": "Find PoC",
        "shodan": "Shodan",
        "no_open_ports": "No open ports",
        "no_vulns": "No vulnerabilities found",
        "no_creds_tested": "No credentials tested",
        "no_rtsp": "No RTSP streams found",
        "no_onvif": "No ONVIF data",
        "no_extra": "No additional info",
        "starting_deep_scan": "Starting deep scan...",
        "deep_scan_complete": "Deep scan complete!",
        "checking_creds": "Checking default credentials...",
        "cred_check_complete": "Credential check complete! {count} successful logins found.",
        "capturing_frame": "Attempting to capture frame...",
        "frame_saved": "Frame saved to: {path}",
        "frame_failed": "Could not capture frame.",
        "searching_msf": "Searching Metasploit modules...",
        "found_msf_modules": "Found {count} MSF modules:",
        "no_msf_modules": "No matching MSF modules found.",
        "msf_manual_note": "To run exploits, use msfconsole manually.",
        "searching_poc": "Searching for PoC exploits...",
        "found_exploits": "Found {count} exploits:",
        "no_exploits": "No public exploits found.",
        "querying_shodan": "Querying Shodan...",
        "shodan_no_key": "Shodan API key not configured. Set it in data/api_keys.json",
        "shodan_results": "Shodan results:",

        # ─── Auto-Pwn Screen ───
        "autopwn_title": "Auto-Pwn",
        "autopwn_subtitle": "Automated Penetration Testing Pipeline",
        "mode_selection": "Mode Selection",
        "passive": "Passive",
        "aggressive": "Aggressive",
        "generate_html": "Generate HTML Report",
        "generate_pdf": "Generate PDF Report",
        "view_results": "View Results",
        "found": "Found",
        "mode_passive_desc": "Passive: Discovery + fingerprinting + CVE matching. No active exploitation or credential testing.",
        "mode_normal_autopwn_desc": "Normal: Discovery + fingerprinting + CVE + default credential testing + backdoor checks.",
        "mode_aggressive_desc": "Aggressive: Full pipeline including Metasploit exploit matching. Requires user confirmation before exploitation.",
        "autopwn_pipeline": "Auto-Pwn: Discovery → Fingerprint → CVE → Creds → Exploit → Report",

        # ─── Gallery Screen ───
        "camera_gallery": "Camera Gallery",
        "capture_all": "Capture All",
        "no_cameras": "No cameras found. Run a scan first.",
        "total_cameras": "Total cameras: {count}",
        "frame_captured": "Frame captured",
        "no_frame": "No frame",
        "default_creds_label": "DEFAULT CREDS",

        # ─── Footer ───
        "footer_scan": "Tab: Navigate | Enter: Select | Q: Quit | F1: Help",
        "footer_results": "F: Filter | S: Sort | Enter: Device Details | R: Rescan",
        "footer_device": "↑↓: Scroll | Enter: Action | B: Back",
        "footer_gallery": "Gallery shows cameras with accessible streams or captured frames",

        # ─── Scan progress ───
        "scanning_target": "Scanning {target}...",
        "fingerprinting": "Fingerprinting devices...",
        "checking_vulns": "Checking vulnerabilities...",
        "analyzing_cameras": "Analyzing cameras...",
        "checking_credentials": "Checking credentials...",
        "scan_complete": "Scan complete! Found {count} devices",
        "scan_complete_title": "Scan Complete",
        "autopwn_complete": "Auto-Pwn complete! {found} found, {vuln} vulnerable, {comp} compromised.",
        "autopwn_complete_title": "Auto-Pwn Complete",
        "export_complete": "Report saved: {path}",
        "export_complete_title": "Export Complete",
        "export_failed": "Export failed: {error}",
        "no_data_export": "No data to export.",

        # ─── Help ───
        "help_text": "NetScanner Help:\n1: Scan Screen | 2: Results | 3: Gallery | 4: Auto-Pwn\nQ: Quit | Enter: Select | Tab: Navigate",

        # ─── CLI ───
        "cli_checking_deps": "Checking dependencies...",
        "cli_updating_cve": "Updating CVE database...",
        "cli_update_complete": "CVE update complete!",
        "cli_new_cves": "New CVEs: {count}",
        "cli_total_cves": "Total CVEs: {count}",
        "cli_quick_scan": "Quick scanning: {target}",
        "cli_network_discovery": "Network discovery...",
        "cli_found_hosts": "Found {count} hosts",
        "cli_cve_matching": "CVE matching...",
        "cli_results_saved": "Results saved to: {path}",
        "cli_missing_deps": "Missing critical dependencies: {deps}",
        "cli_run_install": "Run: sudo bash install.sh",
        "cli_cve_outdated": "CVE database is outdated. Consider: sudo netscanner --update-cve",
        "cli_requires_root": "NetScanner requires root privileges for network scanning.",
        "cli_run_sudo": "Run: sudo netscanner",

        # ─── Language ───
        "language": "Language",
        "lang_en": "English",
        "lang_ru": "Русский",

        # ─── WiFi Screen ───
        "wifi_manager": "WiFi Manager",
        "wifi_subtitle": "Network Recon & Connection",
        "adapter": "Adapter",
        "select_adapter": "Select Adapter",
        "no_adapters": "No WiFi adapters found.",
        "adapter_info": "{name} ({driver}{monitor})",
        "monitor_supported": ", monitor✓",
        "monitor_not_supported": "",
        "current_status": "Status",
        "connected_to": "Connected to {ssid} ({ip})",
        "not_connected": "Not connected",
        "available_networks": "Available Networks",
        "quick_scan_wifi": "Quick Scan",
        "deep_scan_wifi": "Deep Scan (monitor)",
        "deep_scan_note": "Deep scan uses monitor mode to detect clients per network",
        "network_ssid": "SSID",
        "network_signal": "Signal",
        "network_channel": "Ch",
        "network_security": "Security",
        "network_wps": "WPS",
        "network_clients": "Clients",
        "network_packets": "Pkts",
        "network_router": "Router",
        "network_bssid": "BSSID",
        "hidden_network": "[Hidden]",
        "open_warning": "Open ⚠",
        "wps_warning": "⚠ WPS enabled — vulnerable to brute-force",
        "connection_section": "Connection",
        "selected_network": "Network",
        "enter_password": "Enter password",
        "connect_btn": "Connect",
        "disconnect_btn": "Disconnect",
        "connecting_to": "Connecting to {ssid}...",
        "connection_success": "Connected to {ssid}!",
        "connection_failed": "Connection failed: {error}",
        "disconnected_ok": "Disconnected",
        "network_recon": "Network Recon",
        "recon_after_connect": "Connect to a network to start recon",
        "router_info": "Router",
        "router_ports": "Ports",
        "dhcp_info": "DHCP",
        "internet_access": "Internet",
        "public_ip": "Public IP",
        "online": "Online",
        "offline": "Offline",
        "clients_in_network": "Clients in network ({count})",
        "client_ip": "IP",
        "client_mac": "MAC",
        "client_vendor": "Vendor",
        "client_hostname": "Hostname",
        "proceed_to_scan": "Proceed → Scan",
        "scanning_wifi": "Scanning WiFi networks...",
        "deep_scanning": "Deep scanning ({sec}s)...",
        "starting_monitor": "Starting monitor mode...",
        "stopping_monitor": "Stopping monitor mode...",
        "recon_running": "Running network recon...",
        "scanning_gateway": "Scanning gateway...",
        "discovering_clients": "Discovering clients...",
        "checking_internet": "Checking internet...",
        "recon_complete": "Recon complete!",
        "no_networks": "No networks found.",
        "footer_wifi": "5: WiFi | R: Refresh | D: Deep Scan | Enter: Select | Q: Quit",
    },

    "ru": {
        # ─── Общее ───
        "app_title": "NetScanner",
        "app_subtitle": "Профессиональный сетевой сканер для Kali Linux",
        "version": "v1.0.0",
        "ready": "Готов",
        "complete": "Завершено",
        "error": "Ошибка",
        "ok": "ОК",
        "yes": "Да",
        "no": "Нет",
        "back": "Назад",
        "quit": "Выход",
        "help": "Помощь",
        "navigate": "Навигация",
        "select": "Выбрать",
        "export": "Экспорт",
        "close": "Закрыть",
        "loading": "Загрузка...",
        "not_available": "Н/Д",

        # ─── Экран сканирования ───
        "target": "Цель",
        "target_placeholder": "IP, подсеть (192.168.1.0/24) или диапазон",
        "auto_detect": "Авто-определение",
        "scan_mode": "Режим сканирования",
        "quick": "Быстрый",
        "normal": "Обычный",
        "deep": "Глубокий",
        "auto_pwn": "Авто-взлом",
        "start_scan": "НАЧАТЬ СКАНИРОВАНИЕ",
        "detected_subnets": "Обнаруженные подсети",
        "detecting_interfaces": "Определение сетевых интерфейсов...",
        "no_interfaces": "Активные интерфейсы не найдены.",
        "found_subnets": "Найдено подсетей: {count}",
        "enter_target": "Введите цель или используйте Авто-определение",
        "scan_already_running": "Сканирование уже запущено!",

        "mode_quick_desc": "Быстрый: ARP-обнаружение + топ-100 портов. Быстрый обзор сети.",
        "mode_normal_desc": "Обычный: ARP + сканирование портов + определение сервисов + ОС.",
        "mode_deep_desc": "Глубокий: Полное сканирование портов + версии сервисов + NSE скрипты + фингерпринтинг.",
        "mode_autopwn_desc": "Авто-взлом: Полный автоматический конвейер: скан → фингерпринт → CVE → пароли → эксплойты → скриншоты.",

        # ─── Экран результатов ───
        "results": "Результаты",
        "total": "Всего",
        "cameras": "Камеры",
        "vulnerable": "Уязвимые",
        "compromised": "Взломанные",
        "all": "Все",
        "iot": "IoT",
        "routers": "Роутеры",
        "pcs": "ПК",
        "nvr_dvr": "NVR/DVR",
        "printers": "Принтеры",
        "filter": "Фильтр",
        "sort": "Сортировка",
        "rescan": "Пересканировать",
        "export_html": "Экспорт HTML",
        "export_pdf": "Экспорт PDF",
        "export_json": "Экспорт JSON",
        "back_to_scan": "К сканированию",
        "no_results": "Нет результатов. Сначала запустите сканирование.",
        "device_details": "Детали устройства",

        # ─── Экран устройства ───
        "device_detail": "Детали устройства",
        "open_ports": "Открытые порты и сервисы",
        "vulnerabilities": "Уязвимости",
        "credentials": "Учётные данные",
        "rtsp_streams": "RTSP-потоки",
        "onvif_info": "Информация ONVIF",
        "additional_info": "Дополнительная информация",
        "deep_scan": "Глубокий скан",
        "check_creds": "Проверить пароли",
        "grab_frame": "Захват кадра",
        "exploit_msf": "Эксплойт (MSF)",
        "find_poc": "Найти PoC",
        "shodan": "Shodan",
        "no_open_ports": "Нет открытых портов",
        "no_vulns": "Уязвимости не найдены",
        "no_creds_tested": "Пароли не проверялись",
        "no_rtsp": "RTSP-потоки не найдены",
        "no_onvif": "Нет данных ONVIF",
        "no_extra": "Нет дополнительной информации",
        "starting_deep_scan": "Запуск глубокого сканирования...",
        "deep_scan_complete": "Глубокое сканирование завершено!",
        "checking_creds": "Проверка стандартных паролей...",
        "cred_check_complete": "Проверка завершена! Найдено успешных входов: {count}.",
        "capturing_frame": "Попытка захвата кадра...",
        "frame_saved": "Кадр сохранён: {path}",
        "frame_failed": "Не удалось захватить кадр.",
        "searching_msf": "Поиск модулей Metasploit...",
        "found_msf_modules": "Найдено модулей MSF: {count}:",
        "no_msf_modules": "Подходящие модули MSF не найдены.",
        "msf_manual_note": "Для запуска эксплойтов используйте msfconsole.",
        "searching_poc": "Поиск PoC эксплойтов...",
        "found_exploits": "Найдено эксплойтов: {count}:",
        "no_exploits": "Публичные эксплойты не найдены.",
        "querying_shodan": "Запрос к Shodan...",
        "shodan_no_key": "API ключ Shodan не настроен. Укажите в data/api_keys.json",
        "shodan_results": "Результаты Shodan:",

        # ─── Экран Auto-Pwn ───
        "autopwn_title": "Авто-взлом",
        "autopwn_subtitle": "Автоматический конвейер пентеста",
        "mode_selection": "Выбор режима",
        "passive": "Пассивный",
        "aggressive": "Агрессивный",
        "generate_html": "Создать отчёт HTML",
        "generate_pdf": "Создать отчёт PDF",
        "view_results": "Просмотр результатов",
        "found": "Найдено",
        "mode_passive_desc": "Пассивный: Обнаружение + фингерпринтинг + CVE. Без активной эксплуатации и проверки паролей.",
        "mode_normal_autopwn_desc": "Обычный: Обнаружение + фингерпринтинг + CVE + проверка паролей + бэкдоры.",
        "mode_aggressive_desc": "Агрессивный: Полный конвейер включая подбор эксплойтов Metasploit. Требует подтверждения.",
        "autopwn_pipeline": "Авто-взлом: Обнаружение → Фингерпринт → CVE → Пароли → Эксплойт → Отчёт",

        # ─── Экран галереи ───
        "camera_gallery": "Галерея камер",
        "capture_all": "Захватить все",
        "no_cameras": "Камеры не найдены. Сначала запустите сканирование.",
        "total_cameras": "Всего камер: {count}",
        "frame_captured": "Кадр захвачен",
        "no_frame": "Нет кадра",
        "default_creds_label": "СТАНДАРТНЫЕ ПАРОЛИ",

        # ─── Подвал ───
        "footer_scan": "Tab: Навигация | Enter: Выбрать | Q: Выход | F1: Помощь",
        "footer_results": "F: Фильтр | S: Сортировка | Enter: Детали | R: Пересканировать",
        "footer_device": "↑↓: Прокрутка | Enter: Действие | B: Назад",
        "footer_gallery": "Галерея показывает камеры с доступными потоками или захваченными кадрами",

        # ─── Прогресс сканирования ───
        "scanning_target": "Сканирование {target}...",
        "fingerprinting": "Определение устройств...",
        "checking_vulns": "Проверка уязвимостей...",
        "analyzing_cameras": "Анализ камер...",
        "checking_credentials": "Проверка паролей...",
        "scan_complete": "Сканирование завершено! Найдено устройств: {count}",
        "scan_complete_title": "Сканирование завершено",
        "autopwn_complete": "Авто-взлом завершён! Найдено: {found}, уязвимых: {vuln}, взломано: {comp}.",
        "autopwn_complete_title": "Авто-взлом завершён",
        "export_complete": "Отчёт сохранён: {path}",
        "export_complete_title": "Экспорт завершён",
        "export_failed": "Ошибка экспорта: {error}",
        "no_data_export": "Нет данных для экспорта.",

        # ─── Помощь ───
        "help_text": "Справка NetScanner:\n1: Сканирование | 2: Результаты | 3: Галерея | 4: Авто-взлом\nQ: Выход | Enter: Выбрать | Tab: Навигация",

        # ─── CLI ───
        "cli_checking_deps": "Проверка зависимостей...",
        "cli_updating_cve": "Обновление базы CVE...",
        "cli_update_complete": "Обновление CVE завершено!",
        "cli_new_cves": "Новых CVE: {count}",
        "cli_total_cves": "Всего CVE: {count}",
        "cli_quick_scan": "Быстрое сканирование: {target}",
        "cli_network_discovery": "Обнаружение сети...",
        "cli_found_hosts": "Найдено хостов: {count}",
        "cli_cve_matching": "Проверка CVE...",
        "cli_results_saved": "Результаты сохранены: {path}",
        "cli_missing_deps": "Отсутствуют критические зависимости: {deps}",
        "cli_run_install": "Запустите: sudo bash install.sh",
        "cli_cve_outdated": "База CVE устарела. Рекомендуется: sudo netscanner --update-cve",
        "cli_requires_root": "NetScanner требует права root для сетевого сканирования.",
        "cli_run_sudo": "Запустите: sudo netscanner",

        # ─── Язык ───
        "language": "Язык",
        "lang_en": "English",
        "lang_ru": "Русский",

        # ─── Экран WiFi ───
        "wifi_manager": "WiFi Менеджер",
        "wifi_subtitle": "Разведка сети и подключение",
        "adapter": "Адаптер",
        "select_adapter": "Выберите адаптер",
        "no_adapters": "WiFi адаптеры не найдены.",
        "adapter_info": "{name} ({driver}{monitor})",
        "monitor_supported": ", monitor✓",
        "monitor_not_supported": "",
        "current_status": "Статус",
        "connected_to": "Подключено к {ssid} ({ip})",
        "not_connected": "Не подключено",
        "available_networks": "Доступные сети",
        "quick_scan_wifi": "Быстрый скан",
        "deep_scan_wifi": "Глубокий скан (monitor)",
        "deep_scan_note": "Глубокий скан использует monitor mode для определения клиентов каждой сети",
        "network_ssid": "SSID",
        "network_signal": "Сигнал",
        "network_channel": "Кан",
        "network_security": "Защита",
        "network_wps": "WPS",
        "network_clients": "Клиенты",
        "network_packets": "Пакеты",
        "network_router": "Роутер",
        "network_bssid": "BSSID",
        "hidden_network": "[Скрытая]",
        "open_warning": "Открытая ⚠",
        "wps_warning": "⚠ WPS включён — уязвим для brute-force",
        "connection_section": "Подключение",
        "selected_network": "Сеть",
        "enter_password": "Введите пароль",
        "connect_btn": "Подключиться",
        "disconnect_btn": "Отключить",
        "connecting_to": "Подключение к {ssid}...",
        "connection_success": "Подключено к {ssid}!",
        "connection_failed": "Ошибка подключения: {error}",
        "disconnected_ok": "Отключено",
        "network_recon": "Разведка сети",
        "recon_after_connect": "Подключитесь к сети для начала разведки",
        "router_info": "Роутер",
        "router_ports": "Порты",
        "dhcp_info": "DHCP",
        "internet_access": "Интернет",
        "public_ip": "Публичный IP",
        "online": "Онлайн",
        "offline": "Оффлайн",
        "clients_in_network": "Клиенты в сети ({count})",
        "client_ip": "IP",
        "client_mac": "MAC",
        "client_vendor": "Производитель",
        "client_hostname": "Имя хоста",
        "proceed_to_scan": "Далее → Сканирование",
        "scanning_wifi": "Сканирование WiFi сетей...",
        "deep_scanning": "Глубокое сканирование ({sec}с)...",
        "starting_monitor": "Запуск monitor mode...",
        "stopping_monitor": "Остановка monitor mode...",
        "recon_running": "Разведка сети...",
        "scanning_gateway": "Сканирование шлюза...",
        "discovering_clients": "Обнаружение клиентов...",
        "checking_internet": "Проверка интернета...",
        "recon_complete": "Разведка завершена!",
        "no_networks": "Сети не найдены.",
        "footer_wifi": "5: WiFi | R: Обновить | D: Глубокий скан | Enter: Выбрать | Q: Выход",
    },
}


# ═══════════════════════════════════════════════════════════════
# Global state and API
# ═══════════════════════════════════════════════════════════════

_current_lang = "en"


def get_lang() -> str:
    """Get current language code."""
    return _current_lang


def set_lang(lang: str) -> None:
    """Set current language. Saves to settings."""
    global _current_lang
    if lang in TRANSLATIONS:
        _current_lang = lang
        _save_setting("language", lang)


def t(key: str, **kwargs) -> str:
    """Get translated string by key. Supports {placeholder} formatting."""
    text = TRANSLATIONS.get(_current_lang, TRANSLATIONS["en"]).get(key)
    if text is None:
        # Fallback to English
        text = TRANSLATIONS["en"].get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError):
            pass
    return text


def load_language() -> None:
    """Load saved language preference."""
    global _current_lang
    settings = _load_settings()
    lang = settings.get("language", "en")
    if lang in TRANSLATIONS:
        _current_lang = lang


def available_languages() -> list[tuple[str, str]]:
    """Return list of (code, native_name) tuples."""
    return [
        ("en", "English"),
        ("ru", "Русский"),
    ]


# ═══════════════════════════════════════════════════════════════
# Settings persistence
# ═══════════════════════════════════════════════════════════════

def _load_settings() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_setting(key: str, value: str) -> None:
    settings = _load_settings()
    settings[key] = value
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(settings, f, indent=2)
    except OSError:
        pass
