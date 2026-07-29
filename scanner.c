/*
 * NetScan - простой многопоточный TCP/UDP сканер локальной сети для Windows
 * Совместимость: Windows Vista - Windows 11 (x86 / x64)
 *
 * Сборка (кросс-компиляция с Linux):
 *   x86_64-w64-mingw32-gcc -O2 -municode -D_WIN32_WINNT=0x0600 scanner.c -o netscan_x64.exe -lws2_32 -static -static-libgcc
 *
 * Автор: сгенерировано Claude по ТЗ пользователя.
 */

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define FD_SETSIZE 1024

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <ipexport.h>
#include <icmpapi.h>
#include <iphlpapi.h>
#include <wininet.h>
#define COBJMACROS
#include <objbase.h>
#include <wbemidl.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wtsapi32.lib")

/* ---------------------------------------------------------------------- */
/* Общие структуры                                                        */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint32_t start; /* host byte order */
    uint32_t end;   /* host byte order, inclusive */
    uint64_t cumulative_before; /* сумма количеств хостов всех предыдущих диапазонов */
} IpRange;

static IpRange *g_ranges = NULL;
static int g_range_count = 0;
static uint64_t g_total_hosts = 0;

static uint16_t *g_ports = NULL;
static int g_port_count = 0;

typedef struct {
    uint32_t ip;
    uint16_t port;
} Hit;

static Hit *g_tcp_hits = NULL;
static int g_tcp_hit_count = 0;
static int g_tcp_hit_cap = 0;

static Hit *g_udp_hits = NULL;
static int g_udp_hit_count = 0;
static int g_udp_hit_cap = 0;

static CRITICAL_SECTION g_results_cs;
static CRITICAL_SECTION g_console_cs;

/* прогресс */
typedef struct {
    volatile LONG64 claim;     /* атомарный счётчик захвата задач */
    volatile LONG64 completed; /* сколько задач реально выполнено */
    volatile LONG64 found;
    uint64_t total;
    const char *name;
    int is_tcp;        /* актуально для TCP/UDP фаз, для PING игнорируется */
    int console_line;  /* -1 = обычный однострочный режим (перезапись через \r);
                           >=0 = фиксированная строка в консоли (для параллельного TCP+UDP) */
} ScanState;

static int g_console_base_y = -1; /* строка консоли, с которой начинаются "закреплённые" строки прогресса */


/* ICMP-разведка (host discovery) */
static uint32_t *g_alive_ips = NULL;
static int *g_alive_ttl = NULL; /* параллельный массив: TTL из ICMP-ответа (-1 = неизвестен) */
static int g_alive_count = 0;
static int g_alive_cap = 0;
static CRITICAL_SECTION g_alive_cs;
static int g_discover_mode = 0;       /* --discover: фильтровать по живым хостам */
static int g_ping_timeout_ms = 500;
static int g_retries = 1;             /* число попыток на TCP/UDP порт */

static int g_thread_count = 100;
static int g_fast_mode = 0; /* 0 = full, 1 = fast */
static int g_timeout_ms = 800;
static int g_batch_size = 32; /* fast-режим: сколько соединений держит открытыми ОДИН поток одновременно */
static int g_sequential = 0;  /* --sequential: сканировать TCP и UDP по очереди, а не параллельно */
static int g_include_reserved = 0; /* --include-reserved: не пропускать x.x.x.0/x.x.x.255 */
static volatile LONG64 g_skipped_reserved = 0;
static int g_resume_mode = 0; /* --resume/-r: дописывать в файл результатов, а не перезаписывать */
static int g_when_mode = 0;   /* --when/-w: писать метку времени перед результатами */
static int g_sort_by_port_also = 0; /* --sort-by-port: доп. файл с результатами, отсортированными по порту */
static int g_sort_os = 0;     /* --sort-os: сортировать блок "Информация об устройствах" по ОС */
static char g_out_path[MAX_PATH] = "scan_result.txt";

/* ---------------------------------------------------------------------- */
/* Диагностика устройств (--info): TTL/ОС, MAC+вендор, SNMP, NetBIOS,     */
/* mDNS, эвристика по открытым портам. Собирается ОДИН РАЗ на хост,       */
/* не на порт - не замедляет сам скан.                                   */
/* ---------------------------------------------------------------------- */

static int g_info_mode = 0;         /* --info: собирать доп. информацию об устройствах */
static int g_deep_resolve = 0;      /* --deep-resolve: доп. способы определения имени (PTR через DNS, SMB2/NTLMSSP) */
static uint32_t g_dns_server_override = 0; /* --dns-server: свой DNS-сервер для обратных PTR-запросов вместо шлюза */

/* ---------------------------------------------------------------------- */
/* WMI через DCOM (--wmi): версия ОС, время загрузки, ядра/RAM,           */
/* залогиненный пользователь. Требует прав на целевой машине (SSO текущим */
/* пользователем ЛИБО явные логин/пароль) - в отличие от всей остальной   */
/* диагностики выше, это НЕ анонимные протокольные запросы.               */
/* ---------------------------------------------------------------------- */
static int g_wmi_mode = 0;
static int g_wmi_gpu = 0;         /* --wmi-gpu: дополнительно запросить модель видеоадаптера */
static char g_wmi_user[128] = ""; /* --wmi-user: пусто = текущий пользователь (SSO) */
static char g_wmi_password[128] = "";
static char g_wmi_domain[128] = ""; /* --wmi-domain: опционально, для user -> DOMAIN\user */
static int g_wmi_com_ready = 0;   /* CoInitializeSecurity выполнен успешно в главном потоке */

/* ---------------------------------------------------------------------- */
/* WTS (Terminal Services API, --wts): то же самое, что делает            */
/* штатный quser/qwinsta - логон/бездействие/сессия удалённого хоста.     */
/* Использует ТЕ ЖЕ учётные данные --wmi-user/--wmi-password/--wmi-domain */
/* (пусто = текущая сессия, SSO), т.к. концептуально это тот же класс     */
/* "требует прав" диагностики, что и --wmi, просто другой API/транспорт.  */
/* ---------------------------------------------------------------------- */
static int g_wts_mode = 0;
static int g_update_oui_only = 0;   /* --update-oui: только скачать базу OUI и выйти */
#define OUI_URL "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes"

typedef struct {
    char prefix[10]; /* до 9 hex-символов (24/28/36-бит префикс) + \0 */
    int prefix_len;  /* длина строки префикса в hex-символах */
    char *vendor;
} OuiEntry;

static OuiEntry *g_oui = NULL;
static int g_oui_count = 0;

typedef struct {
    uint32_t ip;
    int has_ttl;
    int ttl;
    const char *os_guess;
    int has_mac;
    unsigned char mac[6];
    const char *vendor;
    int has_netbios;
    char netbios_name[17];
    char netbios_group[17];
    int has_snmp;
    char snmp_descr[256];
    int has_mdns;
    char mdns_name[256];
    int has_llmnr;
    char llmnr_name[256];
    int has_ptr;
    char ptr_name[256];
    int has_smb;
    char smb_nb_name[64];
    char smb_nb_domain[64];
    char smb_dns_name[128];
    char smb_dns_domain[128];
    int has_wmi;
    char wmi_error[160];      /* причина неудачи - важно для диагностики прав/файрвола */
    char wmi_os_caption[128]; /* "Microsoft Windows 10 Pro" и т.п. */
    char wmi_os_version[64];  /* "10.0.19045" */
    char wmi_os_build[32];
    char wmi_boot_time[32];   /* дата/время последней загрузки, человекочитаемо */
    int wmi_cpu_cores;
    double wmi_ram_gb;
    char wmi_logged_user[128];
    char wmi_logon_time[32];
    char wmi_gpu[128];
    int has_wts;
    char wts_error[160];
    char wts_username[64];
    char wts_domain[64];
    char wts_logon_time[32];
    char wts_connect_time[32];
    double wts_idle_minutes; /* -1 = неизвестно */
    const char *device_guess;
} HostInfo;

static HostInfo *g_host_infos = NULL;
static int g_host_info_count = 0;

/* ---------------------------------------------------------------------- */
/* Утилиты                                                                */
/* ---------------------------------------------------------------------- */

/* Исходник в UTF-8, но cmd.exe по умолчанию использует другую кодовую
   страницу (обычно OEM 866), и на некоторых версиях Windows связка
   conprintf()+кодовая страница 65001 ломает вывод многобайтовых символов.
   Поэтому пишем в консоль напрямую через WriteConsoleW (UTF-16) - это
   работает корректно на любой Windows Vista-11 независимо от текущей
   кодовой страницы. Если вывод перенаправлен в файл/pipe (не консоль),
   пишем как есть в UTF-8. */
static void conprint_h(HANDLE h, const char *fmt, va_list ap) {
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int needed = vsnprintf(NULL, 0, fmt, ap_copy);
    va_end(ap_copy);
    if (needed < 0) return;

    char *buf = malloc((size_t)needed + 1);
    if (!buf) return;
    vsnprintf(buf, (size_t)needed + 1, fmt, ap);

    DWORD mode;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        int wneeded = MultiByteToWideChar(CP_UTF8, 0, buf, -1, NULL, 0);
        if (wneeded > 0) {
            wchar_t *wbuf = malloc(sizeof(wchar_t) * (size_t)wneeded);
            if (wbuf) {
                MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, wneeded);
                DWORD written;
                WriteConsoleW(h, wbuf, (DWORD)(wneeded - 1), &written, NULL);
                free(wbuf);
                free(buf);
                return;
            }
        }
    }
    FILE *target = (h == GetStdHandle(STD_ERROR_HANDLE)) ? stderr : stdout;
    fputs(buf, target);
    fflush(target);
    free(buf);
}

static void conprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    conprint_h(GetStdHandle(STD_OUTPUT_HANDLE), fmt, ap);
    va_end(ap);
}

static void conprintf_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    conprint_h(GetStdHandle(STD_ERROR_HANDLE), fmt, ap);
    va_end(ap);
}

static void die(const char *msg) {
    conprintf_err("Ошибка: %s\n", msg);
    exit(1);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        *--end = 0;
    }
    return s;
}

static uint32_t ip_to_u32(const char *s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) {
        conprintf_err("Некорректный IP адрес: %s\n", s);
        exit(1);
    }
    return ntohl(a.s_addr);
}

static void u32_to_ip_str(uint32_t ip, char *buf, size_t bufsize) {
    struct in_addr a;
    a.s_addr = htonl(ip);
    /* inet_ntop is thread-safe, no static buffers */
    inet_ntop(AF_INET, &a, buf, (socklen_t)bufsize);
}

/* ---------------------------------------------------------------------- */
/* OUI-база (MAC -> вендор). Файл oui.txt лежит рядом с exe, формат nmap: */
/* "XXXXXX VendorName" (6/7/9 hex-символов - 24/28/36-битный префикс).    */
/* ---------------------------------------------------------------------- */

static void get_oui_path(char *buf, size_t bufsize) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
    char *last_slash = strrchr(exe_path, '\\');
    if (last_slash) {
        size_t dir_len = (size_t)(last_slash - exe_path) + 1;
        if (dir_len >= bufsize) dir_len = bufsize - 1;
        memcpy(buf, exe_path, dir_len);
        buf[dir_len] = 0;
        strncat(buf, "oui.txt", bufsize - strlen(buf) - 1);
    } else {
        strncpy(buf, "oui.txt", bufsize - 1);
        buf[bufsize - 1] = 0;
    }
}

static int download_oui_database(const char *dest_path) {
    conprintf("Скачиваю базу OUI (%s)...\n", OUI_URL);
    HINTERNET hInternet = InternetOpenA("NetScan/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        conprintf_err("Не удалось инициализировать WinINet\n");
        return 0;
    }
    HINTERNET hUrl = InternetOpenUrlA(hInternet, OUI_URL, NULL, 0,
                                       INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        conprintf_err("Не удалось скачать базу OUI (нет сети или заблокирован доступ к GitHub)\n");
        InternetCloseHandle(hInternet);
        return 0;
    }
    FILE *f = fopen(dest_path, "wb");
    if (!f) {
        conprintf_err("Не удалось создать файл %s\n", dest_path);
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return 0;
    }
    char buf[8192];
    DWORD read_bytes;
    long total = 0;
    while (InternetReadFile(hUrl, buf, sizeof(buf), &read_bytes) && read_bytes > 0) {
        fwrite(buf, 1, read_bytes, f);
        total += (long)read_bytes;
    }
    fclose(f);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (total < 1000) { /* подозрительно маленький файл - скорее всего ошибка/заглушка */
        conprintf_err("Скачанный файл подозрительно мал (%ld байт) - похоже, скачивание не удалось\n", total);
        return 0;
    }
    conprintf("Готово: %ld байт сохранено в %s\n", total, dest_path);
    return 1;
}

static void load_oui_database(void) {
    char path[MAX_PATH];
    get_oui_path(path, sizeof(path));

    FILE *f = fopen(path, "r");
    if (!f) return; /* базы нет - молча работаем без определения вендора */

    int cap = 4096;
    g_oui = malloc(sizeof(OuiEntry) * cap);
    g_oui_count = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\r' || line[0] == '\n') continue;
        char *sp = strchr(line, ' ');
        if (!sp) continue;
        *sp = 0;
        char *prefix = line;
        char *vendor = sp + 1;
        char *nl = strpbrk(vendor, "\r\n");
        if (nl) *nl = 0;
        int plen = (int)strlen(prefix);
        if (plen < 6 || plen > 9) continue;
        if (*vendor == 0) continue;

        if (g_oui_count == cap) {
            cap *= 2;
            g_oui = realloc(g_oui, sizeof(OuiEntry) * cap);
        }
        strncpy(g_oui[g_oui_count].prefix, prefix, sizeof(g_oui[g_oui_count].prefix) - 1);
        g_oui[g_oui_count].prefix[sizeof(g_oui[g_oui_count].prefix) - 1] = 0;
        for (char *p = g_oui[g_oui_count].prefix; *p; p++) *p = (char)toupper((unsigned char)*p);
        g_oui[g_oui_count].prefix_len = plen;
        g_oui[g_oui_count].vendor = _strdup(vendor);
        g_oui_count++;
    }
    fclose(f);
}

/* ищет вендора по MAC, отдавая предпочтение самому длинному (самому
   точному) совпадающему префиксу среди 24/28/36-битных записей */
static const char *lookup_vendor(const unsigned char mac[6]) {
    if (!g_oui || g_oui_count == 0) return NULL;

    char hex[13];
    snprintf(hex, sizeof(hex), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    const char *best = NULL;
    int best_len = 0;
    for (int i = 0; i < g_oui_count; i++) {
        int plen = g_oui[i].prefix_len;
        if (plen <= best_len) continue; /* уже нашли не хуже - короткие не интересны */
        if (memcmp(hex, g_oui[i].prefix, (size_t)plen) == 0) {
            best = g_oui[i].vendor;
            best_len = plen;
        }
    }
    return best;
}

/* ---------------------------------------------------------------------- */
/* Разбор диапазонов IP: "192.168.0.1-192.168.255.255,10.51.11.1-10.51.11.255" */
/* Так же поддерживается перенос строки как разделитель и одиночные IP.    */
/* ---------------------------------------------------------------------- */

static void parse_ip_ranges(const char *input) {
    char *copy = _strdup(input);
    int cap = 8;
    g_ranges = malloc(sizeof(IpRange) * cap);
    g_range_count = 0;

    /* заменяем переносы строк на запятые, чтобы разбирать всё единым образом */
    for (char *p = copy; *p; p++) {
        if (*p == '\n' || *p == '\r' || *p == ';') *p = ',';
    }

    char *saveptr = NULL;
    char *tok = strtok_s(copy, ",", &saveptr);
    while (tok) {
        char *t = trim(tok);
        if (*t) {
            char *dash = strchr(t, '-');
            uint32_t start, end;
            if (dash) {
                *dash = 0;
                char *left = trim(t);
                char *right = trim(dash + 1);
                start = ip_to_u32(left);
                end = ip_to_u32(right);
            } else {
                start = end = ip_to_u32(t);
            }
            if (start > end) { uint32_t tmp = start; start = end; end = tmp; }

            if (g_range_count == cap) {
                cap *= 2;
                g_ranges = realloc(g_ranges, sizeof(IpRange) * cap);
            }
            g_ranges[g_range_count].start = start;
            g_ranges[g_range_count].end = end;
            g_ranges[g_range_count].cumulative_before = g_total_hosts;
            g_total_hosts += ((uint64_t)end - (uint64_t)start + 1ULL);
            g_range_count++;
        }
        tok = strtok_s(NULL, ",", &saveptr);
    }
    free(copy);

    if (g_range_count == 0) die("Не удалось разобрать список IP-адресов");
}

static uint32_t ip_at_index(uint64_t idx) {
    /* диапазонов обычно немного - линейный поиск достаточен */
    for (int i = 0; i < g_range_count; i++) {
        uint64_t count = (uint64_t)g_ranges[i].end - (uint64_t)g_ranges[i].start + 1ULL;
        if (idx < g_ranges[i].cumulative_before + count) {
            uint64_t offset = idx - g_ranges[i].cumulative_before;
            return g_ranges[i].start + (uint32_t)offset;
        }
    }
    /* не должно происходить */
    return g_ranges[g_range_count - 1].end;
}

/* Возвращает хост для сканирования по индексу: если включён --discover -
   берём из материализованного списка живых (по данным ICMP), иначе -
   ленивый перебор всего адресного диапазона. */
static uint32_t get_scan_host(uint64_t idx) {
    if (g_discover_mode) return g_alive_ips[idx];
    return ip_at_index(idx);
}

/* x.x.x.0 и x.x.x.255 почти всегда сетевой/broadcast-адрес для типичной
   домашней/офисной /24-сети. Опрос broadcast-адреса даёт ложные результаты
   (отвечает случайный сосед по подсети, а не "хост" x.x.x.255 - такого
   хоста просто не существует), поэтому по умолчанию пропускаем. */
static int is_reserved_host(uint32_t ip) {
    if (g_include_reserved) return 0;
    uint32_t last_octet = ip & 0xFF;
    return last_octet == 0 || last_octet == 255;
}

static void add_alive(ScanState *st, uint32_t ip, int ttl) {
    EnterCriticalSection(&g_alive_cs);
    if (g_alive_count == g_alive_cap) {
        g_alive_cap = g_alive_cap ? g_alive_cap * 2 : 256;
        g_alive_ips = realloc(g_alive_ips, sizeof(uint32_t) * g_alive_cap);
        g_alive_ttl = realloc(g_alive_ttl, sizeof(int) * g_alive_cap);
    }
    g_alive_ips[g_alive_count] = ip;
    g_alive_ttl[g_alive_count] = ttl;
    g_alive_count++;
    LeaveCriticalSection(&g_alive_cs);
    InterlockedIncrement64((volatile LONG64 *)&st->found);
}

/* ---------------------------------------------------------------------- */
/* Разбор портов: "80,443,1000-1200,500,445,53"                           */
/* ---------------------------------------------------------------------- */

static void parse_ports(const char *input) {
    char *copy = _strdup(input);
    int cap = 16;
    g_ports = malloc(sizeof(uint16_t) * cap);
    g_port_count = 0;

    /* битовая карта уже добавленных портов - защита от дублей во входных
       данных (например, пользователь указал один и тот же порт дважды) */
    unsigned char seen[8192] = {0}; /* 65536 бит */
    #define PORT_SEEN(p)     (seen[(p) >> 3] & (1 << ((p) & 7)))
    #define PORT_MARK_SEEN(p) (seen[(p) >> 3] |= (1 << ((p) & 7)))

    char *saveptr = NULL;
    char *tok = strtok_s(copy, ",", &saveptr);
    while (tok) {
        char *t = trim(tok);
        if (*t) {
            char *dash = strchr(t, '-');
            int start, end;
            if (dash) {
                *dash = 0;
                start = atoi(trim(t));
                end = atoi(trim(dash + 1));
            } else {
                start = end = atoi(t);
            }
            if (start > end) { int tmp = start; start = end; end = tmp; }
            if (start < 1 || end > 65535) die("Порт вне диапазона 1-65535");

            for (int p = start; p <= end; p++) {
                if (PORT_SEEN(p)) continue; /* уже добавлен - пропускаем дубль */
                PORT_MARK_SEEN(p);
                if (g_port_count == cap) {
                    cap *= 2;
                    g_ports = realloc(g_ports, sizeof(uint16_t) * cap);
                }
                g_ports[g_port_count++] = (uint16_t)p;
            }
        }
        tok = strtok_s(NULL, ",", &saveptr);
    }
    free(copy);

    #undef PORT_SEEN
    #undef PORT_MARK_SEEN

    if (g_port_count == 0) die("Не удалось разобрать список портов");
}

/* ---------------------------------------------------------------------- */
/* Сохранение результатов                                                  */
/* ---------------------------------------------------------------------- */

static void add_hit(ScanState *st, int is_tcp, uint32_t ip, uint16_t port) {
    EnterCriticalSection(&g_results_cs);
    if (is_tcp) {
        if (g_tcp_hit_count == g_tcp_hit_cap) {
            g_tcp_hit_cap = g_tcp_hit_cap ? g_tcp_hit_cap * 2 : 64;
            g_tcp_hits = realloc(g_tcp_hits, sizeof(Hit) * g_tcp_hit_cap);
        }
        g_tcp_hits[g_tcp_hit_count].ip = ip;
        g_tcp_hits[g_tcp_hit_count].port = port;
        g_tcp_hit_count++;
    } else {
        if (g_udp_hit_count == g_udp_hit_cap) {
            g_udp_hit_cap = g_udp_hit_cap ? g_udp_hit_cap * 2 : 64;
            g_udp_hits = realloc(g_udp_hits, sizeof(Hit) * g_udp_hit_cap);
        }
        g_udp_hits[g_udp_hit_count].ip = ip;
        g_udp_hits[g_udp_hit_count].port = port;
        g_udp_hit_count++;
    }
    InterlockedIncrement64((volatile LONG64 *)&st->found);
    LeaveCriticalSection(&g_results_cs);
}

static int hit_cmp(const void *a, const void *b) {
    const Hit *ha = (const Hit *)a, *hb = (const Hit *)b;
    if (ha->ip != hb->ip) return (ha->ip < hb->ip) ? -1 : 1;
    if (ha->port != hb->port) return (ha->port < hb->port) ? -1 : 1;
    return 0;
}

static int hit_cmp_by_port(const void *a, const void *b) {
    const Hit *ha = (const Hit *)a, *hb = (const Hit *)b;
    if (ha->port != hb->port) return (ha->port < hb->port) ? -1 : 1;
    if (ha->ip != hb->ip) return (ha->ip < hb->ip) ? -1 : 1;
    return 0;
}

/* убирает соседние дубликаты в уже отсортированном массиве - подстраховка
   на случай пересекающихся диапазонов IP или иных источников повторов */
static int dedup_hits(Hit *arr, int count) {
    if (count <= 1) return count;
    int out = 1;
    for (int i = 1; i < count; i++) {
        if (arr[i].ip != arr[out - 1].ip || arr[i].port != arr[out - 1].port) {
            arr[out++] = arr[i];
        }
    }
    return out;
}

static int host_has_tcp_port(uint32_t ip, uint16_t port) {
    for (int i = 0; i < g_tcp_hit_count; i++)
        if (g_tcp_hits[i].ip == ip && g_tcp_hits[i].port == port) return 1;
    return 0;
}
static int host_has_udp_port(uint32_t ip, uint16_t port) {
    for (int i = 0; i < g_udp_hit_count; i++)
        if (g_udp_hits[i].ip == ip && g_udp_hits[i].port == port) return 1;
    return 0;
}

/* эвристика типа устройства по набору открытых портов - чистый offline
   анализ уже собранных результатов, ноль дополнительных пакетов */
static const char *guess_device_by_ports(uint32_t ip) {
    if (host_has_tcp_port(ip, 515) || host_has_tcp_port(ip, 631) || host_has_tcp_port(ip, 9100))
        return "Принтер (LPD/IPP/JetDirect)";
    if (host_has_tcp_port(ip, 554))
        return "IP-камера/медиа (RTSP)";
    if (host_has_tcp_port(ip, 5555))
        return "Android (открыт ADB)";
    if (host_has_tcp_port(ip, 62078))
        return "iOS-устройство (сервис синхронизации)";
    if (host_has_tcp_port(ip, 3389))
        return "Windows (RDP)";
    if (host_has_tcp_port(ip, 445) && host_has_tcp_port(ip, 139))
        return "Windows/Samba (SMB)";
    if (host_has_udp_port(ip, 1900) || host_has_tcp_port(ip, 8009) || host_has_tcp_port(ip, 8008))
        return "Медиа-устройство (UPnP/Cast)";
    if (host_has_tcp_port(ip, 22) && !host_has_tcp_port(ip, 445))
        return "Linux/сетевое устройство (SSH)";
    return NULL;
}

/* ---------------------------------------------------------------------- */
/* Прогресс-бар                                                           */
/* ---------------------------------------------------------------------- */

static void print_progress(ScanState *st) {
    EnterCriticalSection(&g_console_cs);
    LONG64 done = st->completed;
    uint64_t total = st->total ? st->total : 1;
    double pct = 100.0 * (double)done / (double)total;
    if (pct > 100.0) pct = 100.0;
    int barw = 30;
    int filled = (int)(pct / 100.0 * barw);
    char bar[64];
    int i = 0;
    for (; i < filled && i < barw; i++) bar[i] = '#';
    for (; i < barw; i++) bar[i] = '-';
    bar[barw] = 0;

    char line[256];
    snprintf(line, sizeof(line), "[%s] [%s] %5.1f%%  %10llu/%-10llu  найдено:%-6lld",
             st->name, bar, pct,
             (unsigned long long)done, (unsigned long long)total,
             (long long)st->found);

    if (st->console_line >= 0 && g_console_base_y >= 0) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        COORD pos;
        pos.X = 0;
        pos.Y = (SHORT)(g_console_base_y + st->console_line);
        SetConsoleCursorPosition(h, pos);
        conprintf("%s", line);
        fflush(stdout);
        COORD safe;
        safe.X = 0;
        safe.Y = (SHORT)(g_console_base_y + 2);
        SetConsoleCursorPosition(h, safe);
    } else {
        conprintf("\r%s", line);
        fflush(stdout);
    }
    LeaveCriticalSection(&g_console_cs);
}

/* ---------------------------------------------------------------------- */
/* Скан TCP: один порт, режим full (одно неблокирующее подключение с      */
/* таймаутом на поток)                                                     */
/* ---------------------------------------------------------------------- */

static int tcp_check(uint32_t ip_h, uint16_t port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode); /* неблокирующий режим */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip_h);

    int r = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (r == 0) {
        closesocket(s);
        return 1; /* мгновенный успех (localhost и т.п.) */
    }

    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK) {
        closesocket(s);
        return 0;
    }

    fd_set wfds, efds;
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(s, &wfds);
    FD_SET(s, &efds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(0, NULL, &wfds, &efds, &tv);
    int open = 0;
    if (sel > 0 && FD_ISSET(s, &wfds) && !FD_ISSET(s, &efds)) {
        int soerr = 0;
        int len = sizeof(soerr);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len) == 0 && soerr == 0) {
            open = 1;
        }
    }
    closesocket(s);
    return open;
}

/* ---------------------------------------------------------------------- */
/* Осмысленные пробники для распространённых UDP-сервисов.                */
/* Пустой/произвольный байт многие сервисы (DNS и т.п.) молча игнорируют, */
/* т.к. не могут распарсить его как валидный запрос - поэтому TCP:53      */
/* находится, а UDP:53 - нет, хотя сервис работает. Отправляем настоящий  */
/* протокольный запрос, чтобы получить осмысленный ответ.                 */
/* ---------------------------------------------------------------------- */

static int get_udp_payload(uint16_t port, unsigned char *buf, int bufcap) {
    switch (port) {
        case 53: { /* DNS: A-запрос настоящего домена example.com (запрос
                      корневой зоны "." нетипичен и некоторые нестандартные
                      резолверы, например DNS-прокси Tor, могут вести себя
                      с ним непредсказуемо) */
            static const unsigned char dns[] = {
                0x00,0x01, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00, /* QNAME */
                0x00,0x01,        /* QTYPE: A */
                0x00,0x01         /* QCLASS: IN */
            };
            if (bufcap < (int)sizeof(dns)) return 0;
            memcpy(buf, dns, sizeof(dns));
            return (int)sizeof(dns);
        }
        case 123: { /* NTP: стандартный клиентский запрос (client mode 3) */
            if (bufcap < 48) return 0;
            memset(buf, 0, 48);
            buf[0] = 0x1B;
            return 48;
        }
        case 161: { /* SNMP v1 GetRequest, community "public", sysDescr.0 */
            static const unsigned char snmp[] = {
                0x30,0x29,
                0x02,0x01,0x00,
                0x04,0x06,'p','u','b','l','i','c',
                0xA0,0x1C,
                0x02,0x04,0x00,0x00,0x00,0x01,
                0x02,0x01,0x00,
                0x02,0x01,0x00,
                0x30,0x0E,
                0x30,0x0C,
                0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,
                0x05,0x00
            };
            if (bufcap < (int)sizeof(snmp)) return 0;
            memcpy(buf, snmp, sizeof(snmp));
            return (int)sizeof(snmp);
        }
        default:
            return 0; /* нет специфичной сигнатуры - используем общий 1-байтовый пробник */
    }
}

/* ---------------------------------------------------------------------- */
/* Скан UDP: отправляем короткий пробный пакет, ждём явный ответ.         */
/* Если ответа нет за таймаут - порт НЕ выводится (по требованию).        */
/* ---------------------------------------------------------------------- */

static int udp_check(uint32_t ip_h, uint16_t port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip_h);

    unsigned char payload[128];
    int plen = get_udp_payload(port, payload, sizeof(payload));
    if (plen <= 0) { payload[0] = 0; plen = 1; }
    sendto(s, (const char *)payload, plen, 0, (struct sockaddr *)&addr, sizeof(addr));

    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));

    char buf[512];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int r = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);

    closesocket(s);
    return (r >= 0); /* явный ответ получен -> открыт */
}

/* ---------------------------------------------------------------------- */
/* ICMP-пинг для разведки живых хостов. Использует IcmpSendEcho -          */
/* штатный Windows API (iphlpapi), НЕ требует прав администратора и        */
/* raw-сокетов, работает начиная с Windows XP.                             */
/* ---------------------------------------------------------------------- */

static int icmp_check_ex(uint32_t ip_h, int timeout_ms, int *ttl_out) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return 0;

    char send_data[32] = "netscan-probe";
    char reply_buf[sizeof(ICMP_ECHO_REPLY) + sizeof(send_data) + 16];

    DWORD ret = IcmpSendEcho(hIcmp, htonl(ip_h), send_data, (WORD)sizeof(send_data),
                              NULL, reply_buf, sizeof(reply_buf), (DWORD)timeout_ms);

    IcmpCloseHandle(hIcmp);

    if (ret == 0) return 0;
    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)reply_buf;
    if (reply->Status == IP_SUCCESS) {
        if (ttl_out) *ttl_out = reply->Options.Ttl;
        return 1;
    }
    return 0;
}

/* грубая эвристика ОС по TTL: реальные системы уменьшают TTL на 1 за хоп,
   поэтому округляем наблюдаемое значение до ближайшего "снизу" стандартного
   стартового TTL. Точность условна (TTL можно поменять вручную), но как
   быстрый ориентир - вполне рабочий метод. */
static const char *guess_os_by_ttl(int ttl) {
    if (ttl <= 0) return NULL;
    if (ttl <= 64) return "Linux/Android/embedded (TTL<=64)";
    if (ttl <= 128) return "Windows (TTL<=128)";
    return "Сетевое оборудование/иное (TTL<=255)";
}

/* ---------------------------------------------------------------------- */
/* Локальные подсети этой машины (нужно для ARP-разведки: SendARP для     */
/* адреса ВНЕ локального L2-сегмента тихо вернёт MAC шлюза вместо ошибки, */
/* поэтому доверять ARP-результату можно только если адрес точно в одной */
/* из наших локально подключённых подсетей).                              */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint32_t network;
    uint32_t mask;
} LocalSubnet;

static LocalSubnet *g_local_subnets = NULL;
static int g_local_subnet_count = 0;
static uint32_t *g_own_ips = NULL;
static int g_own_ip_count = 0;
static uint32_t g_gateway_ip = 0; /* первый найденный шлюз - по умолчанию для --deep-resolve PTR */
#define LOOPBACK_IP 0x7F000001u /* 127.0.0.1 */

static void load_local_subnets(void) {
    ULONG buf_len = 0;
    GetAdaptersInfo(NULL, &buf_len);
    if (buf_len == 0) return;

    PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)malloc(buf_len);
    if (!info) return;

    if (GetAdaptersInfo(info, &buf_len) != NO_ERROR) {
        free(info);
        return;
    }

    int cap = 8;
    g_local_subnets = malloc(sizeof(LocalSubnet) * cap);
    g_local_subnet_count = 0;
    g_own_ips = malloc(sizeof(uint32_t) * cap);
    g_own_ip_count = 0;

    for (PIP_ADAPTER_INFO p = info; p; p = p->Next) {
        for (PIP_ADDR_STRING addr = &p->IpAddressList; addr; addr = addr->Next) {
            struct in_addr ip_a, mask_a;
            if (inet_pton(AF_INET, addr->IpAddress.String, &ip_a) != 1) continue;
            if (inet_pton(AF_INET, addr->IpMask.String, &mask_a) != 1) continue;
            uint32_t ip_h = ntohl(ip_a.s_addr);
            uint32_t mask_h = ntohl(mask_a.s_addr);
            if (ip_h == 0 || mask_h == 0) continue;

            if (g_local_subnet_count == cap) {
                cap *= 2;
                g_local_subnets = realloc(g_local_subnets, sizeof(LocalSubnet) * cap);
                g_own_ips = realloc(g_own_ips, sizeof(uint32_t) * cap);
            }
            g_local_subnets[g_local_subnet_count].network = ip_h & mask_h;
            g_local_subnets[g_local_subnet_count].mask = mask_h;
            g_local_subnet_count++;

            g_own_ips[g_own_ip_count++] = ip_h;
        }
        if (g_gateway_ip == 0) {
            for (PIP_ADDR_STRING gw = &p->GatewayList; gw; gw = gw->Next) {
                struct in_addr gw_a;
                if (inet_pton(AF_INET, gw->IpAddress.String, &gw_a) == 1 && gw_a.s_addr != 0) {
                    g_gateway_ip = ntohl(gw_a.s_addr);
                    break;
                }
            }
        }
    }
    free(info);
}

static int is_same_subnet(uint32_t ip) {
    for (int i = 0; i < g_local_subnet_count; i++) {
        if ((ip & g_local_subnets[i].mask) == g_local_subnets[i].network) return 1;
    }
    return 0;
}

static int is_own_ip(uint32_t ip) {
    for (int i = 0; i < g_own_ip_count; i++) {
        if (g_own_ips[i] == ip) return 1;
    }
    return 0;
}

/* Windows почему-то не отвечает на NetBIOS/LLMNR/mDNS/SNMP-запросы,
   адресованные его СОБСТВЕННОМУ реальному IP (подтверждено практикой:
   тот же запрос с другого устройства сети получает нормальный ответ).
   Через loopback такой двусмысленности профиля/интерфейса нет, поэтому
   для "себя" подменяем адрес запроса на 127.0.0.1 - MAC/TTL при этом
   всё равно берём по настоящему IP, тут подмена не нужна и не поможет. */
static uint32_t query_ip_for(uint32_t ip) {
    return is_own_ip(ip) ? LOOPBACK_IP : ip;
}

/* MAC-адрес через ARP (SendARP, iphlpapi) - почти бесплатно: если запись
   уже в ARP-кеше (а после пинга/коннекта она обычно уже там), функция
   вернёт мгновенно; если нет - пошлёт один короткий ARP-запрос сама. */
static int get_mac_via_arp(uint32_t ip_h, unsigned char mac_out[6]) {
    ULONG mac_addr[2];
    ULONG mac_len = 6;
    memset(mac_addr, 0xff, sizeof(mac_addr));
    DWORD res = SendARP((IPAddr)htonl(ip_h), 0, mac_addr, &mac_len);
    if (res != NO_ERROR || mac_len < 6) return 0;
    memcpy(mac_out, mac_addr, 6);
    return 1;
}

/* Шлёт SNMP GetRequest (используем уже готовый payload для порта 161) и,
   если получен ответ, вытаскивает из него текст sysDescr. Ищем нашу же
   OID-последовательность в ответе и берём следующий за ней TLV (OCTET
   STRING) - это ровно то место, куда сервер кладёт значение. */
static int snmp_get_sysdescr(uint32_t ip_h, int timeout_ms, char *out, size_t out_cap) {
    unsigned char payload[128];
    int plen = get_udp_payload(161, payload, sizeof(payload));
    if (plen <= 0) return 0;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(161);
    addr.sin_addr.s_addr = htonl(ip_h);

    sendto(s, (const char *)payload, plen, 0, (struct sockaddr *)&addr, sizeof(addr));

    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));

    unsigned char buf[1024];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int r = recvfrom(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);
    if (r <= 0) return 0;

    /* ищем нашу OID-последовательность (sysDescr: 2B 06 01 02 01 01 01 00) */
    static const unsigned char oid[] = {0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00};
    int oid_pos = -1;
    for (int i = 0; i + (int)sizeof(oid) <= r; i++) {
        if (memcmp(buf + i, oid, sizeof(oid)) == 0) { oid_pos = i; break; }
    }
    if (oid_pos < 0) return 0;

    int p = oid_pos + (int)sizeof(oid);
    if (p + 2 > r) return 0;
    if (buf[p] != 0x04) return 0; /* ожидаем OCTET STRING */
    int val_len = buf[p + 1];
    if (val_len & 0x80) return 0; /* длинная форма длины - редкость для sysDescr, не обрабатываем */
    p += 2;
    if (p + val_len > r) return 0;
    if (val_len <= 0) return 0;

    size_t copy_len = (size_t)val_len < out_cap - 1 ? (size_t)val_len : out_cap - 1;
    memcpy(out, buf + p, copy_len);
    out[copy_len] = 0;
    /* заменяем непечатаемые байты на точки - описание может содержать что угодно */
    for (size_t i = 0; i < copy_len; i++) {
        if ((unsigned char)out[i] < 0x20 && out[i] != 0) out[i] = '.';
    }
    return 1;
}

/* NetBIOS NBSTAT (UDP 137) - один запрос "*" отдаёт таблицу NetBIOS-имён
   устройства: собственное имя (unique) и рабочую группу/домен (group). */
static int netbios_nbstat(uint32_t ip_h, int timeout_ms,
                           char *name_out, size_t name_cap,
                           char *group_out, size_t group_cap) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(137);
    addr.sin_addr.s_addr = htonl(ip_h);

    /* классический NBSTAT-запрос узла "*" (как делает nbtstat -A) */
    static const unsigned char query[] = {
        0x00,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x20,
        'C','K','C','A','C','A','C','A','C','A','C','A','C','A','C','A',
        'C','A','C','A','C','A','C','A','C','A','C','A','C','A','C','A',
        0x00,
        0x00,0x21,
        0x00,0x01
    };

    sendto(s, (const char *)query, sizeof(query), 0, (struct sockaddr *)&addr, sizeof(addr));

    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));

    unsigned char buf[1024];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int r = recvfrom(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);
    if (r < 13) return 0;

    int p = 12;
    if (buf[p] == 0xC0) {
        p += 2;
    } else {
        int namelen = buf[p];
        p += 1 + namelen;
        if (p >= r) return 0;
        p += 1;
    }
    if (p + 10 > r) return 0; /* TYPE+CLASS+TTL+RDLENGTH */
    p += 10;
    if (p >= r) return 0;

    int num_names = buf[p];
    p += 1;

    int found_unique = 0, found_group = 0;
    for (int i = 0; i < num_names && p + 18 <= r; i++) {
        char raw_name[16];
        memcpy(raw_name, buf + p, 15);
        raw_name[15] = 0;
        unsigned char name_type = buf[p + 15];
        unsigned short flags = (unsigned short)((buf[p + 16] << 8) | buf[p + 17]);
        int is_group = (flags & 0x8000) != 0;

        int end = 14;
        while (end >= 0 && raw_name[end] == ' ') end--;
        raw_name[end + 1] = 0;

        if (!is_group && !found_unique && name_type == 0x00 && raw_name[0]) {
            strncpy(name_out, raw_name, name_cap - 1);
            name_out[name_cap - 1] = 0;
            found_unique = 1;
        }
        if (is_group && !found_group && raw_name[0]) {
            strncpy(group_out, raw_name, group_cap - 1);
            group_out[group_cap - 1] = 0;
            found_group = 1;
        }
        p += 18;
    }

    return found_unique || found_group;
}

/* mDNS (UDP 5353), best-effort: спрашиваем список сервисов
   ("_services._dns-sd._udp.local" PTR). Полноценный разбор DNS-сжатия
   избыточен для наших целей - просто вытаскиваем первую достаточно длинную
   печатаемую ASCII-подстроку из ответа (обычно это и есть имя хоста или
   имя сервиса). */
static int mdns_query(uint32_t ip_h, int timeout_ms, char *out, size_t out_cap) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    /* RFC 6762 п.11: строгие mDNS-респондеры тоже проверяют TTL=255 у
       входящих пакетов по той же причине, что и LLMNR. */
    int ttl255 = 255;
    setsockopt(s, IPPROTO_IP, IP_TTL, (const char *)&ttl255, sizeof(ttl255));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353);
    addr.sin_addr.s_addr = htonl(ip_h);

    static const unsigned char q[] = {
        0x00,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x09,'_','s','e','r','v','i','c','e','s',
        0x07,'_','d','n','s','-','s','d',
        0x04,'_','u','d','p',
        0x05,'l','o','c','a','l',
        0x00,
        0x00,0x0C,
        0x00,0x01
    };

    sendto(s, (const char *)q, sizeof(q), 0, (struct sockaddr *)&addr, sizeof(addr));

    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));

    unsigned char buf[1500];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int r = recvfrom(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);
    if (r <= 12) return 0;

    /* многие респондеры эхают вопрос обратно в ответе - это неинтересная
       часть (просто наш же запрос), пропускаем её, чтобы не выхватить её
       вместо реальных данных из секции ответа */
    int scan_from = 12;
    if ((size_t)r >= sizeof(q) && memcmp(buf + 12, q + 12, sizeof(q) - 12) == 0) {
        scan_from = (int)sizeof(q);
    }

    /* берём САМУЮ ДЛИННУЮ печатаемую ASCII-подстроку - обычно это и есть
       осмысленное имя хоста/сервиса, а не короткий случайный фрагмент */
    int best_start = -1, best_len = 0;
    int start = -1;
    for (int i = scan_from; i <= r; i++) {
        int printable = (i < r) && (buf[i] >= 0x20 && buf[i] < 0x7F);
        if (printable && start < 0) start = i;
        if (!printable && start >= 0) {
            int len = i - start;
            if (len > best_len) { best_len = len; best_start = start; }
            start = -1;
        }
    }
    if (best_len < 4) return 0;

    int copy_len = best_len < (int)out_cap - 1 ? best_len : (int)out_cap - 1;
    memcpy(out, buf + best_start, (size_t)copy_len);
    out[copy_len] = 0;
    return 1;
}

/* Универсальный декодер DNS-имени с поддержкой сжатия (указателей 0xC0XX) -
   нужен для LLMNR, где respondер почти всегда ссылается на имя из вопроса
   вместо повторения его буквально. Возвращает число байт, реально занятых
   именем в исходном потоке НАЧИНАЯ С offset (переходы по указателю в этот
   счёт не входят - это то место, откуда чтение продолжается дальше). */
static int dns_read_name(const unsigned char *buf, int buflen, int offset, char *out, size_t out_cap) {
    int pos = offset;
    int jumps = 0;
    int consumed = -1;
    size_t out_len = 0;
    out[0] = 0;

    while (1) {
        if (pos < 0 || pos >= buflen) return -1;
        unsigned char len = buf[pos];
        if (len == 0) {
            pos += 1;
            if (consumed < 0) consumed = pos - offset;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= buflen) return -1;
            int ptr = ((len & 0x3F) << 8) | buf[pos + 1];
            if (consumed < 0) consumed = (pos + 2) - offset;
            if (++jumps > 20) return -1; /* защита от циклов в некорректных пакетах */
            pos = ptr;
            continue;
        }
        if (pos + 1 + len > buflen) return -1;
        if (out_len + (size_t)len + 1 >= out_cap) len = (unsigned char)(out_cap - out_len - 1);
        if (out_len > 0) out[out_len++] = '.';
        memcpy(out + out_len, buf + pos + 1, len);
        out_len += len;
        out[out_len] = 0;
        pos += 1 + len;
    }
    return consumed;
}

static int write_dns_label(unsigned char *buf, int pos, const char *text) {
    int len = (int)strlen(text);
    buf[pos++] = (unsigned char)len;
    memcpy(buf + pos, text, (size_t)len);
    return pos + len;
}

/* LLMNR (UDP 5355) - современная замена NetBIOS для имени компьютера в
   Windows. Работает даже когда "NetBIOS over TCP/IP" отключён - запрашиваем
   PTR-запись обратного адреса (d.c.b.a.in-addr.arpa), респондер отвечает
   собственным именем компьютера. */
static int llmnr_query(uint32_t dest_ip, uint32_t query_ip, int timeout_ms, char *out, size_t out_cap) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    /* RFC 4795 п.2.5: LLMNR-респондер ОБЯЗАН молча отбросить запрос, если
       IP TTL пакета не равен 255 (защита протокола от утечки за пределы
       локального линка через маршрутизаторы). Обычный сокет Windows шлёт
       с дефолтным TTL (обычно 128) - без этой установки ответа не будет
       вообще, даже если сервис в остальном включён и не заблокирован. */
    int ttl255 = 255;
    setsockopt(s, IPPROTO_IP, IP_TTL, (const char *)&ttl255, sizeof(ttl255));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5355);
    addr.sin_addr.s_addr = htonl(dest_ip);

    unsigned char q[64];
    int qlen = 0;
    q[qlen++]=0x12; q[qlen++]=0x34; /* Transaction ID */
    q[qlen++]=0x00; q[qlen++]=0x00; /* Flags: standard query, RD=0 (по RFC 4795) */
    q[qlen++]=0x00; q[qlen++]=0x01; /* QDCOUNT=1 */
    q[qlen++]=0x00; q[qlen++]=0x00;
    q[qlen++]=0x00; q[qlen++]=0x00;
    q[qlen++]=0x00; q[qlen++]=0x00;

    /* содержимое запроса всегда про РЕАЛЬНЫЙ IP (даже если пакет физически
       уходит на loopback при самоопросе) - иначе спросим "как зовут
       127.0.0.1" вместо "как зовут настоящий адрес хоста" */
    unsigned char octets[4] = {
        (unsigned char)((query_ip >> 24) & 0xFF), (unsigned char)((query_ip >> 16) & 0xFF),
        (unsigned char)((query_ip >> 8) & 0xFF),  (unsigned char)(query_ip & 0xFF)
    };
    char lbl[4];
    for (int i = 3; i >= 0; i--) {
        snprintf(lbl, sizeof(lbl), "%d", octets[i]);
        qlen = write_dns_label(q, qlen, lbl);
    }
    qlen = write_dns_label(q, qlen, "in-addr");
    qlen = write_dns_label(q, qlen, "arpa");
    q[qlen++] = 0x00;
    q[qlen++] = 0x00; q[qlen++] = 0x0C; /* QTYPE: PTR */
    q[qlen++] = 0x00; q[qlen++] = 0x01; /* QCLASS: IN */

    sendto(s, (const char *)q, qlen, 0, (struct sockaddr *)&addr, sizeof(addr));

    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));

    unsigned char buf[512];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int r = recvfrom(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);
    if (r < 12) return 0;

    /* пропускаем вопрос: имя + TYPE(2) + CLASS(2) */
    char tmp[256];
    int consumed = dns_read_name(buf, r, 12, tmp, sizeof(tmp));
    if (consumed < 0) return 0;
    int p = 12 + consumed + 4;
    if (p >= r) return 0;

    /* ответ (PTR): имя(может быть указателем) + TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) */
    consumed = dns_read_name(buf, r, p, tmp, sizeof(tmp));
    if (consumed < 0) return 0;
    p += consumed;
    if (p + 10 > r) return 0;
    p += 10;
    if (p >= r) return 0;

    /* RDATA PTR-записи - само доменное DNS-имя (имя компьютера) */
    consumed = dns_read_name(buf, r, p, out, out_cap);
    if (consumed < 0 || out[0] == 0) return 0;
    return 1;
}

/* Обратный DNS (PTR) через обычный DNS-сервер (обычно роутер или, в
   доменной сети, AD-контроллер) - многие DHCP-серверы регистрируют
   hostname клиента при выдаче аренды, так что PTR часто отдаёт настоящее
   имя компьютера даже когда NetBIOS/LLMNR по каким-то причинам молчат. */
static int reverse_dns_query(uint32_t dns_server_ip, uint32_t query_ip, int timeout_ms,
                              char *out, size_t out_cap) {
    if (dns_server_ip == 0) return 0;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(dns_server_ip);

    unsigned char q[64];
    int qlen = 0;
    q[qlen++]=0x22; q[qlen++]=0x22; /* Transaction ID */
    q[qlen++]=0x01; q[qlen++]=0x00; /* Flags: standard query, RD=1 (обычному DNS-серверу нужна рекурсия) */
    q[qlen++]=0x00; q[qlen++]=0x01; /* QDCOUNT=1 */
    q[qlen++]=0x00; q[qlen++]=0x00;
    q[qlen++]=0x00; q[qlen++]=0x00;
    q[qlen++]=0x00; q[qlen++]=0x00;

    unsigned char octets[4] = {
        (unsigned char)((query_ip >> 24) & 0xFF), (unsigned char)((query_ip >> 16) & 0xFF),
        (unsigned char)((query_ip >> 8) & 0xFF),  (unsigned char)(query_ip & 0xFF)
    };
    char lbl[4];
    for (int i = 3; i >= 0; i--) {
        snprintf(lbl, sizeof(lbl), "%d", octets[i]);
        qlen = write_dns_label(q, qlen, lbl);
    }
    qlen = write_dns_label(q, qlen, "in-addr");
    qlen = write_dns_label(q, qlen, "arpa");
    q[qlen++] = 0x00;
    q[qlen++] = 0x00; q[qlen++] = 0x0C; /* QTYPE: PTR */
    q[qlen++] = 0x00; q[qlen++] = 0x01; /* QCLASS: IN */

    sendto(s, (const char *)q, qlen, 0, (struct sockaddr *)&addr, sizeof(addr));

    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));

    unsigned char buf[512];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int r = recvfrom(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);
    if (r < 12) return 0;

    /* ANCOUNT (число реальных ответов) - байты 6-7 заголовка, big-endian.
       Если 0 - записи нет (NXDOMAIN/NOERROR-без-ответа), сервер может
       прислать SOA в Authority-секции (это НЕ ответ, а служебная запись
       о зоне) - её нельзя путать с PTR-записью. */
    int ancount = (buf[6] << 8) | buf[7];
    if (ancount < 1) return 0;

    char tmp[256];
    int consumed = dns_read_name(buf, r, 12, tmp, sizeof(tmp));
    if (consumed < 0) return 0;
    int p = 12 + consumed + 4;
    if (p >= r) return 0;

    consumed = dns_read_name(buf, r, p, tmp, sizeof(tmp));
    if (consumed < 0) return 0;
    p += consumed;
    if (p + 10 > r) return 0;

    /* TYPE (2 байта сразу после имени записи) - принимаем только настоящую
       PTR-запись (12), чтобы не принять что-то другое за имя хоста */
    uint16_t rr_type = (uint16_t)((buf[p] << 8) | buf[p + 1]);
    if (rr_type != 12) return 0;

    p += 10; /* TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) */
    if (p >= r) return 0;

    consumed = dns_read_name(buf, r, p, out, out_cap);
    if (consumed < 0 || out[0] == 0) return 0;
    return 1;
}

/* ---------------------------------------------------------------------- */
/* SMB2 NEGOTIATE + SESSION_SETUP (NTLMSSP) - самый надёжный источник     */
/* имени компьютера из всех: без аутентификации сервер обязан прислать    */
/* NTLMSSP CHALLENGE, содержащий NetBIOS-имя, NetBIOS-домен, DNS-имя и    */
/* DNS-домен компьютера. Работает одинаково в рабочей группе и в AD-      */
/* домене (ровно так это делают nmap/enum4linux/CrackMapExec).            */
/* ---------------------------------------------------------------------- */

static SOCKET tcp_connect_timeout(uint32_t ip_h, uint16_t port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip_h);

    int r = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (r == 0) {
        mode = 0; ioctlsocket(s, FIONBIO, &mode);
        return s;
    }
    if (WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); return INVALID_SOCKET; }

    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(s, &wfds); FD_SET(s, &efds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(0, NULL, &wfds, &efds, &tv);
    if (sel <= 0 || FD_ISSET(s, &efds) || !FD_ISSET(s, &wfds)) { closesocket(s); return INVALID_SOCKET; }

    int soerr = 0; int slen = sizeof(soerr);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &slen) != 0 || soerr != 0) {
        closesocket(s); return INVALID_SOCKET;
    }
    mode = 0; ioctlsocket(s, FIONBIO, &mode); /* обратно в блокирующий режим для send/recv */
    return s;
}

static int recv_exact(SOCKET s, unsigned char *buf, int len, int timeout_ms) {
    int got = 0;
    while (got < len) {
        DWORD to = (DWORD)timeout_ms;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));
        int r = recv(s, (char *)buf + got, len - got, 0);
        if (r <= 0) return 0;
        got += r;
    }
    return 1;
}

static void build_smb2_header(unsigned char *buf, uint16_t command, uint64_t message_id) {
    memset(buf, 0, 64);
    buf[0] = 0xFE; buf[1] = 'S'; buf[2] = 'M'; buf[3] = 'B'; /* ProtocolId */
    buf[4] = 64; buf[5] = 0;                                 /* StructureSize=64 */
    buf[12] = (unsigned char)(command & 0xFF);
    buf[13] = (unsigned char)((command >> 8) & 0xFF);        /* Command */
    buf[14] = 1; buf[15] = 0;                                /* CreditRequest=1 */
    for (int i = 0; i < 8; i++) buf[24 + i] = (unsigned char)((message_id >> (8 * i)) & 0xFF); /* MessageId */
    /* Reserved/TreeId/SessionId/Signature - остаются нулями */
}

static int build_negotiate_body(unsigned char *buf) {
    int p = 0;
    buf[p++] = 36; buf[p++] = 0;  /* StructureSize=36 */
    buf[p++] = 1;  buf[p++] = 0;  /* DialectCount=1 */
    buf[p++] = 1;  buf[p++] = 0;  /* SecurityMode = SIGNING_ENABLED */
    buf[p++] = 0;  buf[p++] = 0;  /* Reserved */
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; /* Capabilities=0 */
    for (int i = 0; i < 16; i++) buf[p++] = 0; /* ClientGuid=0 */
    for (int i = 0; i < 8; i++)  buf[p++] = 0; /* ClientStartTime=0 (pre-3.1.1 формат) */
    buf[p++] = 0x02; buf[p++] = 0x02; /* Dialect: SMB 2.0.2 - максимально совместимый выбор */
    return p; /* 38 байт */
}

static int build_ntlmssp_negotiate(unsigned char *buf) {
    int p = 0;
    memcpy(buf + p, "NTLMSSP", 7); buf[p+7]=0; p += 8; /* Signature */
    buf[p++]=1; buf[p++]=0; buf[p++]=0; buf[p++]=0;    /* MessageType=1 */
    uint32_t flags = 0x00088205; /* UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|EXTENDED_SECURITY */
    buf[p++]=(unsigned char)(flags&0xFF); buf[p++]=(unsigned char)((flags>>8)&0xFF);
    buf[p++]=(unsigned char)((flags>>16)&0xFF); buf[p++]=(unsigned char)((flags>>24)&0xFF);
    for (int i = 0; i < 8; i++) buf[p++] = 0; /* DomainName Len/MaxLen/Offset */
    for (int i = 0; i < 8; i++) buf[p++] = 0; /* Workstation Len/MaxLen/Offset */
    return p; /* 32 байта */
}

static int build_session_setup_body(unsigned char *buf, const unsigned char *ntlmssp, int ntlmssp_len) {
    int p = 0;
    buf[p++] = 25; buf[p++] = 0;              /* StructureSize=25 */
    buf[p++] = 0;                              /* Flags */
    buf[p++] = 1;                              /* SecurityMode = SIGNING_ENABLED */
    buf[p++]=0; buf[p++]=0; buf[p++]=0; buf[p++]=0; /* Capabilities */
    buf[p++]=0; buf[p++]=0; buf[p++]=0; buf[p++]=0; /* Channel */
    int sec_offset = 64 + 24; /* SMB2-заголовок(64) + фиксированная часть тела до буфера(24) */
    buf[p++]=(unsigned char)(sec_offset & 0xFF); buf[p++]=(unsigned char)((sec_offset >> 8) & 0xFF);
    buf[p++]=(unsigned char)(ntlmssp_len & 0xFF); buf[p++]=(unsigned char)((ntlmssp_len >> 8) & 0xFF);
    for (int i = 0; i < 8; i++) buf[p++] = 0; /* PreviousSessionId */
    memcpy(buf + p, ntlmssp, (size_t)ntlmssp_len);
    p += ntlmssp_len;
    return p;
}

static int smb_get_names(uint32_t ip_h, int timeout_ms,
                          char *nb_name, size_t nb_cap,
                          char *nb_domain, size_t nbd_cap,
                          char *dns_name, size_t dns_cap,
                          char *dns_domain, size_t dnsd_cap) {
    SOCKET s = tcp_connect_timeout(ip_h, 445, timeout_ms);
    if (s == INVALID_SOCKET) return 0;

    /* --- NEGOTIATE --- */
    unsigned char hdr[64], body[64];
    build_smb2_header(hdr, 0x0000, 0);
    int body_len = build_negotiate_body(body);

    unsigned char nbss[4];
    uint32_t total_len = 64 + (uint32_t)body_len;
    nbss[0]=0; nbss[1]=(unsigned char)((total_len>>16)&0xFF);
    nbss[2]=(unsigned char)((total_len>>8)&0xFF); nbss[3]=(unsigned char)(total_len&0xFF);

    if (send(s,(char*)nbss,4,0)<0 || send(s,(char*)hdr,64,0)<0 || send(s,(char*)body,body_len,0)<0) {
        closesocket(s); return 0;
    }

    unsigned char resp_nbss[4];
    if (!recv_exact(s, resp_nbss, 4, timeout_ms)) { closesocket(s); return 0; }
    uint32_t resp_len = ((uint32_t)resp_nbss[1]<<16)|((uint32_t)resp_nbss[2]<<8)|resp_nbss[3];
    if (resp_len == 0 || resp_len > 8192) { closesocket(s); return 0; }
    unsigned char *resp = malloc(resp_len);
    if (!resp || !recv_exact(s, resp, resp_len, timeout_ms)) { free(resp); closesocket(s); return 0; }
    free(resp); /* NEGOTIATE-ответ детально не разбираем - раз дошли сюда, сервер SMB2-совместим */

    /* --- SESSION_SETUP с NTLMSSP NEGOTIATE --- */
    unsigned char ntlmssp[32];
    int ntlmssp_len = build_ntlmssp_negotiate(ntlmssp);
    unsigned char ss_body[24+32];
    int ss_body_len = build_session_setup_body(ss_body, ntlmssp, ntlmssp_len);

    build_smb2_header(hdr, 0x0001, 1);
    total_len = 64 + (uint32_t)ss_body_len;
    nbss[0]=0; nbss[1]=(unsigned char)((total_len>>16)&0xFF);
    nbss[2]=(unsigned char)((total_len>>8)&0xFF); nbss[3]=(unsigned char)(total_len&0xFF);

    if (send(s,(char*)nbss,4,0)<0 || send(s,(char*)hdr,64,0)<0 || send(s,(char*)ss_body,ss_body_len,0)<0) {
        closesocket(s); return 0;
    }

    if (!recv_exact(s, resp_nbss, 4, timeout_ms)) { closesocket(s); return 0; }
    resp_len = ((uint32_t)resp_nbss[1]<<16)|((uint32_t)resp_nbss[2]<<8)|resp_nbss[3];
    if (resp_len == 0 || resp_len > 8192) { closesocket(s); return 0; }
    resp = malloc(resp_len);
    if (!resp || !recv_exact(s, resp, resp_len, timeout_ms)) { free(resp); closesocket(s); return 0; }
    closesocket(s);

    if (resp_len < 64 + 8) { free(resp); return 0; }
    unsigned char *body_ptr = resp + 64;
    uint16_t sec_offset = (uint16_t)(body_ptr[4] | (body_ptr[5] << 8));
    uint16_t sec_len = (uint16_t)(body_ptr[6] | (body_ptr[7] << 8));
    if (sec_offset == 0 || sec_len == 0 || (uint32_t)sec_offset + sec_len > resp_len) { free(resp); return 0; }

    unsigned char *chal = resp + sec_offset;
    if (sec_len < 48 || memcmp(chal, "NTLMSSP", 7) != 0 || chal[7] != 0) { free(resp); return 0; }
    uint32_t msg_type = (uint32_t)chal[8] | ((uint32_t)chal[9]<<8) | ((uint32_t)chal[10]<<16) | ((uint32_t)chal[11]<<24);
    if (msg_type != 2) { free(resp); return 0; }

    uint16_t ti_len = (uint16_t)(chal[40] | (chal[41] << 8));
    uint32_t ti_offset = (uint32_t)chal[44] | ((uint32_t)chal[45]<<8) | ((uint32_t)chal[46]<<16) | ((uint32_t)chal[47]<<24);

    int found_any = 0;
    if (ti_len > 0 && ti_offset + (uint32_t)ti_len <= sec_len) {
        unsigned char *av = chal + ti_offset;
        uint32_t off = 0;
        while (off + 4 <= (uint32_t)ti_len) {
            uint16_t av_id = (uint16_t)(av[off] | (av[off+1] << 8));
            uint16_t av_len = (uint16_t)(av[off+2] | (av[off+3] << 8));
            off += 4;
            if (off + av_len > (uint32_t)ti_len) break;
            if (av_id == 0) break; /* MsvAvEOL */

            char *dst = NULL; size_t dst_cap = 0;
            if (av_id == 1) { dst = nb_name; dst_cap = nb_cap; }
            else if (av_id == 2) { dst = nb_domain; dst_cap = nbd_cap; }
            else if (av_id == 3) { dst = dns_name; dst_cap = dns_cap; }
            else if (av_id == 4) { dst = dns_domain; dst_cap = dnsd_cap; }

            if (dst && dst_cap > 0) {
                /* UTF-16LE -> обычная строка (имена компьютеров - ASCII, младшего байта достаточно) */
                size_t out_i = 0;
                for (int i = 0; (uint32_t)i + 1 < av_len && out_i < dst_cap - 1; i += 2) {
                    dst[out_i++] = (char)av[off + i];
                }
                dst[out_i] = 0;
                if (out_i > 0) found_any = 1;
            }
            off += av_len;
        }
    }

    free(resp);
    return found_any;
}

/* Собирает всю доступную информацию по ОДНОМУ хосту. Делает до 4 сетевых
   обращений (ICMP если TTL ещё не известен, SNMP, NetBIOS, mDNS) - но
   ОДИН РАЗ НА ХОСТ, не на порт, поэтому не влияет на скорость самого
   скана портов. */
/* ---------------------------------------------------------------------- */
/* WMI через DCOM. В отличие от всей диагностики выше (--info/           */
/* --deep-resolve), это НЕ анонимные протокольные запросы - нужны права   */
/* на целевой машине (SSO текущим пользователем, либо явные логин/пароль).*/
/* ---------------------------------------------------------------------- */

static void ascii_to_wide(const char *s, wchar_t *out, size_t cap) {
    size_t i = 0;
    for (; s[i] && i + 1 < cap; i++) out[i] = (wchar_t)(unsigned char)s[i];
    out[i] = 0;
}

static void bstr_to_narrow(BSTR b, char *out, size_t cap) {
    if (!b) { out[0] = 0; return; }
    int n = WideCharToMultiByte(CP_UTF8, 0, b, -1, out, (int)cap, NULL, NULL);
    if (n <= 0) out[0] = 0;
}

/* WMI хранит дату в формате DMTF: "20260722143500.000000+180" */
static void format_wmi_datetime(const char *dmtf, char *out, size_t cap) {
    out[0] = 0;
    if (!dmtf || strlen(dmtf) < 14) return;
    char year[5], mon[3], day[3], hh[3], mm[3], ss[3];
    memcpy(year, dmtf, 4);     year[4] = 0;
    memcpy(mon,  dmtf + 4, 2); mon[2]  = 0;
    memcpy(day,  dmtf + 6, 2); day[2]  = 0;
    memcpy(hh,   dmtf + 8, 2); hh[2]   = 0;
    memcpy(mm,   dmtf + 10, 2); mm[2]  = 0;
    memcpy(ss,   dmtf + 12, 2); ss[2]  = 0;
    snprintf(out, cap, "%s.%s.%s %s:%s:%s", day, mon, year, hh, mm, ss);
}

static void wmi_get_string_prop(IWbemClassObject *obj, const wchar_t *name, char *out, size_t cap) {
    out[0] = 0;
    VARIANT vt;
    VariantInit(&vt);
    if (SUCCEEDED(IWbemClassObject_Get(obj, name, 0, &vt, 0, 0)) && vt.vt == VT_BSTR) {
        bstr_to_narrow(vt.bstrVal, out, cap);
    }
    VariantClear(&vt);
}

static int wmi_get_int_prop(IWbemClassObject *obj, const wchar_t *name, int *out) {
    VARIANT vt;
    VariantInit(&vt);
    int ok = 0;
    if (SUCCEEDED(IWbemClassObject_Get(obj, name, 0, &vt, 0, 0))) {
        if (vt.vt == VT_I4) { *out = vt.lVal; ok = 1; }
        else if (vt.vt == VT_UI4) { *out = (int)vt.ulVal; ok = 1; }
        else if (vt.vt == VT_I2) { *out = vt.iVal; ok = 1; }
    }
    VariantClear(&vt);
    return ok;
}

/* TotalPhysicalMemory приходит строкой (может не влезать в 32 бита) */
static int wmi_get_uint64_str_prop(IWbemClassObject *obj, const wchar_t *name, double *out_gb) {
    VARIANT vt;
    VariantInit(&vt);
    int ok = 0;
    if (SUCCEEDED(IWbemClassObject_Get(obj, name, 0, &vt, 0, 0))) {
        char buf[32] = "";
        if (vt.vt == VT_BSTR) bstr_to_narrow(vt.bstrVal, buf, sizeof(buf));
        else if (vt.vt == VT_UI8) snprintf(buf, sizeof(buf), "%llu", (unsigned long long)vt.ullVal);
        if (buf[0]) {
            double bytes = atof(buf);
            *out_gb = bytes / (1024.0 * 1024.0 * 1024.0);
            ok = 1;
        }
    }
    VariantClear(&vt);
    return ok;
}

/* Одна WQL-выборка, разбор первой строки результата через callback */
typedef void (*WmiRowFn)(IWbemClassObject *obj, HostInfo *hi);

static int wmi_run_query(IWbemServices *svc, const wchar_t *wql, WmiRowFn fn, HostInfo *hi) {
    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(wql);
    IEnumWbemClassObject *pEnum = NULL;
    HRESULT hr = IWbemServices_ExecQuery(svc, lang, query,
                                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                          NULL, &pEnum);
    SysFreeString(lang);
    SysFreeString(query);
    if (FAILED(hr) || !pEnum) return 0;

    IWbemClassObject *obj = NULL;
    ULONG got = 0;
    int ok = 0;
    if (IEnumWbemClassObject_Next(pEnum, 5000, 1, &obj, &got) == S_OK && got) {
        fn(obj, hi);
        IWbemClassObject_Release(obj);
        ok = 1;
    }
    IEnumWbemClassObject_Release(pEnum);
    return ok;
}

static void wmi_row_os(IWbemClassObject *obj, HostInfo *hi) {
    wmi_get_string_prop(obj, L"Caption", hi->wmi_os_caption, sizeof(hi->wmi_os_caption));
    wmi_get_string_prop(obj, L"Version", hi->wmi_os_version, sizeof(hi->wmi_os_version));
    wmi_get_string_prop(obj, L"BuildNumber", hi->wmi_os_build, sizeof(hi->wmi_os_build));

    char raw_boot[64];
    wmi_get_string_prop(obj, L"LastBootUpTime", raw_boot, sizeof(raw_boot));
    format_wmi_datetime(raw_boot, hi->wmi_boot_time, sizeof(hi->wmi_boot_time));
}

static void wmi_row_computer_system(IWbemClassObject *obj, HostInfo *hi) {
    wmi_get_int_prop(obj, L"NumberOfLogicalProcessors", &hi->wmi_cpu_cores);
    wmi_get_uint64_str_prop(obj, L"TotalPhysicalMemory", &hi->wmi_ram_gb);
    /* UserName - "DOMAIN\\user", текущий залогиненный интерактивно пользователь;
       пусто, если на машине никто не залогинен */
    wmi_get_string_prop(obj, L"UserName", hi->wmi_logged_user, sizeof(hi->wmi_logged_user));
}

static void wmi_row_gpu(IWbemClassObject *obj, HostInfo *hi) {
    wmi_get_string_prop(obj, L"Name", hi->wmi_gpu, sizeof(hi->wmi_gpu));
}

/* Win32_LogonSession не хранит логин (это отдельный класс Win32_LoggedOnUser,
   связанный через ассоциацию) - для нашей цели "когда залогинился текущий
   интерактивный пользователь" достаточно взять StartTime самой свежей
   интерактивной сессии (LogonType=2), без полного join. На рабочей станции
   обычно ровно одна такая сессия. */
static void wmi_row_logon_session(IWbemClassObject *obj, HostInfo *hi) {
    char raw[64];
    wmi_get_string_prop(obj, L"StartTime", raw, sizeof(raw));
    format_wmi_datetime(raw, hi->wmi_logon_time, sizeof(hi->wmi_logon_time));
}

/* Основная точка входа: подключается к \\ip\root\cimv2 через DCOM и
   собирает ОС/железо/пользователя. При явных --wmi-user/--wmi-password
   аутентифицируется под ними, иначе - под текущим пользователем (SSO). */
static int wmi_query_host(uint32_t ip_h, HostInfo *hi) {
    if (!g_wmi_com_ready) {
        snprintf(hi->wmi_error, sizeof(hi->wmi_error), "COM не инициализирован");
        return 0;
    }

    /* Быстрая предпроверка порта 135 (DCOM endpoint mapper) нашим же
       TCP-коннектом с коротким таймаутом. ConnectServer сам по себе не
       даёт настроить таймаут - использует RPC-таймаут ОС по умолчанию,
       который на недоступном/зафильтрованном хосте может занимать
       20+ секунд. Без этой проверки --wmi по диапазону, где DCOM не
       открыт у большинства хостов, был бы практически неюзабельным. */
    if (!tcp_check(ip_h, 135, 700)) {
        snprintf(hi->wmi_error, sizeof(hi->wmi_error), "порт 135 (DCOM) недоступен");
        return 0;
    }

    char ipstr[64];
    u32_to_ip_str(ip_h, ipstr, sizeof(ipstr));
    wchar_t wip[64];
    ascii_to_wide(ipstr, wip, sizeof(wip) / sizeof(wchar_t));

    wchar_t wpath[160];
    wcscpy(wpath, L"\\\\");
    wcscat(wpath, wip);
    wcscat(wpath, L"\\root\\cimv2");

    IWbemLocator *pLoc = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                   &IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hr) || !pLoc) {
        snprintf(hi->wmi_error, sizeof(hi->wmi_error), "CoCreateInstance: 0x%08lX", (unsigned long)hr);
        return 0;
    }

    BSTR bpath = SysAllocString(wpath);
    BSTR buser = NULL, bpass = NULL;
    if (g_wmi_user[0]) {
        wchar_t wuser[256] = L"";
        if (g_wmi_domain[0]) {
            wchar_t wd[128], wu[128];
            ascii_to_wide(g_wmi_domain, wd, 128);
            ascii_to_wide(g_wmi_user, wu, 128);
            wcscpy(wuser, wd); wcscat(wuser, L"\\"); wcscat(wuser, wu);
        } else {
            ascii_to_wide(g_wmi_user, wuser, 256);
        }
        buser = SysAllocString(wuser);
        wchar_t wpass[256];
        ascii_to_wide(g_wmi_password, wpass, 256);
        bpass = SysAllocString(wpass);
    }

    IWbemServices *pSvc = NULL;
    hr = IWbemLocator_ConnectServer(pLoc, bpath, buser, bpass, NULL, 0, NULL, NULL, &pSvc);

    if (buser) SysFreeString(buser);
    if (bpass) SysFreeString(bpass);
    SysFreeString(bpath);

    if (FAILED(hr) || !pSvc) {
        snprintf(hi->wmi_error, sizeof(hi->wmi_error), "ConnectServer: 0x%08lX "
                 "(нет доступа/файрвол/DCOM выключен на цели)", (unsigned long)hr);
        IWbemLocator_Release(pLoc);
        return 0;
    }

    hr = CoSetProxyBlanket((IUnknown *)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        snprintf(hi->wmi_error, sizeof(hi->wmi_error), "CoSetProxyBlanket: 0x%08lX", (unsigned long)hr);
        IWbemServices_Release(pSvc);
        IWbemLocator_Release(pLoc);
        return 0;
    }

    int got_os = wmi_run_query(pSvc, L"SELECT Caption,Version,BuildNumber,LastBootUpTime "
                                      L"FROM Win32_OperatingSystem", wmi_row_os, hi);
    int got_cs = wmi_run_query(pSvc, L"SELECT NumberOfLogicalProcessors,TotalPhysicalMemory,UserName "
                                      L"FROM Win32_ComputerSystem", wmi_row_computer_system, hi);
    /* WQL не поддерживает ORDER BY - берём первую попавшуюся интерактивную
       (LogonType=2) сессию. На обычной рабочей станции с одним залогиненным
       пользователем это и есть искомое время логона; при нескольких
       интерактивных сессиях (RDP и т.п.) результат может относиться к
       любой из них - это приближение, а не гарантированно "самая свежая". */
    wmi_run_query(pSvc, L"SELECT StartTime FROM Win32_LogonSession WHERE LogonType=2",
                  wmi_row_logon_session, hi);
    if (g_wmi_gpu) {
        wmi_run_query(pSvc, L"SELECT Name FROM Win32_VideoController", wmi_row_gpu, hi);
    }

    IWbemServices_Release(pSvc);
    IWbemLocator_Release(pLoc);

    if (!got_os && !got_cs) {
        snprintf(hi->wmi_error, sizeof(hi->wmi_error), "Подключились, но запросы не вернули данных "
                 "(прав недостаточно?)");
        return 0;
    }
    hi->has_wmi = 1;
    return 1;
}

/* ---------------------------------------------------------------------- */
/* WTS (Terminal Services API) - то, на чём построены сами quser/qwinsta. */
/* WTSQuerySessionInformation с классом WTSSessionInfo отдаёт разом        */
/* LogonTime, LastInputTime (=бездействие), ConnectTime, DisconnectTime,   */
/* имя и домен пользователя - причём удалённо, как quser /server:host.    */
/* ---------------------------------------------------------------------- */

/* LARGE_INTEGER здесь - это FILETIME (100-нс интервалы с 1601 года),
   просто представленный как 64-битное целое, а не структура FILETIME. */
static void filetime_large_to_str(LARGE_INTEGER li, char *out, size_t cap) {
    out[0] = 0;
    if (li.QuadPart == 0) return; /* поле не заполнено (нет значения) */

    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = (DWORD)li.HighPart;

    FILETIME local_ft;
    SYSTEMTIME st;
    if (FileTimeToLocalFileTime(&ft, &local_ft) && FileTimeToSystemTime(&local_ft, &st)) {
        snprintf(out, cap, "%02d.%02d.%04d %02d:%02d:%02d",
                 st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
    }
}

/* Разница между LastInputTime и CurrentTime в минутах - то самое "IDLE
   TIME" из quser, просто в явном числовом виде вместо "5+03:12" формата. */
static double filetime_idle_minutes(LARGE_INTEGER current, LARGE_INTEGER last_input) {
    if (last_input.QuadPart == 0 || current.QuadPart <= last_input.QuadPart) return -1.0;
    ULONGLONG diff_100ns = (ULONGLONG)(current.QuadPart - last_input.QuadPart);
    return (double)diff_100ns / (10000000.0 * 60.0);
}

static int wts_query_host(uint32_t ip_h, HostInfo *hi) {
    char ipstr[64];
    u32_to_ip_str(ip_h, ipstr, sizeof(ipstr));
    wchar_t wip[64];
    ascii_to_wide(ipstr, wip, sizeof(wip) / sizeof(wchar_t));

    /* та же быстрая предпроверка порта 135, что и для --wmi: WTSOpenServer
       сам по себе не даёт настроить таймаут и опирается на тот же RPC-
       транспорт, что и DCOM - на недоступном хосте может тянуться долго. */
    if (!tcp_check(ip_h, 135, 700)) {
        snprintf(hi->wts_error, sizeof(hi->wts_error), "порт 135 (RPC) недоступен");
        return 0;
    }

    HANDLE hImpToken = NULL;
    int impersonating = 0;
    if (g_wmi_user[0]) {
        wchar_t wuser[128], wdomain[128], wpass[128];
        ascii_to_wide(g_wmi_user, wuser, 128);
        ascii_to_wide(g_wmi_password, wpass, 128);
        wcscpy(wdomain, g_wmi_domain[0] ? L"" : L".");
        if (g_wmi_domain[0]) ascii_to_wide(g_wmi_domain, wdomain, 128);

        /* LOGON32_LOGON_NEW_CREDENTIALS = "как runas /netonly" - учётные
           данные подставляются только для исходящих сетевых обращений,
           без локальной проверки пароля (его и нельзя проверить локально
           для доменной учётки без связи с контроллером домена). Ровно то,
           что нужно для сканера, обращающегося к чужим машинам. */
        if (!LogonUserW(wuser, wdomain, wpass, LOGON32_LOGON_NEW_CREDENTIALS,
                         LOGON32_PROVIDER_WINNT50, &hImpToken)) {
            snprintf(hi->wts_error, sizeof(hi->wts_error), "LogonUser: 0x%08lX", GetLastError());
            return 0;
        }
        if (!ImpersonateLoggedOnUser(hImpToken)) {
            snprintf(hi->wts_error, sizeof(hi->wts_error), "ImpersonateLoggedOnUser: 0x%08lX", GetLastError());
            CloseHandle(hImpToken);
            return 0;
        }
        impersonating = 1;
    }

    int found = 0;
    HANDLE hServer = WTSOpenServerW(wip);
    if (hServer) {
        PWTS_SESSION_INFOW pSessions = NULL;
        DWORD count = 0;
        if (WTSEnumerateSessionsW(hServer, 0, 1, &pSessions, &count)) {
            for (DWORD i = 0; i < count && !found; i++) {
                if (pSessions[i].State != WTSActive) continue; /* нас интересует активная сессия */

                LPWSTR buf = NULL;
                DWORD bytes = 0;
                if (WTSQuerySessionInformationW(hServer, pSessions[i].SessionId, WTSSessionInfo,
                                                 &buf, &bytes) && buf && bytes >= sizeof(WTSINFOW)) {
                    WTSINFOW *info = (WTSINFOW *)buf;
                    hi->wts_username[0] = 0;
                    WideCharToMultiByte(CP_UTF8, 0, info->UserName, -1,
                                         hi->wts_username, (int)sizeof(hi->wts_username), NULL, NULL);
                    WideCharToMultiByte(CP_UTF8, 0, info->Domain, -1,
                                         hi->wts_domain, (int)sizeof(hi->wts_domain), NULL, NULL);
                    filetime_large_to_str(info->LogonTime, hi->wts_logon_time, sizeof(hi->wts_logon_time));
                    filetime_large_to_str(info->ConnectTime, hi->wts_connect_time, sizeof(hi->wts_connect_time));
                    hi->wts_idle_minutes = filetime_idle_minutes(info->CurrentTime, info->LastInputTime);
                    found = 1;
                    WTSFreeMemory(buf);
                }
            }
            WTSFreeMemory(pSessions);
        } else {
            snprintf(hi->wts_error, sizeof(hi->wts_error), "WTSEnumerateSessions: 0x%08lX", GetLastError());
        }
        WTSCloseServer(hServer);
    } else {
        snprintf(hi->wts_error, sizeof(hi->wts_error), "WTSOpenServer: 0x%08lX", GetLastError());
    }

    if (impersonating) {
        RevertToSelf();
        CloseHandle(hImpToken);
    }

    if (found) hi->has_wts = 1;
    else if (hi->wts_error[0] == 0) {
        snprintf(hi->wts_error, sizeof(hi->wts_error), "нет активных интерактивных сессий");
    }
    return found;
}

static void gather_host_info(HostInfo *hi) {
    if (!hi->has_ttl) {
        int ttl;
        if (icmp_check_ex(hi->ip, 800, &ttl)) { hi->has_ttl = 1; hi->ttl = ttl; }
    }
    if (hi->has_ttl) hi->os_guess = guess_os_by_ttl(hi->ttl);

    if (is_same_subnet(hi->ip) && get_mac_via_arp(hi->ip, hi->mac)) {
        hi->has_mac = 1;
        hi->vendor = lookup_vendor(hi->mac);
    }

    /* NetBIOS/SNMP/mDNS/LLMNR на СВОЙ собственный реальный IP по какой-то
       причине не отвечают на Windows (подтверждено практикой: тот же
       запрос с другого устройства сети получает нормальный ответ), поэтому
       для "себя" уходим на 127.0.0.1 - там такой проблемы нет */
    uint32_t qip = query_ip_for(hi->ip);

    if (snmp_get_sysdescr(qip, 800, hi->snmp_descr, sizeof(hi->snmp_descr))) {
        hi->has_snmp = 1;
    }

    if (netbios_nbstat(qip, 800, hi->netbios_name, sizeof(hi->netbios_name),
                        hi->netbios_group, sizeof(hi->netbios_group))) {
        hi->has_netbios = 1;
    }

    if (mdns_query(qip, 800, hi->mdns_name, sizeof(hi->mdns_name))) {
        hi->has_mdns = 1;
    }

    if (llmnr_query(qip, hi->ip, 800, hi->llmnr_name, sizeof(hi->llmnr_name))) {
        hi->has_llmnr = 1;
    }

    if (g_deep_resolve) {
        uint32_t dns_srv = g_dns_server_override ? g_dns_server_override : g_gateway_ip;
        if (reverse_dns_query(dns_srv, hi->ip, 1000, hi->ptr_name, sizeof(hi->ptr_name))) {
            hi->has_ptr = 1;
        }

        if (smb_get_names(hi->ip, 1200, hi->smb_nb_name, sizeof(hi->smb_nb_name),
                           hi->smb_nb_domain, sizeof(hi->smb_nb_domain),
                           hi->smb_dns_name, sizeof(hi->smb_dns_name),
                           hi->smb_dns_domain, sizeof(hi->smb_dns_domain))) {
            hi->has_smb = 1;
        }
    }

    if (g_wmi_mode) {
        wmi_query_host(hi->ip, hi);
    }

    if (g_wts_mode) {
        hi->wts_idle_minutes = -1.0;
        wts_query_host(hi->ip, hi);
    }

    hi->device_guess = guess_device_by_ports(hi->ip);
}

static volatile LONG64 g_info_claim = 0;

static void wait_for_all_threads(HANDLE *handles, int count); /* определена ниже */

static DWORD WINAPI worker_info(LPVOID param) {
    (void)param;
    if (g_wmi_mode) CoInitializeEx(NULL, COINIT_MULTITHREADED);

    for (;;) {
        LONG64 idx = InterlockedIncrement64((volatile LONG64 *)&g_info_claim) - 1;
        if (idx >= g_host_info_count) break;
        gather_host_info(&g_host_infos[idx]);
    }

    if (g_wmi_mode) CoUninitialize();
    return 0;
}

/* Строит список "интересных" хостов и параллельно собирает по ним
   доп. информацию. Если использовался --discover - берём уже
   опрошенные ICMP-разведкой хосты (TTL уже известен, бесплатно).
   Иначе - только хосты, на которых реально нашёлся открытый порт
   (не гоняем доп.протоколы по всему диапазону впустую). */
static void run_info_gathering(void) {
    if (g_discover_mode) {
        g_host_info_count = g_alive_count;
        g_host_infos = calloc((size_t)g_host_info_count, sizeof(HostInfo));
        for (int i = 0; i < g_alive_count; i++) {
            g_host_infos[i].ip = g_alive_ips[i];
            if (g_alive_ttl[i] >= 0) {
                g_host_infos[i].has_ttl = 1;
                g_host_infos[i].ttl = g_alive_ttl[i];
            }
        }
    } else {
        /* собираем уникальные IP из уже найденных TCP/UDP хитов */
        int cap = 64;
        uint32_t *unique_ips = malloc(sizeof(uint32_t) * cap);
        int count = 0;
        for (int src = 0; src < 2; src++) {
            Hit *arr = src ? g_udp_hits : g_tcp_hits;
            int n = src ? g_udp_hit_count : g_tcp_hit_count;
            for (int i = 0; i < n; i++) {
                int found = 0;
                for (int j = 0; j < count; j++) if (unique_ips[j] == arr[i].ip) { found = 1; break; }
                if (!found) {
                    if (count == cap) { cap *= 2; unique_ips = realloc(unique_ips, sizeof(uint32_t) * cap); }
                    unique_ips[count++] = arr[i].ip;
                }
            }
        }
        g_host_info_count = count;
        g_host_infos = calloc((size_t)count, sizeof(HostInfo));
        for (int i = 0; i < count; i++) g_host_infos[i].ip = unique_ips[i];
        free(unique_ips);
    }

    if (g_host_info_count == 0) return;

    conprintf("Собираю доп. информацию об устройствах (%d)...\n", g_host_info_count);

    g_info_claim = 0;
    int threads_to_spawn = g_thread_count;
    if (threads_to_spawn > g_host_info_count) threads_to_spawn = g_host_info_count;
    if (threads_to_spawn < 1) threads_to_spawn = 1;
    if (threads_to_spawn > 128) threads_to_spawn = 128;

    HANDLE *handles = malloc(sizeof(HANDLE) * threads_to_spawn);
    for (int i = 0; i < threads_to_spawn; i++) {
        handles[i] = CreateThread(NULL, 0, worker_info, NULL, 0, NULL);
    }
    wait_for_all_threads(handles, threads_to_spawn);
    free(handles);
}

static int host_info_cmp(const void *a, const void *b) {
    const HostInfo *ha = (const HostInfo *)a, *hb = (const HostInfo *)b;
    if (ha->ip != hb->ip) return (ha->ip < hb->ip) ? -1 : 1;
    return 0;
}

/* --sort-os: группирует по строке-эвристике ОС (TTL-догадка), внутри
   группы - по IP. Хосты без определённой ОС уходят в конец. */
static int host_info_cmp_by_os(const void *a, const void *b) {
    const HostInfo *ha = (const HostInfo *)a, *hb = (const HostInfo *)b;
    const char *oa = ha->os_guess ? ha->os_guess : "\xFF";
    const char *ob = hb->os_guess ? hb->os_guess : "\xFF";
    int c = strcmp(oa, ob);
    if (c != 0) return c;
    if (ha->ip != hb->ip) return (ha->ip < hb->ip) ? -1 : 1;
    return 0;
}

static void print_host_info_section(FILE *f) {
    if (g_host_info_count == 0) return;
    qsort(g_host_infos, (size_t)g_host_info_count, sizeof(HostInfo),
          g_sort_os ? host_info_cmp_by_os : host_info_cmp);

    conprintf("\nИнформация об устройствах:\n");
    if (f) fprintf(f, "\nИнформация об устройствах:\n");

    for (int i = 0; i < g_host_info_count; i++) {
        HostInfo *hi = &g_host_infos[i];
        char ipbuf[64];
        u32_to_ip_str(hi->ip, ipbuf, sizeof(ipbuf));

        if (i > 0) {
            conprintf("\n******************************************************************\n");
            if (f) fprintf(f, "\n******************************************************************\n");
        }

        conprintf("%s\n", ipbuf);
        if (f) fprintf(f, "%s\n", ipbuf);

        if (hi->has_mac) {
            if (hi->vendor) {
                conprintf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X (%s)\n",
                          hi->mac[0],hi->mac[1],hi->mac[2],hi->mac[3],hi->mac[4],hi->mac[5], hi->vendor);
                if (f) fprintf(f, "  MAC: %02X:%02X:%02X:%02X:%02X:%02X (%s)\n",
                               hi->mac[0],hi->mac[1],hi->mac[2],hi->mac[3],hi->mac[4],hi->mac[5], hi->vendor);
            } else {
                conprintf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                          hi->mac[0],hi->mac[1],hi->mac[2],hi->mac[3],hi->mac[4],hi->mac[5]);
                if (f) fprintf(f, "  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                               hi->mac[0],hi->mac[1],hi->mac[2],hi->mac[3],hi->mac[4],hi->mac[5]);
            }
        }
        if (hi->has_ttl && hi->os_guess) {
            conprintf("  TTL: %d -> %s\n", hi->ttl, hi->os_guess);
            if (f) fprintf(f, "  TTL: %d -> %s\n", hi->ttl, hi->os_guess);
        }
        if (hi->device_guess) {
            conprintf("  Тип (по портам): %s\n", hi->device_guess);
            if (f) fprintf(f, "  Тип (по портам): %s\n", hi->device_guess);
        }
        if (hi->has_netbios && (hi->netbios_name[0] || hi->netbios_group[0])) {
            conprintf("  NetBIOS: имя=%s группа/домен=%s\n", hi->netbios_name, hi->netbios_group);
            if (f) fprintf(f, "  NetBIOS: имя=%s группа/домен=%s\n", hi->netbios_name, hi->netbios_group);
        }
        if (hi->has_snmp) {
            conprintf("  SNMP sysDescr: %s\n", hi->snmp_descr);
            if (f) fprintf(f, "  SNMP sysDescr: %s\n", hi->snmp_descr);
        }
        if (hi->has_mdns) {
            conprintf("  mDNS: %s\n", hi->mdns_name);
            if (f) fprintf(f, "  mDNS: %s\n", hi->mdns_name);
        }
        if (hi->has_llmnr) {
            conprintf("  LLMNR (имя компьютера): %s\n", hi->llmnr_name);
            if (f) fprintf(f, "  LLMNR (имя компьютера): %s\n", hi->llmnr_name);
        }
        if (hi->has_ptr) {
            conprintf("  PTR (обратный DNS): %s\n", hi->ptr_name);
            if (f) fprintf(f, "  PTR (обратный DNS): %s\n", hi->ptr_name);
        }
        if (hi->has_smb) {
            conprintf("  SMB NetBIOS: имя=%s домен=%s\n", hi->smb_nb_name, hi->smb_nb_domain);
            if (f) fprintf(f, "  SMB NetBIOS: имя=%s домен=%s\n", hi->smb_nb_name, hi->smb_nb_domain);
            if (hi->smb_dns_name[0]) {
                conprintf("  SMB DNS: имя=%s домен=%s\n", hi->smb_dns_name, hi->smb_dns_domain);
                if (f) fprintf(f, "  SMB DNS: имя=%s домен=%s\n", hi->smb_dns_name, hi->smb_dns_domain);
            }
        }
        if (hi->has_wmi) {
            if (hi->wmi_os_caption[0]) {
                conprintf("  WMI ОС: %s (версия %s, сборка %s)\n",
                          hi->wmi_os_caption, hi->wmi_os_version, hi->wmi_os_build);
                if (f) fprintf(f, "  WMI ОС: %s (версия %s, сборка %s)\n",
                               hi->wmi_os_caption, hi->wmi_os_version, hi->wmi_os_build);
            }
            if (hi->wmi_boot_time[0]) {
                conprintf("  WMI загружена: %s\n", hi->wmi_boot_time);
                if (f) fprintf(f, "  WMI загружена: %s\n", hi->wmi_boot_time);
            }
            if (hi->wmi_cpu_cores > 0 || hi->wmi_ram_gb > 0) {
                conprintf("  WMI железо: %d ядер, %.1f ГБ ОЗУ\n", hi->wmi_cpu_cores, hi->wmi_ram_gb);
                if (f) fprintf(f, "  WMI железо: %d ядер, %.1f ГБ ОЗУ\n", hi->wmi_cpu_cores, hi->wmi_ram_gb);
            }
            if (hi->wmi_logged_user[0]) {
                conprintf("  WMI залогинен: %s\n", hi->wmi_logged_user);
                if (f) fprintf(f, "  WMI залогинен: %s\n", hi->wmi_logged_user);
            }
            if (hi->wmi_logon_time[0]) {
                conprintf("  WMI время логона: %s\n", hi->wmi_logon_time);
                if (f) fprintf(f, "  WMI время логона: %s\n", hi->wmi_logon_time);
            }
            if (hi->wmi_gpu[0]) {
                conprintf("  WMI видеоадаптер: %s\n", hi->wmi_gpu);
                if (f) fprintf(f, "  WMI видеоадаптер: %s\n", hi->wmi_gpu);
            }
        } else if (g_wmi_mode && hi->wmi_error[0]) {
            conprintf("  WMI: не удалось (%s)\n", hi->wmi_error);
            if (f) fprintf(f, "  WMI: не удалось (%s)\n", hi->wmi_error);
        }
        if (hi->has_wts) {
            if (hi->wts_username[0]) {
                conprintf("  WTS сессия: %s\\%s\n", hi->wts_domain, hi->wts_username);
                if (f) fprintf(f, "  WTS сессия: %s\\%s\n", hi->wts_domain, hi->wts_username);
            }
            if (hi->wts_logon_time[0]) {
                conprintf("  WTS время логона: %s\n", hi->wts_logon_time);
                if (f) fprintf(f, "  WTS время логона: %s\n", hi->wts_logon_time);
            }
            if (hi->wts_idle_minutes >= 0) {
                conprintf("  WTS бездействие: %.1f мин.\n", hi->wts_idle_minutes);
                if (f) fprintf(f, "  WTS бездействие: %.1f мин.\n", hi->wts_idle_minutes);
            }
        } else if (g_wts_mode && hi->wts_error[0]) {
            conprintf("  WTS: не удалось (%s)\n", hi->wts_error);
            if (f) fprintf(f, "  WTS: не удалось (%s)\n", hi->wts_error);
        }
    }
}

/* Обёртка с повторными попытками (--retries) поверх tcp_check/udp_check -
   помогает при потере пакетов на слабом/перегруженном роутере. */
static int check_with_retries(int is_tcp, uint32_t ip, uint16_t port, int timeout_ms) {
    for (int attempt = 0; attempt < g_retries; attempt++) {
        int open = is_tcp ? tcp_check(ip, port, timeout_ms)
                           : udp_check(ip, port, timeout_ms);
        if (open) return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Неблокирующий "выстрел" запроса без ожидания ответа - используется     */
/* в fast-режиме, где один поток держит открытыми много соединений сразу  */
/* и через select() узнаёт, какие из них уже готовы, не дожидаясь         */
/* остальных по очереди.                                                  */
/* ---------------------------------------------------------------------- */

static SOCKET tcp_launch(uint32_t ip_h, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip_h);

    connect(s, (struct sockaddr *)&addr, sizeof(addr)); /* асинхронно, результат заберём позже через select */
    return s;
}

static SOCKET udp_launch(uint32_t ip_h, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip_h);

    unsigned char payload[128];
    int plen = get_udp_payload(port, payload, sizeof(payload));
    if (plen <= 0) { payload[0] = 0; plen = 1; }
    sendto(s, (const char *)payload, plen, 0, (struct sockaddr *)&addr, sizeof(addr));
    return s;
}

/* ---------------------------------------------------------------------- */
/* Рабочие потоки                                                          */
/* ---------------------------------------------------------------------- */

typedef struct {
    ScanState *st;
} WorkerArgs;

static DWORD WINAPI worker_full(LPVOID param) {
    WorkerArgs *wa = (WorkerArgs *)param;
    ScanState *st = wa->st;
    for (;;) {
        LONG64 idx = InterlockedIncrement64((volatile LONG64 *)&st->claim) - 1;
        if ((uint64_t)idx >= st->total) break;

        uint64_t host_idx = (uint64_t)idx / (uint64_t)g_port_count;
        int port_idx = (int)((uint64_t)idx % (uint64_t)g_port_count);
        uint32_t ip = get_scan_host(host_idx);
        uint16_t port = g_ports[port_idx];

        if (is_reserved_host(ip)) {
            InterlockedIncrement64((volatile LONG64 *)&g_skipped_reserved);
            LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
            if ((done % 37) == 0) print_progress(st);
            continue;
        }

        int open = check_with_retries(st->is_tcp, ip, port, g_timeout_ms);
        if (open) add_hit(st, st->is_tcp, ip, port);

        LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
        if ((done % 37) == 0) print_progress(st);
    }
    return 0;
}

/* ---------------------------------------------------------------------- */
/* fast-режим: настоящее асинхронное сканирование.                        */
/* Один поток держит одновременно открытыми до g_batch_size соединений    */
/* ("выстрелил и не ждёт"), через select() узнаёт, какие уже готовы -     */
/* готовые сразу фиксируются, а на их место тут же запускается следующая  */
/* задача из очереди. Соединения без ответа ждут ровно до своего личного  */
/* дедлайна (timeout), не тормозя остальные - именно это и даёт настоящую */
/* высокую пропускную способность, а не просто "больше потоков".         */
/* ---------------------------------------------------------------------- */

typedef struct {
    SOCKET sock;
    uint32_t ip;
    uint16_t port;
    DWORD deadline;
    int retries_left;
    int active;
} InFlight;

static void launch_slot(WorkerArgs *wa, InFlight *slot, int timeout_ms) {
    ScanState *st = wa->st;
    LONG64 idx = InterlockedIncrement64((volatile LONG64 *)&st->claim) - 1;
    if ((uint64_t)idx >= st->total) {
        slot->active = 0;
        return;
    }
    uint64_t host_idx = (uint64_t)idx / (uint64_t)g_port_count;
    int port_idx = (int)((uint64_t)idx % (uint64_t)g_port_count);
    uint32_t ip = get_scan_host(host_idx);
    uint16_t port = g_ports[port_idx];

    if (is_reserved_host(ip)) {
        InterlockedIncrement64((volatile LONG64 *)&g_skipped_reserved);
        slot->active = 0;
        LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
        if ((done % 97) == 0) print_progress(st);
        return;
    }

    SOCKET s = st->is_tcp ? tcp_launch(ip, port) : udp_launch(ip, port);
    slot->sock = s;
    slot->ip = ip;
    slot->port = port;
    slot->deadline = GetTickCount() + (DWORD)timeout_ms;
    slot->retries_left = g_retries - 1;
    slot->active = (s != INVALID_SOCKET);
    if (!slot->active) {
        /* сокет не удалось создать - сразу считаем задачу выполненной,
           чтобы не зависнуть навечно */
        LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
        if ((done % 97) == 0) print_progress(st);
    }
}

/* повторно использует тот же слот для retry (не берёт новую задачу из очереди) */
static void relaunch_slot(WorkerArgs *wa, InFlight *slot, int timeout_ms) {
    ScanState *st = wa->st;
    SOCKET s = st->is_tcp ? tcp_launch(slot->ip, slot->port) : udp_launch(slot->ip, slot->port);
    slot->sock = s;
    slot->deadline = GetTickCount() + (DWORD)timeout_ms;
    slot->retries_left--;
    slot->active = (s != INVALID_SOCKET);
}

static DWORD WINAPI worker_fast(LPVOID param) {
    WorkerArgs *wa = (WorkerArgs *)param;
    ScanState *st = wa->st;
    int timeout = g_timeout_ms;
    int batch = g_batch_size;
    if (batch < 1) batch = 1;
    if (batch > FD_SETSIZE - 4) batch = FD_SETSIZE - 4;

    InFlight *slots = calloc(batch, sizeof(InFlight));
    int any_active = 0;

    for (int i = 0; i < batch; i++) {
        launch_slot(wa, &slots[i], timeout);
        if (slots[i].active) any_active = 1;
    }

    while (any_active) {
        fd_set wfds, rfds, efds;
        FD_ZERO(&wfds);
        FD_ZERO(&rfds);
        FD_ZERO(&efds);
        int have_any = 0;

        for (int i = 0; i < batch; i++) {
            if (!slots[i].active) continue;
            have_any = 1;
            if (st->is_tcp) {
                FD_SET(slots[i].sock, &wfds);
                FD_SET(slots[i].sock, &efds);
            } else {
                FD_SET(slots[i].sock, &rfds);
            }
        }

        if (!have_any) break;

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; /* 100мс - частота проверки персональных дедлайнов */
        select(0, &rfds, &wfds, &efds, &tv);

        DWORD now = GetTickCount();
        any_active = 0;

        for (int i = 0; i < batch; i++) {
            if (!slots[i].active) continue;

            int finished = 0, success = 0;

            if (st->is_tcp) {
                if (FD_ISSET(slots[i].sock, &wfds) && !FD_ISSET(slots[i].sock, &efds)) {
                    int soerr = 0, len = sizeof(soerr);
                    if (getsockopt(slots[i].sock, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len) == 0 && soerr == 0) {
                        success = 1;
                    }
                    finished = 1;
                } else if (FD_ISSET(slots[i].sock, &efds)) {
                    finished = 1; /* явный отказ (RST и т.п.) - порт закрыт, ретраить бессмысленно */
                }
            } else {
                if (FD_ISSET(slots[i].sock, &rfds)) {
                    char buf[512];
                    struct sockaddr_in from;
                    int fl = sizeof(from);
                    int r = recvfrom(slots[i].sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
                    success = (r >= 0);
                    finished = 1;
                }
            }

            int timed_out = 0;
            if (!finished && (int32_t)(now - slots[i].deadline) >= 0) {
                timed_out = 1;
                finished = 1;
            }

            if (finished) {
                closesocket(slots[i].sock);
                if (success) {
                    add_hit(st, st->is_tcp, slots[i].ip, slots[i].port);
                    LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
                    if ((done % 97) == 0) print_progress(st);
                    launch_slot(wa, &slots[i], timeout);
                } else if (timed_out && slots[i].retries_left > 0) {
                    /* не отвечает - даём ещё один шанс на случай перегруженного роутера,
                       задачу выполненной пока НЕ считаем */
                    relaunch_slot(wa, &slots[i], timeout);
                } else {
                    LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
                    if ((done % 97) == 0) print_progress(st);
                    launch_slot(wa, &slots[i], timeout);
                }
            }

            if (slots[i].active) any_active = 1;
        }
    }

    free(slots);
    return 0;
}

/* WaitForMultipleObjects принципиально не может ждать больше 64 хендлов
   одновременно - при превышении вызов молча проваливается (WAIT_FAILED),
   и вызывающий код ошибочно считает работу завершённой, хотя потоки ещё
   выполняются. Ждём каждый хендл по отдельности - лимита нет, порядок
   завершения не важен. */
static void wait_for_all_threads(HANDLE *handles, int count) {
    for (int i = 0; i < count; i++) {
        WaitForSingleObject(handles[i], INFINITE);
        CloseHandle(handles[i]);
    }
}

static DWORD WINAPI worker_ping(LPVOID param) {
    ScanState *st = (ScanState *)param;
    for (;;) {
        LONG64 idx = InterlockedIncrement64((volatile LONG64 *)&st->claim) - 1;
        if ((uint64_t)idx >= st->total) break;

        uint32_t ip = ip_at_index((uint64_t)idx);

        if (is_reserved_host(ip)) {
            InterlockedIncrement64((volatile LONG64 *)&g_skipped_reserved);
            LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
            if ((done % 37) == 0) print_progress(st);
            continue;
        }

        int ttl = -1;
        int alive = icmp_check_ex(ip, g_ping_timeout_ms, &ttl);

        if (!alive && is_same_subnet(ip)) {
            /* ICMP не ответил, но устройство в нашей же L2-подсети - ARP
               не обходится настройками "пинг отключён", это отдельный,
               более надёжный сигнал живости */
            unsigned char mac_tmp[6];
            if (get_mac_via_arp(ip, mac_tmp)) alive = 1;
        }

        if (alive) add_alive(st, ip, ttl);

        LONG64 done = InterlockedIncrement64((volatile LONG64 *)&st->completed);
        if ((done % 37) == 0) print_progress(st);
    }
    return 0;
}

static void run_discovery_phase(void) {
    ScanState st = {0};
    st.name = "PING";
    st.total = g_total_hosts;
    st.console_line = -1;

    int threads_to_spawn = g_thread_count * 2;
    if (threads_to_spawn < 1) threads_to_spawn = 1;
    if (threads_to_spawn > 512) threads_to_spawn = 512;

    HANDLE *handles = malloc(sizeof(HANDLE) * threads_to_spawn);
    for (int i = 0; i < threads_to_spawn; i++) {
        handles[i] = CreateThread(NULL, 0, worker_ping, &st, 0, NULL);
    }
    wait_for_all_threads(handles, threads_to_spawn);
    free(handles);

    print_progress(&st);
    conprintf("\n");
    conprintf("Разведка (ICMP+ARP): живых %d из %llu (в подсети %d подключений)\n",
               g_alive_count, (unsigned long long)g_total_hosts, g_local_subnet_count);
    if (g_alive_count == 0) {
        conprintf("Внимание: ни один хост не ответил ни на пинг, ни на ARP. Возможные причины: "
               "неверный диапазон адресов, либо сеть в принципе не L2-подключена (VPN/маршрутизация).\n");
    }
}

/* Запускает пул потоков для одной фазы (TCP или UDP) и ждёт её завершения.
   ScanState передаётся вызывающей стороной уже с выставленными total/name/
   is_tcp/console_line - это позволяет запускать TCP и UDP одновременно
   (см. run_both_parallel), каждую в своём вызывающем потоке. */
static void run_phase(ScanState *st) {
    st->claim = 0;
    st->completed = 0;
    st->found = 0;

    /* в fast-режиме параллелизм обеспечивает g_batch_size (много соединений
       на один поток), поэтому число ОС-потоков не нужно искусственно
       умножать - это раньше не давало прироста, только тратило ресурсы */
    int threads_to_spawn = g_thread_count;
    if (threads_to_spawn < 1) threads_to_spawn = 1;
    if (threads_to_spawn > 512) threads_to_spawn = 512;

    HANDLE *handles = malloc(sizeof(HANDLE) * threads_to_spawn);
    WorkerArgs wa;
    wa.st = st;

    LPTHREAD_START_ROUTINE fn = g_fast_mode ? worker_fast : worker_full;

    for (int i = 0; i < threads_to_spawn; i++) {
        handles[i] = CreateThread(NULL, 0, fn, &wa, 0, NULL);
    }
    wait_for_all_threads(handles, threads_to_spawn);
    free(handles);

    print_progress(st);
    if (st->console_line < 0) conprintf("\n");
}

typedef struct {
    ScanState *st;
} PhaseDriverArgs;

static DWORD WINAPI phase_driver_thread(LPVOID param) {
    PhaseDriverArgs *pa = (PhaseDriverArgs *)param;
    run_phase(pa->st);
    return 0;
}

/* Запускает TCP и UDP сканирование ОДНОВРЕМЕННО, каждое в своём наборе
   потоков, а не последовательно. Прогресс каждого протокола рисуется на
   своей закреплённой строке консоли (через Win32 Console API - работает
   на всех Windows Vista-11 без ANSI/VT, в отличие от '\r'). */
static void run_both_parallel(int do_tcp, int do_udp) {
    uint64_t hosts_for_scan = g_discover_mode ? (uint64_t)g_alive_count : g_total_hosts;
    uint64_t total_work = hosts_for_scan * (uint64_t)g_port_count;

    ScanState tcp_st = {0}, udp_st = {0};

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hOut, &csbi);
    g_console_base_y = csbi.dwCursorPosition.Y;
    conprintf("\n\n"); /* резервируем 2 строки под прогресс-бары */
    fflush(stdout);

    HANDLE threads[2];
    PhaseDriverArgs pa_tcp, pa_udp;
    int n = 0;
    int line = 0;

    if (do_tcp) {
        tcp_st.name = "TCP";
        tcp_st.is_tcp = 1;
        tcp_st.total = total_work;
        tcp_st.console_line = line++;
        pa_tcp.st = &tcp_st;
        threads[n++] = CreateThread(NULL, 0, phase_driver_thread, &pa_tcp, 0, NULL);
    }
    if (do_udp) {
        udp_st.name = "UDP";
        udp_st.is_tcp = 0;
        udp_st.total = total_work;
        udp_st.console_line = line++;
        pa_udp.st = &udp_st;
        threads[n++] = CreateThread(NULL, 0, phase_driver_thread, &pa_udp, 0, NULL);
    }

    wait_for_all_threads(threads, n);

    COORD below;
    below.X = 0;
    below.Y = (SHORT)(g_console_base_y + line);
    SetConsoleCursorPosition(hOut, below);
    conprintf("\n");
    g_console_base_y = -1;
}

/* ---------------------------------------------------------------------- */
/* Вывод результатов                                                       */
/* ---------------------------------------------------------------------- */

static void write_results(int do_tcp, int do_udp) {
    FILE *f = fopen(g_out_path, g_resume_mode ? "a" : "w");
    if (!f) {
        conprintf_err("Не удалось открыть файл для записи: %s\n", g_out_path);
    }

    if (f && g_resume_mode) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        if (size > 0) fprintf(f, "\n\n"); /* разделитель между разными по времени сканированиями */
    }

    if (f && g_when_mode) {
        SYSTEMTIME t;
        GetLocalTime(&t);
        fprintf(f, "%02d:%02d:%02d  %02d.%02d.%04d\n",
                t.wHour, t.wMinute, t.wSecond, t.wDay, t.wMonth, t.wYear);
    }

    if (do_tcp) {
        qsort(g_tcp_hits, g_tcp_hit_count, sizeof(Hit), hit_cmp);
        g_tcp_hit_count = dedup_hits(g_tcp_hits, g_tcp_hit_count);
        conprintf("TCP\n");
        if (f) fprintf(f, "TCP\n");
        for (int i = 0; i < g_tcp_hit_count; i++) {
            char ipbuf[64];
            u32_to_ip_str(g_tcp_hits[i].ip, ipbuf, sizeof(ipbuf));
            conprintf("%s:%u\n", ipbuf, g_tcp_hits[i].port);
            if (f) fprintf(f, "%s:%u\n", ipbuf, g_tcp_hits[i].port);
        }
    }

    if (do_udp) {
        qsort(g_udp_hits, g_udp_hit_count, sizeof(Hit), hit_cmp);
        g_udp_hit_count = dedup_hits(g_udp_hits, g_udp_hit_count);
        conprintf("UDP\n");
        if (f) fprintf(f, "UDP\n");
        for (int i = 0; i < g_udp_hit_count; i++) {
            char ipbuf[64];
            u32_to_ip_str(g_udp_hits[i].ip, ipbuf, sizeof(ipbuf));
            conprintf("%s:%u\n", ipbuf, g_udp_hits[i].port);
            if (f) fprintf(f, "%s:%u\n", ipbuf, g_udp_hits[i].port);
        }
    }

    if (g_info_mode) print_host_info_section(f);

    if (f) fclose(f);
}

/* вычисляет путь для доп. файла с сортировкой по портам: result.txt -> result_by_port.txt */
static void derive_by_port_path(char *out, size_t out_cap) {
    const char *dot = strrchr(g_out_path, '.');
    const char *base_end = dot ? dot : g_out_path + strlen(g_out_path);
    size_t base_len = (size_t)(base_end - g_out_path);
    if (base_len > out_cap - 20) base_len = out_cap - 20;
    memcpy(out, g_out_path, base_len);
    out[base_len] = 0;
    strncat(out, "_by_port", out_cap - strlen(out) - 1);
    if (dot) strncat(out, dot, out_cap - strlen(out) - 1);
}

/* --sort-by-port: пишет ДОПОЛНИТЕЛЬНЫЙ файл с теми же результатами, но
   отсортированными сначала по порту, потом по IP - основной файл
   (по IP) при этом не трогаем, оба варианта сохраняются одновременно */
static void write_results_by_port(int do_tcp, int do_udp) {
    char path[MAX_PATH];
    derive_by_port_path(path, sizeof(path));

    FILE *f = fopen(path, g_resume_mode ? "a" : "w");
    if (!f) {
        conprintf_err("Не удалось открыть файл для записи (сортировка по порту): %s\n", path);
        return;
    }

    if (g_resume_mode) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        if (size > 0) fprintf(f, "\n\n");
    }

    if (g_when_mode) {
        SYSTEMTIME t;
        GetLocalTime(&t);
        fprintf(f, "%02d:%02d:%02d  %02d.%02d.%04d\n",
                t.wHour, t.wMinute, t.wSecond, t.wDay, t.wMonth, t.wYear);
    }

    if (do_tcp) {
        qsort(g_tcp_hits, g_tcp_hit_count, sizeof(Hit), hit_cmp_by_port);
        fprintf(f, "TCP\n");
        for (int i = 0; i < g_tcp_hit_count; i++) {
            char ipbuf[64];
            u32_to_ip_str(g_tcp_hits[i].ip, ipbuf, sizeof(ipbuf));
            fprintf(f, "%s:%u\n", ipbuf, g_tcp_hits[i].port);
        }
    }
    if (do_udp) {
        qsort(g_udp_hits, g_udp_hit_count, sizeof(Hit), hit_cmp_by_port);
        fprintf(f, "UDP\n");
        for (int i = 0; i < g_udp_hit_count; i++) {
            char ipbuf[64];
            u32_to_ip_str(g_udp_hits[i].ip, ipbuf, sizeof(ipbuf));
            fprintf(f, "%s:%u\n", ipbuf, g_udp_hits[i].port);
        }
    }

    fclose(f);
    conprintf("Доп. файл (сортировка по портам): %s\n", path);
}

/* ---------------------------------------------------------------------- */
/* CLI                                                                     */
/* ---------------------------------------------------------------------- */

static void print_usage(const char *prog) {
    conprintf(
        "NetScan - консольный TCP/UDP сканер локальной сети\n\n"
        "Использование:\n"
        "  %s --ip \"192.168.0.1-192.168.255.255,10.51.11.1-10.51.11.255\"\n"
        "     --ports \"80,443,1000-1200,500,445,53\"\n"
        "     --proto all|tcp|udp\n"
        "     --threads 50\n"
        "     --mode full|fast\n"
        "     [--timeout 800]\n"
        "     [--retries 1]\n"
        "     [--batch 32]\n"
        "     [--discover] [--ping-timeout 500]\n"
        "     [--out result.txt] [--resume] [--when]\n\n"
        "  --discover       сначала ICMP-пингом определить живые хосты и сканировать порты\n"
        "                   только по ним (кардинально быстрее + диагностирует блокировки роутера)\n"
        "  --retries N      число попыток на каждый порт при неответе (по умолчанию 1)\n"
        "  --batch N        (только в --mode fast) сколько соединений держит открытыми ОДИН\n"
        "                   поток одновременно, не дожидаясь ответа по очереди.\n"
        "                   Реальная параллельность = --threads x --batch.\n"
        "                   Пример: 50 потоков x 32 batch = 1600 одновременных проверок.\n"
        "  --sequential     сканировать TCP и UDP по очереди (по умолчанию при --proto all\n"
        "                   они сканируются ОДНОВРЕМЕННО - вдвое быстрее).\n"
        "  --include-reserved  не пропускать x.x.x.0/x.x.x.255 (по умолчанию пропускаются -\n"
        "                   это обычно сетевой/broadcast адрес, а не реальный хост).\n"
        "  --resume, -r     дописывать результат в конец файла (а не перезаписывать),\n"
        "                   отделяя сканирования двумя пустыми строками.\n"
        "  --when, -w       записывать дату и время сканирования перед результатами\n"
        "                   (формат: 07:15:00  12.07.2026).\n"
        "  --info           собрать доп. информацию по найденным хостам: MAC+вендор (ARP),\n"
        "                   TTL->ОС, SNMP sysDescr, NetBIOS имя/домен, mDNS, тип по портам.\n"
        "  --update-oui     скачать/обновить базу MAC-вендоров (oui.txt рядом с exe) и выйти.\n"
        "  --deep-resolve   перебрать доп. способы определения ИМЕНИ КОМПЬЮТЕРА: обратный DNS\n"
        "                   (PTR через шлюз или --dns-server) и SMB2/NTLMSSP-хендшейк (TCP 445,\n"
        "                   без аутентификации - работает и в рабочей группе, и в AD-домене).\n"
        "                   Включает --info автоматически.\n"
        "  --dns-server IP  свой DNS-сервер для обратных PTR-запросов при --deep-resolve\n"
        "                   (по умолчанию - автоопределённый шлюз).\n"
        "  --wmi            запросить через WMI/DCOM: точную версию ОС, время последней\n"
        "                   загрузки, число ядер CPU, объём RAM, залогиненного пользователя.\n"
        "                   ТРЕБУЕТ ПРАВ на целевой машине (в отличие от всего остального\n"
        "                   выше) - либо текущего пользователя (SSO, порт 135 + DCOM должны\n"
        "                   быть доступны), либо явных --wmi-user/--wmi-password. Включает\n"
        "                   --info автоматически.\n"
        "  --wmi-user U     логин для WMI (без указания - используется текущий пользователь).\n"
        "  --wmi-password P пароль для WMI (используется вместе с --wmi-user).\n"
        "  --wmi-domain D   домен для --wmi-user (опционально, для DOMAIN\\user).\n"
        "  --wmi-gpu        дополнительно запросить через WMI модель видеоадаптера.\n"
        "  --wts            запросить через Terminal Services API (то же, что делают\n"
        "                    штатные quser/qwinsta): текущего пользователя сессии, время\n"
        "                    логона, время бездействия. Использует ТЕ ЖЕ --wmi-user/\n"
        "                    --wmi-password/--wmi-domain, что и --wmi. Включает --info.\n"
        "  --sort-by-port   доп. файл result_by_port.txt с теми же результатами, но\n"
        "                   отсортированными по порту (основной файл по IP не меняется -\n"
        "                   сохраняются оба варианта одновременно).\n"
        "  --sort-os        сортировать блок \"Информация об устройствах\" по ОС (TTL-эвристика)\n"
        "                   вместо IP.\n\n"
        "Максимальная скорость + защита от потерь пакетов на слабом роутере:\n"
        "  %s --ip 192.168.1.1-192.168.1.254 --ports 22,80,443,445 --proto all \\\n"
        "     --mode fast --threads 50 --batch 64 --retries 2 --discover\n",
        prog, prog);
}

int main(int argc, char **argv) {
    conprintf("NetScan запущен, обрабатываю параметры...\n");

    char *ip_arg = NULL;
    char *ports_arg = NULL;
    char proto_arg[8] = "all";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
            ip_arg = argv[++i];
        } else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
            ports_arg = argv[++i];
        } else if (strcmp(argv[i], "--proto") == 0 && i + 1 < argc) {
            strncpy(proto_arg, argv[++i], sizeof(proto_arg) - 1);
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            g_thread_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            g_fast_mode = (strcmp(argv[++i], "fast") == 0) ? 1 : 0;
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            g_timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            strncpy(g_out_path, argv[++i], sizeof(g_out_path) - 1);
        } else if (strcmp(argv[i], "--discover") == 0) {
            g_discover_mode = 1;
        } else if (strcmp(argv[i], "--ping-timeout") == 0 && i + 1 < argc) {
            g_ping_timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--retries") == 0 && i + 1 < argc) {
            g_retries = atoi(argv[++i]);
            if (g_retries < 1) g_retries = 1;
        } else if (strcmp(argv[i], "--batch") == 0 && i + 1 < argc) {
            g_batch_size = atoi(argv[++i]);
            if (g_batch_size < 1) g_batch_size = 1;
        } else if (strcmp(argv[i], "--sequential") == 0) {
            g_sequential = 1;
        } else if (strcmp(argv[i], "--include-reserved") == 0) {
            g_include_reserved = 1;
        } else if (strcmp(argv[i], "--resume") == 0 || strcmp(argv[i], "-r") == 0) {
            g_resume_mode = 1;
        } else if (strcmp(argv[i], "--when") == 0 || strcmp(argv[i], "-w") == 0) {
            g_when_mode = 1;
        } else if (strcmp(argv[i], "--info") == 0) {
            g_info_mode = 1;
        } else if (strcmp(argv[i], "--deep-resolve") == 0) {
            g_deep_resolve = 1;
            g_info_mode = 1; /* --deep-resolve подразумевает --info */
        } else if (strcmp(argv[i], "--dns-server") == 0 && i + 1 < argc) {
            g_dns_server_override = ip_to_u32(argv[++i]);
        } else if (strcmp(argv[i], "--wmi") == 0) {
            g_wmi_mode = 1;
            g_info_mode = 1; /* --wmi подразумевает --info */
        } else if (strcmp(argv[i], "--wmi-gpu") == 0) {
            g_wmi_gpu = 1;
        } else if (strcmp(argv[i], "--wmi-user") == 0 && i + 1 < argc) {
            strncpy(g_wmi_user, argv[++i], sizeof(g_wmi_user) - 1);
        } else if (strcmp(argv[i], "--wmi-password") == 0 && i + 1 < argc) {
            strncpy(g_wmi_password, argv[++i], sizeof(g_wmi_password) - 1);
        } else if (strcmp(argv[i], "--wmi-domain") == 0 && i + 1 < argc) {
            strncpy(g_wmi_domain, argv[++i], sizeof(g_wmi_domain) - 1);
        } else if (strcmp(argv[i], "--wts") == 0) {
            g_wts_mode = 1;
            g_info_mode = 1; /* --wts подразумевает --info */
        } else if (strcmp(argv[i], "--sort-by-port") == 0) {
            g_sort_by_port_also = 1;
        } else if (strcmp(argv[i], "--sort-os") == 0) {
            g_sort_os = 1;
        } else if (strcmp(argv[i], "--update-oui") == 0) {
            g_update_oui_only = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (g_update_oui_only) {
        char path[MAX_PATH];
        get_oui_path(path, sizeof(path));
        int ok = download_oui_database(path);
        return ok ? 0 : 1;
    }

    if (!ip_arg || !ports_arg) {
        print_usage(argv[0]);
        return 1;
    }

    int do_tcp = (strcmp(proto_arg, "all") == 0 || strcmp(proto_arg, "tcp") == 0);
    int do_udp = (strcmp(proto_arg, "all") == 0 || strcmp(proto_arg, "udp") == 0);
    if (!do_tcp && !do_udp) die("Некорректное значение --proto (all|tcp|udp)");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) die("WSAStartup не удался");

    InitializeCriticalSection(&g_results_cs);
    InitializeCriticalSection(&g_console_cs);
    InitializeCriticalSection(&g_alive_cs);

    parse_ip_ranges(ip_arg);
    parse_ports(ports_arg);

    if (g_info_mode) {
        load_oui_database();
        if (g_oui_count == 0) {
            conprintf("База OUI не найдена рядом с exe - вендор по MAC не будет определяться. "
                      "Запусти с --update-oui, чтобы скачать (%s).\n", OUI_URL);
        }
    }

    conprintf("Хостов: %llu   Портов: %d   Потоков: %d   Режим: %s   Таймаут: %d мс   Повторов: %d\n",
           (unsigned long long)g_total_hosts, g_port_count, g_thread_count,
           g_fast_mode ? "fast" : "full", g_timeout_ms, g_retries);
    if (g_fast_mode) {
        conprintf("Batch: %d   Параллельность: %d одновременных проверок\n",
               g_batch_size, g_thread_count * g_batch_size);
    }
    conprintf("Диапазон: %s\n", ip_arg);
    conprintf("Порты: %s\n", ports_arg);
    conprintf("Файл результатов: %s%s\n", g_out_path, g_resume_mode ? " (дозапись)" : "");

    DWORD t0 = GetTickCount();

    if (g_wmi_mode) {
        HRESULT hr_com = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr_com) || hr_com == S_FALSE) {
            HRESULT hr_sec = CoInitializeSecurity(NULL, -1, NULL, NULL,
                                                   RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                                                   NULL, EOAC_NONE, NULL);
            if (SUCCEEDED(hr_sec)) {
                g_wmi_com_ready = 1;
            } else {
                conprintf_err("CoInitializeSecurity не удался (0x%08lX) - --wmi работать не будет\n",
                               (unsigned long)hr_sec);
            }
        } else {
            conprintf_err("CoInitializeEx не удался (0x%08lX) - --wmi работать не будет\n",
                           (unsigned long)hr_com);
        }
    }

    if (g_discover_mode || g_info_mode) {
        load_local_subnets();
    }

    if (g_discover_mode) {
        run_discovery_phase();
    }

    if (do_tcp && do_udp && !g_sequential) {
        run_both_parallel(1, 1);
    } else {
        uint64_t hosts_for_scan = g_discover_mode ? (uint64_t)g_alive_count : g_total_hosts;
        uint64_t total_work = hosts_for_scan * (uint64_t)g_port_count;
        if (do_tcp) {
            ScanState st = {0};
            st.name = "TCP"; st.is_tcp = 1; st.total = total_work; st.console_line = -1;
            run_phase(&st);
        }
        if (do_udp) {
            ScanState st = {0};
            st.name = "UDP"; st.is_tcp = 0; st.total = total_work; st.console_line = -1;
            run_phase(&st);
        }
    }

    DWORD t1 = GetTickCount();
    conprintf("Сканирование завершено за %.1f сек.\n\n", (t1 - t0) / 1000.0);

    if (g_skipped_reserved > 0) {
        conprintf("Пропущено адресов вида x.x.x.0/x.x.x.255 (сетевой/broadcast): %lld "
                  "(--include-reserved, чтобы всё же сканировать)\n\n", (long long)g_skipped_reserved);
    }

    if (g_info_mode) run_info_gathering();

    write_results(do_tcp, do_udp);
    if (g_sort_by_port_also) write_results_by_port(do_tcp, do_udp);

    conprintf("\nРезультат сохранён в файл: %s\n", g_out_path);

    WSACleanup();
    return 0;
}
