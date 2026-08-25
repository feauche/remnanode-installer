#!/usr/bin/env bash
#===============================================================================
# nodectl — Node Auto-Installer
# Description: Подготовка сервера под ноду Remnawave «под ключ»:
#              firewall, fail2ban, kernel hardening, сеть/лимиты, авто-обновления,
#              анти-флуд, установка Docker + ноды Remnawave, Docker+UFW fix,
#              и команда управления `nodectl` (geoblock, IPv6/ICMP, SYNPROXY,
#              Psiphon для Gemini, Selfsteal для Reality).
#===============================================================================

set -uo pipefail
umask 022

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
RESET='\033[0m'

# --- Параметры по умолчанию (можно переопределить переменными окружения) ---
DEFAULT_NODE_PORT="${NODE_PORT:-2420}"

#===============================================================================
# Баннер
#===============================================================================
clear
echo -e "${CYAN}========================================================================${RESET}"
echo -e "${GREEN}                    _            _   _                               ${RESET}"
echo -e "${GREEN}   _ __   ___   __| | ___  ___| |_| |                               ${RESET}"
echo -e "${GREEN}  | '_ \\ / _ \\ / _\` |/ _ \\/ __| __| |                              ${RESET}"
echo -e "${GREEN}  | | | | (_) | (_| |  __/ (__| |_| |                              ${RESET}"
echo -e "${GREEN}  |_| |_|\\___/ \\__,_|\\___|\\___|\\__|_|                              ${RESET}"
echo -e "${CYAN}========================================================================${RESET}"
echo -e "${YELLOW}                    NODE SETUP & SECURITY                           ${RESET}"
echo -e "${CYAN}========================================================================${RESET}"
echo ""

#===============================================================================
# Хелперы вывода (в едином стиле с web-proxy-tg-installer)
#===============================================================================
CURRENT_STEP="подготовка"

function step()    { CURRENT_STEP="$1"; echo -e "\n${YELLOW}========================================\n$1\n========================================${RESET}"; }
function success() { echo -e "${GREEN}[+] $1${RESET}"; }
function info()    { echo -e "${BLUE}[i] $1${RESET}"; }
function warn()    { echo -e "${YELLOW}[!] $1${RESET}"; }

function print_recovery() {
    echo -e "${YELLOW}Что делать дальше:${RESET}"
    echo -e "  • Изучите сообщение об ошибке выше — обычно в нём указана причина."
    echo -e "  • Устраните её (сеть, занятый порт, права, место на диске)."
    echo -e "  • Запустите установку заново — шаги закалки идемпотентны и безопасны при повторе."
}

# Критическая ошибка: печатает объяснение и полностью прерывает установку.
function error() {
    echo -e "\n${RED}==================== УСТАНОВКА ПРЕРВАНА ====================${RESET}"
    echo -e "${RED}[-] $1${RESET}"
    echo -e "${RED}Этап: ${CURRENT_STEP}${RESET}"
    print_recovery
    echo -e "${RED}===========================================================${RESET}"
    exit 1
}

# --- Учёт шагов: успешные и провалившиеся (некритичные) ---
SETUP_DONE=()
SETUP_FAIL=()
function step_ok()   { SETUP_DONE+=("$1"); echo -e "${GREEN}━━━ ✅ $1 — OK ━━━${RESET}"; }
function step_fail() { SETUP_FAIL+=("$1"); echo -e "${RED}━━━ ⚠️  $1 — не выполнен ━━━${RESET}"; }

#===============================================================================
# Хелперы ввода
#===============================================================================
# ask "Вопрос" "значение_по_умолчанию" -> печатает выбранное значение в stdout
function ask() {
    local prompt="$1" default="${2:-}" ans
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${BLUE}${prompt} [${default}]: ${RESET}")" ans
        echo "${ans:-$default}"
    else
        read -rp "$(echo -e "${BLUE}${prompt}: ${RESET}")" ans
        echo "$ans"
    fi
}

# ask_required "Вопрос" -> зацикливается, пока не введут непустое
function ask_required() {
    local prompt="$1" val
    while true; do
        val=$(ask "$prompt")
        [[ -n "$val" ]] && { echo "$val"; return 0; }
        warn "Значение не может быть пустым." >&2
    done
}

# confirm "Вопрос" "y|n" -> код возврата 0 (да) / 1 (нет)
function confirm() {
    local prompt="$1" def="${2:-y}" ans
    read -rp "$(echo -e "${BLUE}${prompt} [y/n] (${def}): ${RESET}")" ans
    ans="${ans:-$def}"
    [[ "$ans" =~ ^[yYдД] ]]
}

function validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

#===============================================================================
# Предварительные проверки
#===============================================================================
if [[ $EUID -ne 0 ]]; then
    error "Скрипт должен быть запущен от имени root (используйте sudo)."
fi

if ! command -v apt-get >/dev/null 2>&1; then
    error "Поддерживаются только Debian/Ubuntu (apt-get не найден)."
fi

# --- Непрозрачные имена файлов (обфускация) ---
# Файлы, которые создаёт скрипт, получают имена-хэши без слов вроде "node"/
# "hardening" — так по ним нельзя понять, что на сервере стоит нода. Хэш
# детерминирован (от machine-id данного сервера), поэтому уникален на каждом
# сервере и стабилен при повторном запуске — то же имя перезаписывается, дублей
# конфигов не возникает.
_MACHINE_SEED="$(cat /etc/machine-id 2>/dev/null || hostname 2>/dev/null || echo seed)"
tok() { printf '%s' "${_MACHINE_SEED}:$1" | sha256sum | cut -c1-12; }

SSHPORT_CONF="/etc/ssh/sshd_config.d/99-$(tok sshport).conf"
HARDEN_CONF="/etc/sysctl.d/99-$(tok harden).conf"
BOOST_CONF="/etc/sysctl.d/99-$(tok boost).conf"
IPV6_CONF="/etc/sysctl.d/98-$(tok ipv6).conf"
DOCKER_MARK="$(tok dmark)"

# --- Проверка: не установлена ли уже нода (чтобы не поставить вторую) ---
# Имена наших файлов рандомные, поэтому существование ноды определяем по
# стандартным артефактам самой Remnawave, а не по нашим файлам.
NODE_EXISTS=0
NODE_EVIDENCE=""
if [[ -f /opt/remnanode/docker-compose.yml ]]; then
    NODE_EXISTS=1; NODE_EVIDENCE="файл /opt/remnanode/docker-compose.yml"
elif command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^remnanode'; then
    NODE_EXISTS=1; NODE_EVIDENCE="docker-контейнер remnanode"
elif command -v remnanode >/dev/null 2>&1; then
    NODE_EXISTS=1; NODE_EVIDENCE="команда remnanode в системе"
fi

#===============================================================================
# ОПРОС: собираем все параметры заранее (дальше — без вопросов)
#===============================================================================
step "Опрос: параметры установки"

if [[ $NODE_EXISTS -eq 1 ]]; then
    warn "На сервере уже обнаружена нода (${NODE_EVIDENCE})."
    warn "Повторная установка ноды выполнена НЕ будет — второй экземпляр не ставим."
    info "Можно продолжить, чтобы применить/обновить только закалку сервера и firewall."
    if ! confirm "Продолжить (только закалка, без установки ноды)?" "y"; then
        info "Отмена."
        exit 0
    fi
    echo ""
fi

# --- Текущий SSH-порт: sshd_config.d > sshd_config > что реально слушает ss ---
detect_ssh_port() {
    local p
    p=$(grep -h "^Port " /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1 | awk '{print $2}')
    [[ -z "$p" ]] && p=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$p" ]] && p=$(ss -tlnp 2>/dev/null | grep -E "sshd|ssh" | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)
    echo "${p:-22}"
}

CURRENT_SSH_PORT=$(detect_ssh_port)
info "Текущий SSH-порт обнаружен: ${CYAN}${CURRENT_SSH_PORT}${RESET}"

SSH_PORT=$(ask "На каком порту должен быть SSH (Enter = оставить как есть)" "$CURRENT_SSH_PORT")
if ! validate_port "$SSH_PORT"; then
    error "Некорректный SSH-порт: '$SSH_PORT' (нужно 1–65535)."
fi

SECRET_KEY=""
if [[ $NODE_EXISTS -eq 0 ]]; then
    echo ""
    info "Секретный ключ ноды: Панель → Nodes → Add Node → Secret Key"
    SECRET_KEY=$(ask_required "Секретный ключ ноды")
    # Убираем возможные обрамляющие кавычки (панель показывает секрет и в кавычках).
    SECRET_KEY="${SECRET_KEY%\"}"; SECRET_KEY="${SECRET_KEY#\"}"
fi

if [[ $NODE_EXISTS -eq 1 ]]; then
    # Нода уже стоит — порт не спрашиваем, берём из её docker-compose.yml (нужен для UFW).
    NODE_PORT=$(grep -oE 'NODE_PORT=[0-9]+' /opt/remnanode/docker-compose.yml 2>/dev/null | head -1 | cut -d= -f2)
    [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="$DEFAULT_NODE_PORT"
    info "Порт ноды взят из установленной ноды: ${CYAN}${NODE_PORT}${RESET}"
else
    NODE_PORT=$(ask "Порт ноды" "$DEFAULT_NODE_PORT")
    if ! validate_port "$NODE_PORT"; then
        error "Некорректный порт ноды: '$NODE_PORT' (нужно 1–65535)."
    fi
fi

# Версия образа ноды. У remnawave/node нет «скользящего» тега 2 — фиксируем
# конкретную 2.8.0 (последняя в ветке 2.x) либо latest (свежая, ветка 3.x).
NODE_VERSION="2.8.0"
if [[ $NODE_EXISTS -eq 0 ]]; then
    echo ""
    info "Версия ноды:"
    info "  1) 2.8.0  — стабильная, последняя в ветке 2.x (рекомендуется)"
    info "  2) latest — самая свежая (ветка 3.x, может требовать более новую панель)"
    _vchoice=$(ask "Выберите версию (1/2)" "1")
    case "$_vchoice" in
        2|latest|l|L) NODE_VERSION="latest" ;;
        *)            NODE_VERSION="2.8.0" ;;
    esac
    success "Версия ноды: ${NODE_VERSION}"
fi

# --- Сводка + подтверждение ---
echo ""
echo -e "${YELLOW}========================================${RESET}"
echo -e "${YELLOW}СВОДКА:${RESET}"
if [[ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
    echo -e "  SSH порт:        ${RED}${CURRENT_SSH_PORT} → ${SSH_PORT}${RESET} ${YELLOW}(будет миграция!)${RESET}"
else
    echo -e "  SSH порт:        ${CYAN}${SSH_PORT}${RESET} ${GRAY}(без изменений)${RESET}"
fi
if [[ -n "$SECRET_KEY" ]]; then
    echo -e "  Секретный ключ:  ${GRAY}${SECRET_KEY:0:24}…${RESET}"
fi
echo -e "  Порт ноды:       ${CYAN}${NODE_PORT}${RESET}"
if [[ $NODE_EXISTS -eq 0 ]]; then
    echo -e "  Версия ноды:     ${CYAN}${NODE_VERSION}${RESET}"
fi
echo -e "${YELLOW}========================================${RESET}"
echo ""

if [[ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
    warn "Будет миграция SSH с порта ${CURRENT_SSH_PORT} на ${SSH_PORT}."
    warn "После миграции переподключитесь: ${CYAN}ssh -p ${SSH_PORT} <user>@<server>${RESET}"
    warn "Если миграция не удастся — авто-откат на ${CURRENT_SSH_PORT}."
    echo ""
fi

if ! confirm "Запускаю автоматическую настройку?" "y"; then
    info "Отмена."
    exit 0
fi

#===============================================================================
# Обновление системы (перед всем остальным)
#===============================================================================
step "Обновление системы (apt update + upgrade)..."
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
apt-get update -y >/dev/null 2>&1 || warn "apt update завершился с ошибкой — продолжаю."
if apt-get -y -o Dpkg::Options::=--force-confold upgrade >/dev/null 2>&1; then
    success "Система обновлена."
else
    warn "apt upgrade завершился с ошибкой — продолжаю."
fi

# effective_ssh_port — порт, на котором SSH РЕАЛЬНО слушает после шага 2
EFFECTIVE_SSH_PORT="$CURRENT_SSH_PORT"

#===============================================================================
# ШАГ 1/10 — UFW Firewall: установка
#===============================================================================
step "Шаг 1/10: UFW Firewall — установка"
if command -v ufw >/dev/null 2>&1; then
    success "UFW уже установлен."
    step_ok "1/10 UFW"
else
    info "Устанавливаю UFW..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    if apt-get install -y -qq ufw >/dev/null 2>&1; then
        success "UFW установлен."
        step_ok "1/10 UFW"
    else
        error "Не удалось установить UFW — без него дальнейшая настройка бессмысленна."
    fi
fi

#===============================================================================
# ШАГ 2/10 — Миграция SSH (если нужна) + правила UFW + включение
#===============================================================================
step "Шаг 2/10: Миграция SSH + конфигурация UFW"

if [[ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
    info "Мигрирую SSH с ${CURRENT_SSH_PORT} на ${SSH_PORT}..."
    SSHD_BACKUP="/etc/ssh/sshd_config.bak.$(tok sshbak).$(date +%s)"
    cp /etc/ssh/sshd_config "$SSHD_BACKUP"

    # 1. Основной конфиг
    sed -i -e "s/^#*Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    if ! grep -q "^Port " /etc/ssh/sshd_config; then
        echo "Port $SSH_PORT" | tee -a /etc/ssh/sshd_config >/dev/null
    fi

    # 2. sshd_config.d (приоритет на современных системах)
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        echo "Port $SSH_PORT" | tee "$SSHPORT_CONF" >/dev/null
    fi

    # 3. Ubuntu 24+: портом рулит ssh.socket
    MIGRATION_OK=0
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        info "Обнаружен ssh.socket (Ubuntu 24+), правлю systemd unit..."
        mkdir -p /etc/systemd/system/ssh.socket.d
        cat > /etc/systemd/system/ssh.socket.d/override.conf <<SOCKET_EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${SSH_PORT}
ListenStream=[::]:${SSH_PORT}
SOCKET_EOF
        systemctl daemon-reload
        if systemctl restart ssh.socket && systemctl restart ssh.service; then
            MIGRATION_OK=1
        fi
    else
        systemctl daemon-reload 2>/dev/null || true
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            MIGRATION_OK=1
        fi
    fi

    if [[ $MIGRATION_OK -eq 1 ]]; then
        sleep 5
        if ss -tlnH 2>/dev/null | awk -v p="${SSH_PORT}" '{n=split($4,a,":"); if (a[n]==p) f=1} END{exit !f}'; then
            success "SSH теперь слушает порт ${SSH_PORT}."
            EFFECTIVE_SSH_PORT="$SSH_PORT"
        else
            MIGRATION_OK=0
            warn "SSH перезапустился, но не слушает ${SSH_PORT}. Откатываю..."
        fi
    fi

    if [[ $MIGRATION_OK -eq 0 ]]; then
        warn "Миграция SSH не удалась. Откатываю на ${CURRENT_SSH_PORT}..."
        mv "$SSHD_BACKUP" /etc/ssh/sshd_config
        rm -f "$SSHPORT_CONF" 2>/dev/null
        rm -rf /etc/systemd/system/ssh.socket.d 2>/dev/null
        systemctl daemon-reload 2>/dev/null || true
        systemctl restart ssh.socket 2>/dev/null || true
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        EFFECTIVE_SSH_PORT="$CURRENT_SSH_PORT"
        step_fail "2/10 SSH-миграция (откат, продолжаю на порту ${CURRENT_SSH_PORT})"
    fi
else
    success "SSH остаётся на порту ${CURRENT_SSH_PORT}."
fi

info "Сбрасываю старые правила UFW..."
ufw --force reset >/dev/null
info "Default политики: deny incoming, allow outgoing..."
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
if [[ -f /etc/default/ufw ]] && grep -q "^IPV6=yes" /etc/default/ufw; then
    sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw
fi
# По умолчанию открываем ТОЛЬКО SSH и порт ноды (порт ноды — для всех).
# Клиентский порт 443 откроется позже, на этапе установки selfsteal/ноды.
info "Открываю порты: SSH=${EFFECTIVE_SSH_PORT}/tcp, порт ноды=${NODE_PORT}/tcp (для всех)..."
ufw allow "${EFFECTIVE_SSH_PORT}"/tcp comment 'ssh' >/dev/null
ufw allow "${NODE_PORT}"/tcp comment 'app' >/dev/null
info "Включаю UFW..."
if echo "y" | ufw enable >/dev/null 2>&1; then
    success "UFW активирован, SSH доступен на порту ${EFFECTIVE_SSH_PORT}."
    step_ok "2/10 UFW config"
else
    step_fail "2/10 ufw enable"
fi

#===============================================================================
# ШАГ 3/10 — Fail2Ban
#===============================================================================
step "Шаг 3/10: Fail2Ban"
if ! command -v fail2ban-client >/dev/null 2>&1; then
    info "Устанавливаю Fail2Ban..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq fail2ban >/dev/null 2>&1 || true
else
    success "Fail2Ban уже установлен."
fi
if command -v fail2ban-client >/dev/null 2>&1; then
    F2B_LOGPATH="/var/log/auth.log"
    F2B_BACKEND="auto"
    if [[ ! -f "$F2B_LOGPATH" ]] && command -v journalctl >/dev/null 2>&1; then
        F2B_LOGPATH="SYSLOG"
        F2B_BACKEND="systemd"
    fi
    info "Пишу /etc/fail2ban/jail.local (bantime=1ч, maxretry=5, findtime=600с, port=${EFFECTIVE_SSH_PORT})..."
    tee /etc/fail2ban/jail.local >/dev/null <<JAIL
[DEFAULT]
bantime = 3600
findtime = 600s
maxretry = 5
backend = $F2B_BACKEND
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $EFFECTIVE_SSH_PORT
filter = sshd
logpath = $F2B_LOGPATH
JAIL
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
    sleep 1
    if systemctl is-active --quiet fail2ban; then
        success "Fail2Ban запущен, защищает порт ${EFFECTIVE_SSH_PORT}."
        step_ok "3/10 Fail2Ban"
    else
        step_fail "3/10 fail2ban service не стартовал"
    fi
else
    step_fail "3/10 fail2ban не установился"
fi

#===============================================================================
# ШАГ 4/10 — Kernel Hardening
#===============================================================================
step "Шаг 4/10: Kernel Hardening"
SYSCTL_HARDEN="$HARDEN_CONF"
info "Пишу $SYSCTL_HARDEN..."
tee "$SYSCTL_HARDEN" >/dev/null <<'SYSCTL_HARDEN_EOF'
# network / kernel security tuning
# --- SYN Flood Protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_max_syn_backlog = 65535
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 32768

# --- IP Spoofing & Network Attack Protection ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- TCP Tuning ---
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# --- Kernel Security ---
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.kptr_restrict = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.suid_dumpable = 0
SYSCTL_HARDEN_EOF
if sysctl -p "$SYSCTL_HARDEN" >/dev/null 2>&1; then
    success "Kernel Hardening применён."
    step_ok "4/10 Kernel Hardening"
else
    step_fail "4/10 sysctl -p hardening"
fi

#===============================================================================
# ШАГ 5/10 — Сеть, производительность и лимиты
#===============================================================================
step "Шаг 5/10: Сеть, производительность и лимиты"

# Congestion control: BBR. Родной для него qdisc — fq (cake намеренно НЕ берём:
# он режет пиковую скорость ради справедливости между клиентами).
modprobe tcp_bbr >/dev/null 2>&1 || true
# hashsize задаём ДО загрузки модуля (иначе применится только после ребута).
echo "nf_conntrack" > "/etc/modules-load.d/$(tok ct).conf"
echo "options nf_conntrack hashsize=262144" > "/etc/modprobe.d/$(tok ct).conf"
modprobe nf_conntrack >/dev/null 2>&1 || true

info "Пишу $BOOST_CONF (BBR + fq, буферы 32M, лимиты соединений, conntrack)..."
tee "$BOOST_CONF" >/dev/null <<EOF_NET
# network performance & scale tuning
# --- скорость / пропускная способность ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# --- масштаб: тысячи одновременных клиентов ---
fs.file-max = 2000000
net.ipv4.ip_local_port_range = 10000 65535
# Порты наших слушающих сервисов исключаем из эфемерного диапазона, чтобы
# исходящие соединения случайно не заняли их (иначе конфликт).
net.ipv4.ip_local_reserved_ports = ${EFFECTIVE_SSH_PORT},${NODE_PORT}
net.ipv4.tcp_max_tw_buckets = 1440000

# --- conntrack: не переполнять таблицу соединений при тысячах клиентов ---
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
EOF_NET

if sysctl -p "$BOOST_CONF" >/dev/null 2>&1; then
    success "Сеть настроена (BBR + fq, буферы 32M, лимиты соединений)."
    step_ok "5/10 Сеть и лимиты"
else
    warn "Часть параметров (conntrack) применится после перезагрузки — не критично."
    step_ok "5/10 Сеть и лимиты (частично)"
fi

# LimitNOFILE для docker.service: без этого нода упрётся в лимит дескрипторов
# под нагрузкой. Drop-in подхватится, когда Docker установят (на шаге ноды).
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf <<'DOCKER_LIMIT_EOF'
[Service]
LimitNOFILE=1048576
LimitNPROC=1048576
DOCKER_LIMIT_EOF
success "Лимит дескрипторов для Docker подготовлен (LimitNOFILE=1048576)."

#===============================================================================
# ШАГ 6/10 — Отключение IPv6
#===============================================================================
step "Шаг 6/10: Отключение IPv6"
if ! ip -4 addr show scope global 2>/dev/null | grep -q "inet "; then
    warn "У сервера нет глобального IPv4 — отключение IPv6 оборвёт доступ. Пропускаю."
    step_fail "6/10 IPv6 (пропущено: сервер, похоже, IPv6-only)"
else
    tee "$IPV6_CONF" >/dev/null <<'EOF_NO6'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF_NO6
    if sysctl -p "$IPV6_CONF" >/dev/null 2>&1; then
        success "IPv6 отключён."
        step_ok "6/10 IPv6 off"
    else
        step_fail "6/10 sysctl -p ipv6"
    fi
fi

#===============================================================================
# ШАГ 7/10 — Firewall: анти-флуд + ICMP
#===============================================================================
step "Шаг 7/10: Firewall — анти-флуд + ICMP"
BEFORE_RULES="/etc/ufw/before.rules"
FLOOD_MARK="$(tok fw)"
if [[ -f "$BEFORE_RULES" ]]; then
    cp "$BEFORE_RULES" "${BEFORE_RULES}.bak.$(tok fwbak).$(date +%s)"

    # 1) ICMP echo-request: rate-limit ВМЕСТО полного дропа. destination-unreachable
    #    (в т.ч. fragmentation-needed для PMTUD), time-exceeded и parameter-problem
    #    не трогаем — их блок ломает передачу крупных пакетов.
    if grep -q -- '-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT' "$BEFORE_RULES"; then
        sed -i 's|-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT|-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT\n-A ufw-before-input -p icmp --icmp-type echo-request -j DROP|' "$BEFORE_RULES"
    fi

    # 2) Анти-флуд блок в ufw-before-input: дроп INVALID и битых TCP-флагов (сканы)
    #    + per-IP лимит новых SYN на порт ноды. Идемпотентно (по маркеру).
    command -v python3 >/dev/null 2>&1 || apt-get install -y -qq python3 >/dev/null 2>&1 || true
    python3 - "$BEFORE_RULES" "$FLOOD_MARK" "$NODE_PORT" <<'PYEOF'
import sys, re
rules_file, mark, node_port = sys.argv[1], sys.argv[2], sys.argv[3]
begin = "# %s-flood-begin" % mark
end   = "# %s-flood-end" % mark
with open(rules_file) as f:
    content = f.read()
content = re.sub(r'\n' + re.escape(begin) + r'.*?' + re.escape(end) + r'\n', '\n', content, flags=re.DOTALL)
block = (
    "\n" + begin + "\n"
    "-A ufw-before-input -m conntrack --ctstate INVALID -j DROP\n"
    "-A ufw-before-input -p tcp --tcp-flags ALL NONE -j DROP\n"
    "-A ufw-before-input -p tcp --tcp-flags ALL ALL -j DROP\n"
    "-A ufw-before-input -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP\n"
    "-A ufw-before-input -p tcp --tcp-flags SYN,RST SYN,RST -j DROP\n"
    "-A ufw-before-input -p tcp --dport " + node_port + " --syn -m hashlimit "
    "--hashlimit-name synflood --hashlimit-mode srcip --hashlimit-above 30/sec "
    "--hashlimit-burst 60 -j DROP\n"
    + end + "\n"
)
i = content.rfind("COMMIT")
content = content[:i] + block + content[i:] if i != -1 else content + block
with open(rules_file, "w") as f:
    f.write(content)
print("OK")
PYEOF

    ufw reload >/dev/null 2>&1 || true
    success "Анти-флуд активен: дроп INVALID/битых флагов, лимит SYN на порт ноды, ICMP rate-limit."
    step_ok "7/10 Firewall анти-флуд"
else
    warn "$BEFORE_RULES не найден — пропуск."
    step_fail "7/10 before.rules не найден"
fi

#===============================================================================
# ШАГ 8/10 — Авто-обновления безопасности + системные журналы
#===============================================================================
step "Шаг 8/10: Авто-обновления безопасности + журналы"

# Авто-обновления: ставим ТОЛЬКО security-патчи, без авто-перезагрузки.
info "Настраиваю автоматические обновления безопасности..."
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq unattended-upgrades >/dev/null 2>&1 || true
if [[ -d /etc/apt/apt.conf.d ]]; then
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AU_EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AU_EOF
    cat > /etc/apt/apt.conf.d/52-unattended-local <<'AU_EOF2'
Unattended-Upgrade::Automatic-Reboot "false";
AU_EOF2
    success "Авто-обновления безопасности включены (без авто-ребута)."
else
    warn "Каталог /etc/apt/apt.conf.d не найден — пропуск авто-обновлений."
fi

# journald persistent: журналы переживают перезагрузку (нужно для разбора
# инцидентов), с лимитом размера чтобы не переполнить диск.
info "Включаю постоянное хранение системных журналов..."
mkdir -p /etc/systemd/journald.conf.d /var/log/journal
cat > "/etc/systemd/journald.conf.d/$(tok journal).conf" <<'JRN_EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
JRN_EOF
systemctl restart systemd-journald 2>/dev/null || true
success "journald: постоянное хранение включено (лимит 500M)."

step_ok "8/10 Авто-обновления + журналы"

#===============================================================================
# ШАГ 9/10 — Установка Remnanode
#===============================================================================
step "Шаг 9/10: Установка Remnanode"
if [[ $NODE_EXISTS -eq 1 ]]; then
    warn "Нода уже установлена (${NODE_EVIDENCE}) — установку пропускаю, второй экземпляр не ставлю."
    SETUP_DONE+=("9/10 Remnanode (уже установлена — пропущено)")
else
    node_ok=1
    while :; do
        # 1) Docker (официальный установщик get.docker.com)
        if ! command -v docker >/dev/null 2>&1; then
            info "Устанавливаю Docker (get.docker.com, может занять пару минут)..."
            curl -fsSL https://get.docker.com -o /tmp/_getdocker.sh 2>/dev/null && sh /tmp/_getdocker.sh >/dev/null 2>&1
            rm -f /tmp/_getdocker.sh
        fi
        if ! command -v docker >/dev/null 2>&1; then
            warn "Docker не установился."; node_ok=0; break
        fi
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable --now docker >/dev/null 2>&1 || true
        systemctl restart docker >/dev/null 2>&1 || true   # применить LimitNOFILE drop-in (шаг 5)
        if ! docker info >/dev/null 2>&1; then
            warn "Docker установлен, но демон не запущен."; node_ok=0; break
        fi
        success "Docker готов."

        # 2) docker-compose.yml (официальный формат + наши лимиты логов)
        info "Создаю /opt/remnanode/docker-compose.yml (образ remnawave/node:${NODE_VERSION})..."
        mkdir -p /opt/remnanode
        cat > /opt/remnanode/docker-compose.yml <<EOF
services:
  remnanode:
    image: remnawave/node:${NODE_VERSION}
    container_name: remnanode
    hostname: remnanode
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    logging:
      driver: json-file
      options:
        max-size: "30m"
        max-file: "5"
    environment:
      - NODE_PORT=${NODE_PORT}
      - SECRET_KEY="${SECRET_KEY}"
EOF
        chmod 0600 /opt/remnanode/docker-compose.yml

        # 3) Поднять контейнер и дождаться запуска
        info "Поднимаю контейнер ноды..."
        ( cd /opt/remnanode && docker compose up -d ) >/dev/null 2>&1 || true
        _w=0
        while [[ $_w -lt 120 ]]; do
            docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^remnanode$' && break
            sleep 3; _w=$((_w + 3))
        done
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^remnanode$'; then
            node_ok=1
        else
            warn "Контейнер remnanode не поднялся за ${_w}с (логи: cd /opt/remnanode && docker compose logs)."
            node_ok=0
        fi
        break
    done
    if [[ $node_ok -eq 1 ]]; then
        success "Нода remnanode запущена (remnawave/node:${NODE_VERSION}, порт ${NODE_PORT})."
        step_ok "9/10 Remnanode"
    else
        step_fail "9/10 Remnanode (не установилась — см. сообщения выше)"
    fi
fi

#===============================================================================
# ШАГ 10/10 — Docker + UFW Professional Fix (авто)
#===============================================================================
# Docker по умолчанию пишет правила напрямую в iptables в обход UFW, из-за чего
# опубликованные порты контейнеров открыты, даже если UFW стоит на DENY. Этот
# фикс направляет трафик контейнеров через DOCKER-USER → ufw-user-forward.
step "Шаг 10/10: Docker + UFW Fix"
apply_docker_ufw_fix() {
    if ! command -v python3 >/dev/null 2>&1; then
        info "Устанавливаю python3 (нужен для правки after.rules)..."
        apt-get install -y -qq python3 >/dev/null 2>&1 || true
    fi

    # 1. Разрешаем Docker-подсети
    ufw allow from 172.16.0.0/12 comment 'Docker networks' >/dev/null 2>&1 || true
    ufw allow from 192.168.0.0/16 comment 'Docker bridge' >/dev/null 2>&1 || true

    local after_rules="/etc/ufw/after.rules"
    local marker_start="# ${DOCKER_MARK}-begin"
    local marker_end="# ${DOCKER_MARK}-end"
    if [[ ! -f "$after_rules" ]]; then
        warn "$after_rules не найден — пропускаю Docker UFW Fix."
        return 1
    fi

    local iface
    iface=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1)
    iface=${iface:-eth0}

    # Если блок уже есть — удаляем старую версию перед вставкой свежей
    if grep -q "$marker_start" "$after_rules"; then
        info "Обновляю существующий блок Docker UFW Fix..."
        python3 - <<PYEOF
import re
with open('${after_rules}', 'r') as f:
    content = f.read()
content = re.sub(r'\n${marker_start}.*?${marker_end}\n', '', content, flags=re.DOTALL)
with open('${after_rules}', 'w') as f:
    f.write(content)
PYEOF
    fi

    # Вставляем блок перед последним COMMIT
    python3 - "$after_rules" "$marker_start" "$marker_end" "$iface" <<'PYEOF'
import sys
rules_file, marker_s, marker_e, iface = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(rules_file, 'r') as f:
    content = f.read()

docker_block = f"""
{marker_s}
# Эти правила заставляют Docker-трафик проходить через фильтрацию UFW.
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -i {iface} -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN
-A DOCKER-USER -i {iface} -j ufw-user-forward
-A DOCKER-USER -i {iface} -j DROP
-A DOCKER-USER -j RETURN
{marker_e}
"""

if 'COMMIT' in content:
    idx = content.rfind('COMMIT')
    content = content[:idx] + docker_block + content[idx:]
else:
    content += docker_block

with open(rules_file, 'w') as f:
    f.write(content)
print('OK')
PYEOF
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        warn "Не удалось вставить блок в after.rules."
        return 1
    fi
    success "Блок Docker UFW Fix добавлен в ${after_rules} (интерфейс: ${iface})."

    # Синхронизируем route-правила только если Docker уже установлен
    if command -v docker >/dev/null 2>&1; then
        info "Синхронизирую порты Docker-контейнеров с UFW route..."
        local docker_ports ufw_in_ports p
        docker_ports=$(docker ps --format "{{.Ports}}" 2>/dev/null | grep -oE '0.0.0.0:[0-9]+' | cut -d: -f2 | sort -u)
        ufw_in_ports=$(ufw status | grep "ALLOW" | grep -v "(v6)" | awk '{print $1}' | grep -oE '^[0-9]+' | sort -u)
        for p in $ufw_in_ports; do
            if echo "$docker_ports" | grep -qx "$p"; then
                ufw route allow "$p" >/dev/null 2>&1 || true
            else
                ufw route delete allow "$p" >/dev/null 2>&1 || true
            fi
        done
    else
        info "Docker ещё не установлен — правила after.rules готовы, порты синхронизируются после установки ноды."
    fi
    ufw reload >/dev/null 2>&1 || true
    return 0
}

if apply_docker_ufw_fix; then
    success "Docker + UFW Fix применён."
    step_ok "10/10 Docker UFW Fix"
else
    step_fail "10/10 Docker UFW Fix"
fi

#===============================================================================
# Установка команды управления nodectl
#===============================================================================
step "Установка команды управления nodectl..."

cat > /usr/local/bin/nodectl <<'NODECTL_EOF'
#!/usr/bin/env bash
# nodectl — управление безопасностью сервера-ноды
set -uo pipefail

G='\033[0;32m'; B='\033[0;34m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[0;36m'; GR='\033[0;90m'; N='\033[0m'

# Те же обфусцированные имена файлов, что создал установщик (детерминированы от machine-id).
_SEED="$(cat /etc/machine-id 2>/dev/null || hostname 2>/dev/null || echo seed)"
tok() { printf '%s' "${_SEED}:$1" | sha256sum | cut -c1-12; }
IPV6_CONF="/etc/sysctl.d/98-$(tok ipv6).conf"
BEFORE_RULES="/etc/ufw/before.rules"

# Geoblock (только SSH; RU/IR НЕ включаем — это целевая аудитория VPN).
GEO_SET="geoblock4"
GEO_SAVE="/etc/$(tok geo).ipset"
GEO_COUNTRIES="/etc/$(tok geo).countries"
GEO_RESTORE="/usr/local/bin/$(tok georst)"
GEO_SERVICE="/etc/systemd/system/$(tok geosvc).service"
GEO_MARK="$(tok geomark)"
GEO_PRESET="CN,VN,IN,ID,BD,NG,PK,BR,EG,TH,MM,KH,LA"

# SYNPROXY (защита от SYN-флуда на порту ноды).
NODE_PORT_FILE="/etc/$(tok np).port"
SYN_MARK="$(tok syn)"
SYN_SYSCTL="/etc/sysctl.d/99-$(tok synp).conf"

# Кастомный Xray-core: бинарник на хосте монтируется поверх зашитого в образ.
XRAY_BIN="/opt/remnanode/xray"
XRAY_MARK="$(tok xray)"
NODE_COMPOSE="/opt/remnanode/docker-compose.yml"

need_root() { [[ $EUID -eq 0 ]] || { echo -e "${R}Запустите от root (sudo nodectl).${N}"; exit 1; }; }
pause() { echo ""; read -rp "$(echo -e "${GR}Enter — назад...${N}")" _ || true; }

# Единый промпт выбора пункта (с пустой строкой-отступом сверху) и чистый заголовок экрана.
PROMPT="$(echo -ne "\n${C}Выберите пункт меню:${N} ")"
hdr() { clear; echo ""; echo -e "  ${C}$1${N}"; echo -e "  ${GR}────────────────────────────────${N}"; echo ""; }

show_status() {
    echo ""
    echo -e "  ${C}Статус сервера${N}"
    echo -e "  ${GR}────────────────────────────────${N}"
    local s st
    for s in ufw fail2ban; do
        if systemctl is-active --quiet "$s" 2>/dev/null; then st="${G}активен${N}"; else st="${R}не активен${N}"; fi
        printf "  %-20s %b\n" "$s" "$st"
    done
    if [[ -f /opt/remnanode/docker-compose.yml ]] || docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^remnanode'; then
        printf "  %-20s %b\n" "remnanode" "${G}установлена${N}"
    else
        printf "  %-20s %b\n" "remnanode" "${GR}не установлена${N}"
    fi
    echo ""
    echo -e "${C}Сеть / ядро:${N}"
    printf "  %-24s %s\n" "congestion control" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    printf "  %-24s %s\n" "default qdisc" "$(sysctl -n net.core.default_qdisc 2>/dev/null)"
    printf "  %-24s %s\n" "somaxconn" "$(sysctl -n net.core.somaxconn 2>/dev/null)"
    printf "  %-24s %s\n" "nf_conntrack_max" "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '-')"
    if sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q 1; then
        printf "  %-24s %b\n" "IPv6" "${Y}отключён${N}"
    else
        printf "  %-24s %b\n" "IPv6" "${G}включён${N}"
    fi
    if grep -q 'icmp-type echo-request -j DROP' "$BEFORE_RULES" 2>/dev/null; then
        printf "  %-24s %b\n" "ICMP ping" "${Y}ограничен${N}"
    else
        printf "  %-24s %b\n" "ICMP ping" "${G}разрешён${N}"
    fi
    if ipset list "$GEO_SET" -terse &>/dev/null; then
        printf "  %-24s %b\n" "геоблок SSH" "${G}включён${N}"
    else
        printf "  %-24s %b\n" "геоблок SSH" "${GR}выключен${N}"
    fi
    if _syn_enabled; then
        printf "  %-24s %b\n" "SYNPROXY" "${G}включён${N}"
    else
        printf "  %-24s %b\n" "SYNPROXY" "${GR}выключен${N}"
    fi
    if [[ -f "$NODE_COMPOSE" ]]; then
        if _xray_custom_on; then
            printf "  %-24s %b\n" "Xray-core" "${Y}кастомный${N}"
        else
            printf "  %-24s %b\n" "Xray-core" "${G}дефолт${N}"
        fi
    fi
    echo ""
}

menu_fail2ban() {
    command -v fail2ban-client >/dev/null 2>&1 || { clear; echo ""; echo -e "${R}fail2ban не установлен.${N}"; pause; return; }
    local a ip
    while true; do
        hdr "Fail2Ban — баны SSH"
        fail2ban-client status sshd 2>/dev/null || echo "  джейл sshd не найден"
        echo ""
        echo "  1) Разбанить IP"
        echo ""
        echo "  0) Назад"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            1) echo ""; read -rp "  IP для разбана: " ip || continue
               if [[ -z "${ip:-}" ]]; then
                   echo -e "${Y}IP не введён.${N}"
               elif fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1; then
                   echo -e "${G}${ip} разбанен.${N}"
               else
                   echo -e "${R}Не удалось разбанить ${ip} (не забанен или неверный формат).${N}"
               fi
               pause ;;
            0|q|"") return ;;
            *) echo -e "${Y}Неверный выбор.${N}"; sleep 1 ;;
        esac
    done
}

toggle_ipv6() {
    clear; echo ""
    if sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q 1; then
        printf 'net.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv6.conf.default.disable_ipv6 = 0\n' > "$IPV6_CONF"
        sysctl -p "$IPV6_CONF" >/dev/null 2>&1
        # Вернуть IPv6 под фаервол UFW (иначе IPv6 окажется без защиты).
        sed -i 's/^IPV6=no/IPV6=yes/' /etc/default/ufw 2>/dev/null || true
        ufw reload >/dev/null 2>&1 || true
        echo -e "${G}IPv6 включён и фаерволится UFW.${N} (для полного эффекта может понадобиться перезагрузка)"
    else
        # Не отключаем IPv6, если у сервера нет глобального IPv4 — иначе оборвём SSH.
        if ! ip -4 addr show scope global 2>/dev/null | grep -q "inet "; then
            echo -e "${R}У сервера нет глобального IPv4 — отключение IPv6 оборвёт доступ по SSH. Отменено.${N}"
            return
        fi
        local c
        read -rp "$(echo -e "${Y}Точно отключить IPv6? Это может оборвать доступ [y/N]: ${N}")" c || return
        [[ "${c:-}" =~ ^[yYдД] ]] || { echo -e "${GR}Отменено.${N}"; return; }
        printf 'net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\n' > "$IPV6_CONF"
        sysctl -p "$IPV6_CONF" >/dev/null 2>&1
        echo -e "${Y}IPv6 отключён.${N}"
    fi
}

toggle_icmp() {
    clear; echo ""
    [[ -f "$BEFORE_RULES" ]] || { echo -e "${R}$BEFORE_RULES не найден.${N}"; return; }
    if grep -q 'icmp-type echo-request -j DROP' "$BEFORE_RULES"; then
        sed -i '/-A ufw-before-input -p icmp --icmp-type echo-request -m limit .*-j ACCEPT/d' "$BEFORE_RULES"
        sed -i 's|-A ufw-before-input -p icmp --icmp-type echo-request -j DROP|-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT|' "$BEFORE_RULES"
        ufw reload >/dev/null 2>&1
        echo -e "${G}Пинг разрешён.${N}"
    else
        sed -i 's|-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT|-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT\n-A ufw-before-input -p icmp --icmp-type echo-request -j DROP|' "$BEFORE_RULES"
        ufw reload >/dev/null 2>&1
        echo -e "${Y}Пинг ограничен (rate-limit).${N}"
    fi
}

_geo_ssh_port() {
    local p
    p=$(grep -h "^Port " /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1 | awk '{print $2}')
    [[ -z "$p" ]] && p=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$p" ]] && p=$(ss -tlnp 2>/dev/null | grep -E "sshd|ssh" | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)
    echo "${p:-22}"
}

_geo_build() {
    local countries="$1"
    if ! command -v ipset >/dev/null 2>&1; then
        apt-get install -y -qq ipset >/dev/null 2>&1 || { echo -e "${R}Не удалось установить ipset.${N}"; return 1; }
    fi
    local tmp restore temp_set cc n total=0
    tmp=$(mktemp -d); restore="$tmp/restore.txt"; temp_set="${GEO_SET}_t"
    echo "create $temp_set hash:net hashsize 65536 maxelem 500000 -exist" > "$restore"
    IFS=',' read -ra arr <<< "$countries"
    for cc in "${arr[@]}"; do
        cc=$(echo "$cc" | tr 'A-Z' 'a-z' | tr -d ' ')
        [[ -z "$cc" ]] && continue
        local zf="$tmp/$cc.zone"
        curl -fsSL --max-time 20 "https://www.ipdeny.com/ipblocks/data/aggregated/${cc}-aggregated.zone" -o "$zf" 2>/dev/null \
          || curl -fsSL --max-time 20 "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/${cc}/ipv4-aggregated.txt" -o "$zf" 2>/dev/null \
          || curl -fsSL --max-time 20 "https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone" -o "$zf" 2>/dev/null || true
        if [[ -s "$zf" ]]; then
            n=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$zf" 2>/dev/null); n=${n:-0}
            awk -v s="$temp_set" '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/{print "add " s " " $1 " -exist"}' "$zf" >> "$restore"
            total=$((total + n)); echo -e "  ${GR}${cc}: ${n} подсетей${N}"
        else
            echo -e "  ${Y}${cc}: не скачалось, пропуск${N}"
        fi
    done
    if [[ $total -eq 0 ]]; then echo -e "${R}Ни одной подсети не загружено.${N}"; rm -rf "$tmp"; return 1; fi
    ipset destroy "$temp_set" 2>/dev/null || true
    if ipset restore < "$restore"; then
        ipset list "$GEO_SET" &>/dev/null || ipset create "$GEO_SET" hash:net hashsize 65536 maxelem 500000
        ipset swap "$temp_set" "$GEO_SET"; ipset destroy "$temp_set" 2>/dev/null || true
        mkdir -p "$(dirname "$GEO_SAVE")"; ipset save "$GEO_SET" > "$GEO_SAVE"
        echo "$countries" > "$GEO_COUNTRIES"
        echo -e "${G}Загружено ${total} подсетей.${N}"; rm -rf "$tmp"; return 0
    fi
    echo -e "${R}ipset restore не удался.${N}"; ipset destroy "$temp_set" 2>/dev/null || true; rm -rf "$tmp"; return 1
}

_geo_del_rule() {
    [[ -f "$BEFORE_RULES" ]] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    python3 - "$BEFORE_RULES" "$GEO_MARK" <<'PY'
import sys, re
f, mark = sys.argv[1], sys.argv[2]
begin="# %s-geo-begin"%mark; end="# %s-geo-end"%mark
c=open(f).read()
c=re.sub(r'\n'+re.escape(begin)+r'.*?'+re.escape(end)+r'\n','\n',c,flags=re.DOTALL)
open(f,'w').write(c)
PY
}

_geo_add_rule() {
    [[ -f "$BEFORE_RULES" ]] || { echo -e "${R}$BEFORE_RULES не найден.${N}"; return 1; }
    command -v python3 >/dev/null 2>&1 || apt-get install -y -qq python3 >/dev/null 2>&1 || true
    local ssh_port; ssh_port=$(_geo_ssh_port)
    _geo_del_rule
    python3 - "$BEFORE_RULES" "$GEO_MARK" "$GEO_SET" "$ssh_port" <<'PY'
import sys, re
f, mark, s, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
begin="# %s-geo-begin"%mark; end="# %s-geo-end"%mark
c=open(f).read()
c=re.sub(r'\n'+re.escape(begin)+r'.*?'+re.escape(end)+r'\n','\n',c,flags=re.DOTALL)
block="\n%s\n-A ufw-before-input -p tcp --dport %s -m set --match-set %s src -j DROP\n%s\n"%(begin,port,s,end)
i=c.rfind("COMMIT")
c=c[:i]+block+c[i:] if i!=-1 else c+block
open(f,'w').write(c)
PY
    ufw reload >/dev/null 2>&1
}

_geo_make_service() {
    cat > "$GEO_RESTORE" <<RS
#!/usr/bin/env bash
# Набор ВСЕГДА должен существовать (хотя бы пустой), иначе правило UFW с
# --match-set сломает загрузку всего фаервола на буте и запрёт доступ.
ipset create $GEO_SET hash:net hashsize 65536 maxelem 500000 -exist
if [ -f "$GEO_SAVE" ]; then
    ipset flush $GEO_SET 2>/dev/null || true
    ipset restore -exist < "$GEO_SAVE" 2>/dev/null || true
fi
RS
    chmod 0755 "$GEO_RESTORE"
    cat > "$GEO_SERVICE" <<SV
[Unit]
Description=restore ip set
DefaultDependencies=no
Before=ufw.service network-pre.target
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$GEO_RESTORE

[Install]
WantedBy=multi-user.target
SV
    systemctl daemon-reload
    systemctl enable "$(basename "$GEO_SERVICE")" >/dev/null 2>&1 || true
}

geo_status() {
    if ipset list "$GEO_SET" -terse &>/dev/null; then
        local n; n=$(ipset list "$GEO_SET" -terse 2>/dev/null | grep -Fi "Number of entries" | awk '{print $NF}')
        echo -e "  Геоблок: ${G}включён${N} (${n:-0} подсетей, только SSH-порт $(_geo_ssh_port))"
        [[ -f "$GEO_COUNTRIES" ]] && echo -e "  Страны:  ${GR}$(cat "$GEO_COUNTRIES")${N}"
    else
        echo -e "  Геоблок: ${GR}выключен${N}"
    fi
}

geo_enable() {
    local countries="$1"
    echo -e "${C}Скачиваю списки IP и строю ipset (может занять минуту)...${N}"
    _geo_build "$countries" || return 1
    _geo_add_rule || return 1
    _geo_make_service
    echo -e "${G}Геоблокировка включена (только SSH-порт $(_geo_ssh_port)).${N}"
}

geo_disable() {
    _geo_del_rule; ufw reload >/dev/null 2>&1
    # Уничтожать ipset можно ТОЛЬКО если правило реально удалено из before.rules,
    # иначе ссылка на несуществующий set сломает следующий ufw reload/загрузку.
    if grep -q "match-set ${GEO_SET}" "$BEFORE_RULES" 2>/dev/null; then
        echo -e "${R}Правило геоблока не удалилось из before.rules — ipset НЕ трогаю (иначе сломается фаервол). Проверьте вручную.${N}"
        return 1
    fi
    ipset destroy "$GEO_SET" 2>/dev/null || true
    systemctl disable "$(basename "$GEO_SERVICE")" >/dev/null 2>&1 || true
    rm -f "$GEO_SERVICE" "$GEO_RESTORE" "$GEO_SAVE" "$GEO_COUNTRIES"
    systemctl daemon-reload
    echo -e "${Y}Геоблокировка отключена.${N}"
}

# Пере-применить правило геоблока (напр. после ufw reset установщиком). Тихо.
geo_reapply() {
    [[ -f "$GEO_COUNTRIES" ]] || return 0
    if ! ipset list "$GEO_SET" &>/dev/null; then
        [[ -f "$GEO_SAVE" ]] && ipset restore -exist < "$GEO_SAVE" 2>/dev/null || true
    fi
    _geo_add_rule
}

menu_geoblock() {
    local a cc
    while true; do
        hdr "Геоблокировка (только SSH)"
        geo_status
        echo ""
        echo -e "  ${GR}Применяется ТОЛЬКО к SSH-порту. Клиентский 443 не трогаем,${N}"
        echo -e "  ${GR}иначе отрежете своих пользователей из Ирана/России/Китая.${N}"
        echo ""
        echo "  1) Включить (рекоменд. набор, без RU/IR)"
        echo "  2) Включить со своим списком стран"
        echo "  3) Обновить базу IP"
        echo "  4) Выключить"
        echo ""
        echo "  0) Назад"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            1) geo_enable "$GEO_PRESET"; pause ;;
            2) echo ""; read -rp "  Коды стран через запятую (напр. CN,VN,IN): " cc || continue
               if [[ -n "${cc:-}" ]]; then geo_enable "$cc"; else echo -e "${Y}Ничего не введено.${N}"; fi
               pause ;;
            3) if [[ -f "$GEO_COUNTRIES" ]]; then geo_enable "$(cat "$GEO_COUNTRIES")"; else echo -e "${Y}Сначала включите геоблок.${N}"; fi
               pause ;;
            4) geo_disable; pause ;;
            0|q|"") return ;;
            *) echo -e "${Y}Неверный выбор.${N}"; sleep 1 ;;
        esac
    done
}

_syn_port() { [[ -r "$NODE_PORT_FILE" ]] && cat "$NODE_PORT_FILE" || echo ""; }

_syn_available() {
    modprobe nf_synproxy_core 2>/dev/null || true
    modprobe xt_SYNPROXY 2>/dev/null || true
    iptables -t filter -N nodectl_syntest 2>/dev/null || iptables -t filter -F nodectl_syntest 2>/dev/null || true
    local ok=1
    iptables -t filter -A nodectl_syntest -p tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 2>/dev/null || ok=0
    iptables -t filter -F nodectl_syntest 2>/dev/null || true
    iptables -t filter -X nodectl_syntest 2>/dev/null || true
    [[ $ok -eq 1 ]]
}

_syn_enabled() { grep -q "${SYN_MARK}-synflt-begin" "$BEFORE_RULES" 2>/dev/null; }

_syn_apply() {
    python3 - "$BEFORE_RULES" "$SYN_MARK" "$1" <<'PY'
import sys, re
f, mark, port = sys.argv[1], sys.argv[2], sys.argv[3]
rb="# %s-synraw-begin"%mark; rz="# %s-synraw-end"%mark
fb="# %s-synflt-begin"%mark; fz="# %s-synflt-end"%mark
c=open(f).read()
for a,z in ((rb,rz),(fb,fz)):
    c=re.sub(r'\n?'+re.escape(a)+r'.*?'+re.escape(z)+r'\n?','\n',c,flags=re.DOTALL)
raw="%s\n-A PREROUTING -p tcp --dport %s --syn -j CT --notrack\n%s"%(rb,port,rz)
m=re.search(r'^\*raw\b', c, re.M)
if m:
    j=c.find('\nCOMMIT', m.end()); c=c[:j]+"\n"+raw+c[j:]
else:
    tbl="*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"+raw+"\nCOMMIT\n\n"
    fi=c.find('*filter'); c=c[:fi]+tbl+c[fi:]
flt=("%s\n-A ufw-before-input -p tcp --dport %s -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460\n-A ufw-before-input -p tcp --dport %s -m conntrack --ctstate INVALID -j DROP\n%s")%(fb,port,port,fz)
anchor="-A ufw-before-input -i lo -j ACCEPT"
ai=c.find(anchor)
if ai!=-1:
    ins=c.find('\n',ai)+1; c=c[:ins]+flt+"\n"+c[ins:]
else:
    fm=re.search(r'^\*filter\b', c, re.M); k=c.find('\nCOMMIT', fm.end()); c=c[:k]+"\n"+flt+c[k:]
open(f,'w').write(c); print("OK")
PY
}

_syn_remove() {
    [[ -f "$BEFORE_RULES" ]] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    python3 - "$BEFORE_RULES" "$SYN_MARK" <<'PY'
import sys, re
f, mark = sys.argv[1], sys.argv[2]
c=open(f).read()
for a,z in (("# %s-synraw-begin"%mark,"# %s-synraw-end"%mark),("# %s-synflt-begin"%mark,"# %s-synflt-end"%mark)):
    c=re.sub(r'\n?'+re.escape(a)+r'.*?'+re.escape(z)+r'\n?','\n',c,flags=re.DOTALL)
open(f,'w').write(c); print("OK")
PY
}

synproxy_enable() {
    local port="$1"
    _syn_available || { echo -e "${R}Ядро не поддерживает SYNPROXY (нет xt_SYNPROXY). Отмена.${N}"; return 1; }
    [[ -f "$BEFORE_RULES" ]] || { echo -e "${R}$BEFORE_RULES не найден.${N}"; return 1; }
    command -v python3 >/dev/null 2>&1 || { echo -e "${R}Нужен python3.${N}"; return 1; }
    printf 'net.netfilter.nf_conntrack_tcp_loose = 0\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_timestamps = 1\n' > "$SYN_SYSCTL"
    sysctl -p "$SYN_SYSCTL" >/dev/null 2>&1
    local bak; bak="${BEFORE_RULES}.synbak.$$"
    cp "$BEFORE_RULES" "$bak"
    _syn_apply "$port"
    if ufw reload >/dev/null 2>&1; then
        rm -f "$bak"
        if iptables -t raw -S 2>/dev/null | grep -q -- "--dport ${port} .*NOTRACK"; then
            echo -e "${G}SYNPROXY включён на порту ${port}.${N}"
        else
            echo -e "${Y}Правила записаны, но raw-notrack не виден в iptables — возможно, UFW не загрузил таблицу *raw. SYNPROXY может быть неактивен (проверьте: iptables -t raw -S).${N}"
        fi
    else
        cp "$bak" "$BEFORE_RULES"; rm -f "$bak"; ufw reload >/dev/null 2>&1
        rm -f "$SYN_SYSCTL"; sysctl -w net.netfilter.nf_conntrack_tcp_loose=1 >/dev/null 2>&1 || true
        echo -e "${R}ufw reload не прошёл — откатил before.rules, SYNPROXY НЕ включён.${N}"; return 1
    fi
}

synproxy_disable() {
    _syn_remove
    rm -f "$SYN_SYSCTL"
    sysctl -w net.netfilter.nf_conntrack_tcp_loose=1 >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1
    echo -e "${Y}SYNPROXY выключен.${N}"
}

toggle_synproxy() {
    local port a
    port=$(_syn_port)
    if [[ -z "$port" ]]; then
        clear; echo ""; read -rp "  Порт для защиты SYNPROXY (порт ноды): " port || return
    fi
    [[ "$port" =~ ^[0-9]+$ ]] || { clear; echo ""; echo -e "${R}Некорректный порт.${N}"; pause; return; }
    while true; do
        hdr "SYNPROXY — анти-SYN-флуд (порт ${port})"
        if _syn_enabled; then
            echo -e "  Статус: ${G}включён${N}"
            echo ""
            echo "  1) Выключить"
        else
            echo -e "  Статус: ${GR}выключен${N}"
            echo -e "  ${GR}Тяжёлая защита от SYN-флуда сверх syncookies. Требует поддержки ядра.${N}"
            echo ""
            echo "  1) Включить"
        fi
        echo ""
        echo "  0) Назад"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            1) if _syn_enabled; then synproxy_disable; else synproxy_enable "$port"; fi; pause ;;
            0|q|"") return ;;
            *) echo -e "${Y}Неверный выбор.${N}"; sleep 1 ;;
        esac
    done
}

# ---------- Psiphon (обход RU-метки IP, чтобы работал Gemini) ----------
PSI_URL="https://raw.githubusercontent.com/Chara-Freedom/vps-psiphon/main/psiphon_install.sh"

psi_install() {
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        echo -e "${R}Нужен работающий Docker — сначала установите ноду (Docker ставится вместе с ней).${N}"
        return 1
    fi
    echo -e "${C}Скачиваю и ставлю Psiphon (выход через Германию, SOCKS 127.0.0.1:1080)...${N}"
    local t; t=$(mktemp)
    if curl -fsSL "$PSI_URL" -o "$t"; then
        bash "$t" --region DE --bind-loopback --socks-port 1080
        rm -f "$t"
        echo -e "${G}Psiphon установлен.${N} Теперь добавьте outbound+routing в панель (пункт 3 меню)."
    else
        rm -f "$t"; echo -e "${R}Не удалось скачать установщик Psiphon.${N}"
    fi
}

psi_show_xray() {
    cat <<'XRAY'
--- Добавьте это в конфиг Xray на панели Remnawave ---

1) OUTBOUND (в массив "outbounds"):
{
  "tag": "psiphon-out",
  "protocol": "socks",
  "settings": { "servers": [ { "address": "127.0.0.1", "port": 1080 } ] }
}

2) ROUTING-ПРАВИЛО (в "routing" -> "rules"; ТОЛЬКО домены Gemini — не заворачивайте всё!):
{
  "type": "field",
  "outboundTag": "psiphon-out",
  "domain": [
    "domain:generativelanguage.googleapis.com",
    "domain:gemini.google.com",
    "domain:aistudio.google.com"
  ]
}
XRAY
}

menu_psiphon() {
    local a r
    while true; do
        hdr "Psiphon — обход RU-метки IP (для Gemini)"
        if command -v vps-psiphon >/dev/null 2>&1; then
            echo -e "  Статус: ${G}установлен${N}"
            vps-psiphon status 2>/dev/null | head -n 20
        else
            echo -e "  Статус: ${GR}не установлен${N}"
        fi
        echo ""
        echo -e "  ${GR}Локальный SOCKS5 127.0.0.1:1080. Чтобы Gemini пошёл через него,${N}"
        echo -e "  ${GR}добавьте outbound+routing в конфиг Xray на панели (пункт 3).${N}"
        echo ""
        echo "  1) Установить (выход через Германию)"
        echo "  2) Сменить страну выхода"
        echo "  3) Показать outbound+routing для панели"
        echo "  4) Логи Psiphon"
        echo "  5) Удалить"
        echo ""
        echo "  0) Назад"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            1) psi_install; pause ;;
            2) if command -v vps-psiphon >/dev/null 2>&1; then
                   echo ""; read -rp "  Код страны (DE, NL, US, auto): " r || continue
                   if [[ -n "${r:-}" ]]; then vps-psiphon region "$r"; else echo -e "${Y}Ничего не введено.${N}"; fi
               else echo -e "${Y}Сначала установите Psiphon.${N}"; fi
               pause ;;
            3) psi_show_xray; pause ;;
            4) if command -v vps-psiphon >/dev/null 2>&1; then vps-psiphon logs 50; else echo -e "${Y}Не установлен.${N}"; fi; pause ;;
            5) if command -v vps-psiphon >/dev/null 2>&1; then vps-psiphon uninstall; else echo -e "${Y}Не установлен.${N}"; fi; pause ;;
            0|q|"") return ;;
            *) echo -e "${Y}Неверный выбор.${N}"; sleep 1 ;;
        esac
    done
}

# ---------- Selfsteal (маскировка Reality, обёртка скрипта DigneZzZ) ----------
SS_URL="https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh"

ss_install() {
    local mode="$1"
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        echo -e "${R}Нужен работающий Docker — сначала установите ноду.${N}"; return 1
    fi
    local domain
    read -rp "Домен для Reality (напр. reality.example.com): " domain || return
    [[ -n "${domain:-}" ]] || { echo -e "${R}Домен обязателен.${N}"; return 1; }
    echo -e "${GR}Открываю порты 443 (Reality) и 80 (ACME)...${N}"
    ufw allow 443/tcp comment 'reality' >/dev/null 2>&1 || true
    ufw allow 80/tcp comment 'acme' >/dev/null 2>&1 || true
    [[ "$mode" == "nginx" ]] && ufw allow 8443/tcp comment 'acme-alpn' >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1 || true
    echo -e "${GR}Свой серт из certwarden при желании: добавьте --ssl-cert/--ssl-key к команде selfsteal вручную.${N}"
    local t; t=$(mktemp)
    if ! curl -fLs "$SS_URL" -o "$t"; then rm -f "$t"; echo -e "${R}Не удалось скачать selfsteal.sh${N}"; return 1; fi
    if [[ "$mode" == "nginx" ]]; then
        bash "$t" @ --nginx --tcp --force --domain "$domain" install
    else
        bash "$t" @ --force --domain "$domain" install
    fi
    rm -f "$t"
    echo -e "${G}Готово.${N} Дальше добавьте конфиг Xray Reality в панель (пункт 6)."
}

ss_show_xray() {
    cat <<'SSX'
--- Конфиг Xray Reality для панели Remnawave ---
inbound VLESS + Reality, dest = 127.0.0.1:9443 (Caddy/Nginx-TCP), xver = 1:
{
  "tag": "VLESS_REALITY",
  "port": 443,
  "protocol": "vless",
  "settings": { "clients": [], "decryption": "none" },
  "streamSettings": {
    "network": "raw",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "xver": 1,
      "target": "127.0.0.1:9443",
      "spiderX": "/",
      "shortIds": [""],
      "privateKey": "ВАШ_PRIVATE_KEY",
      "serverNames": ["ВАШ_ДОМЕН"]
    }
  }
}
В панели укажите SNI и Host = serverNames (ваш домен). Ключи Reality — ваши.
SSX
}

menu_selfsteal() {
    local a
    while true; do
        hdr "Selfsteal — маскировка Reality"
        if command -v selfsteal >/dev/null 2>&1; then
            echo -e "  Статус: ${G}установлен${N}"
        else
            echo -e "  Статус: ${GR}не установлен${N}"
        fi
        echo -e "  ${GR}Веб-сервер-обманка для Reality; порт 443 остаётся за Xray.${N}"
        echo ""
        echo "  1) Установить (Caddy — проще)"
        echo "  2) Установить (Nginx — тише под пробингом РКН)"
        echo "  3) Статус"
        echo "  4) Логи"
        echo "  5) Перевыпустить сертификат"
        echo "  6) Показать конфиг Xray для панели"
        echo "  7) Удалить"
        echo ""
        echo "  0) Назад"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            1) ss_install caddy; pause ;;
            2) ss_install nginx; pause ;;
            3) if command -v selfsteal >/dev/null 2>&1; then selfsteal status; else echo -e "${Y}Не установлен.${N}"; fi; pause ;;
            4) if command -v selfsteal >/dev/null 2>&1; then selfsteal logs; else echo -e "${Y}Не установлен.${N}"; fi; pause ;;
            5) if command -v selfsteal >/dev/null 2>&1; then selfsteal renew-ssl; else echo -e "${Y}Не установлен.${N}"; fi; pause ;;
            6) ss_show_xray; pause ;;
            7) if command -v selfsteal >/dev/null 2>&1; then selfsteal uninstall; else echo -e "${Y}Не установлен.${N}"; fi; pause ;;
            0|q|"") return ;;
            *) echo -e "${Y}Неверный выбор.${N}"; sleep 1 ;;
        esac
    done
}

# ---------- Кастомный Xray-core ----------
_xray_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "64" ;;
        aarch64|arm64|armv8*) echo "arm64-v8a" ;;
        armv7*|armv7l) echo "arm32-v7a" ;;
        *) echo "" ;;
    esac
}
_xray_cver() { docker exec remnanode xray version 2>/dev/null | head -1 | awk '{print $2}'; }
_xray_custom_on() { grep -q "${XRAY_MARK}-xraybegin" "$NODE_COMPOSE" 2>/dev/null; }

_xray_add_mount() {
    python3 - "$NODE_COMPOSE" "$XRAY_MARK" "$XRAY_BIN" <<'PY'
import sys, re
f, mark, binpath = sys.argv[1], sys.argv[2], sys.argv[3]
b="    # %s-xraybegin"%mark; e="    # %s-xrayend"%mark
c=open(f).read()
c=re.sub(r'\n'+re.escape(b)+r'.*?'+re.escape(e)+r'\n','\n',c,flags=re.DOTALL)
block="%s\n    volumes:\n      - %s:/usr/local/bin/xray\n%s\n"%(b, binpath, e)
m=re.search(r'^    environment:', c, re.M)
c = c[:m.start()]+block+c[m.start():] if m else c.rstrip()+"\n"+block
open(f,'w').write(c); print("OK")
PY
}
_xray_del_mount() {
    python3 - "$NODE_COMPOSE" "$XRAY_MARK" <<'PY'
import sys, re
f, mark = sys.argv[1], sys.argv[2]
b="    # %s-xraybegin"%mark; e="    # %s-xrayend"%mark
c=open(f).read()
c=re.sub(r'\n'+re.escape(b)+r'.*?'+re.escape(e)+r'\n','\n',c,flags=re.DOTALL)
open(f,'w').write(c); print("OK")
PY
}

xray_status() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; return 1; }
    echo -e "  Версия Xray в контейнере: ${C}$(_xray_cver)${N}"
    if _xray_custom_on; then
        echo -e "  Режим: ${Y}кастомная версия${N} (${XRAY_BIN})"
    else
        echo -e "  Режим: ${G}по умолчанию (из образа remnawave/node)${N}"
    fi
}

# Печатает список тегов Xray-core: аргумент stable|all
_xray_list() {
    local mode="$1" raw
    raw=$(curl -fsSL "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=30" 2>/dev/null) || return 1
    [[ -n "$raw" ]] || return 1
    if [[ "$mode" == "stable" ]]; then
        printf '%s' "$raw" | python3 -c 'import sys,json; [print(r["tag_name"]) for r in json.load(sys.stdin) if not r.get("prerelease")]' 2>/dev/null | head -8
    else
        printf '%s' "$raw" | python3 -c 'import sys,json; [print(r["tag_name"]) for r in json.load(sys.stdin)]' 2>/dev/null | head -10
    fi
}

# Скачивает и монтирует конкретную версию Xray-core. Аргумент: тег (напр. v26.3.27)
xray_install_version() {
    local ver="$1"
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; return 1; }
    command -v python3 >/dev/null 2>&1 || { echo -e "${R}Нужен python3.${N}"; return 1; }
    local arch; arch=$(_xray_arch)
    [[ -n "$arch" ]] || { echo -e "${R}Архитектура $(uname -m) не поддерживается.${N}"; return 1; }
    command -v unzip >/dev/null 2>&1 || apt-get install -y -qq unzip >/dev/null 2>&1 || true
    if ! command -v unzip >/dev/null 2>&1; then echo -e "${R}Не найден unzip и не удалось его установить. Установите unzip и повторите.${N}"; return 1; fi
    local url="https://github.com/XTLS/Xray-core/releases/download/${ver}/Xray-linux-${arch}.zip"
    echo -e "${C}Скачиваю Xray-core ${ver} (${arch})...${N}"
    local tmp; tmp=$(mktemp -d)
    if ! curl -fsSL "$url" -o "$tmp/x.zip"; then rm -rf "$tmp"; echo -e "${R}Не скачалось: $url${N}"; return 1; fi
    mkdir -p /opt/remnanode
    if ! unzip -o "$tmp/x.zip" xray -d /opt/remnanode >/dev/null 2>&1; then rm -rf "$tmp"; echo -e "${R}В архиве нет бинарника xray (или архив повреждён).${N}"; return 1; fi
    rm -rf "$tmp"; chmod +x "$XRAY_BIN"
    _xray_add_mount
    echo -e "${C}Пересоздаю контейнер...${N}"
    if ! ( cd /opt/remnanode && docker compose up -d --force-recreate ) >/dev/null 2>&1; then
        echo -e "${R}Не удалось пересоздать контейнер (см. cd /opt/remnanode && docker compose logs).${N}"; return 1
    fi
    sleep 4
    local cv; cv=$(_xray_cver)
    if [[ -n "$cv" ]]; then
        echo -e "${G}Готово. Версия Xray в контейнере: ${cv}.${N}"
    else
        echo -e "${R}Контейнер не поднялся / Xray не отвечает (см. cd /opt/remnanode && docker compose logs).${N}"; return 1
    fi
}

xray_revert() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; return 1; }
    if ! _xray_custom_on; then echo -e "${Y}Уже используется дефолтная версия.${N}"; return; fi
    _xray_del_mount
    rm -f "$XRAY_BIN"
    echo -e "${C}Пересоздаю контейнер...${N}"
    ( cd /opt/remnanode && docker compose up -d --force-recreate ) >/dev/null 2>&1 || true
    sleep 4
    echo -e "${G}Возврат к дефолту. Версия Xray: $(_xray_cver).${N}"
    echo -e "${GR}Теперь после 'nodectl update' будет ядро из нового образа ноды.${N}"
}

menu_xray() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; pause; return 1; }
    command -v python3 >/dev/null 2>&1 || { echo -e "${R}Нужен python3.${N}"; pause; return 1; }
    local mode="stable" versions=() a i v mv arch cver cmode
    mapfile -t versions < <(_xray_list "$mode")
    while true; do
        clear
        arch=$(_xray_arch); [[ -n "$arch" ]] || arch="?"
        cver=$(_xray_cver); [[ -n "$cver" ]] || cver="—"
        if _xray_custom_on; then cmode="${Y}🟢 кастомная (примонтирована)${N}"; else cmode="${G}⚪ встроенная (из образа)${N}"; fi
        echo -e "${C}══════════════ Xray-core ══════════════${N}"
        echo ""
        echo -e "  ${C}🌐 Текущее состояние${N}"
        echo -e "     Версия Xray:   ${cver}"
        echo -e "     Архитектура:   ${arch}"
        echo -e "     Режим ядра:    ${cmode}"
        echo ""
        if [[ "$mode" == "stable" ]]; then
            echo -e "  ${C}🎯 Показ релизов:${N} ${G}только стабильные${N}"
        else
            echo -e "  ${C}🎯 Показ релизов:${N} ${Y}все (включая pre-release)${N}"
        fi
        echo ""
        echo -e "  ${C}🚀 Доступные версии:${N}"
        if [[ ${#versions[@]} -eq 0 ]]; then
            echo -e "     ${R}список не получен (сеть?) — можно ввести вручную (m)${N}"
        else
            i=1
            for v in "${versions[@]}"; do echo "     $i) $v"; i=$((i+1)); done
        fi
        echo ""
        echo -e "  ${C}🔧 Действия:${N}"
        echo "     m) ввести версию вручную"
        if [[ "$mode" == "stable" ]]; then
            echo "     a) показать все (с pre-release)"
        else
            echo "     s) только стабильные"
        fi
        echo "     r) обновить список"
        echo "     d) вернуть встроенную версию (из образа)"
        echo "     0) назад"
        echo -e "${C}═══════════════════════════════════════${N}"
        read -rp "> " a || return
        case "${a:-}" in
            0|q|Q|"") return ;;
            m|M) read -rp "Версия (напр. v26.3.27): " mv || continue
                 [[ -n "${mv:-}" ]] && { xray_install_version "$mv"; pause; } ;;
            a|A) mode="all";    mapfile -t versions < <(_xray_list "$mode") ;;
            s|S) mode="stable"; mapfile -t versions < <(_xray_list "$mode") ;;
            r|R) mapfile -t versions < <(_xray_list "$mode") ;;
            d|D) xray_revert; pause ;;
            *) if [[ "$a" =~ ^[0-9]+$ ]] && (( a >= 1 && a <= ${#versions[@]} )); then
                   xray_install_version "${versions[$((a-1))]}"; pause
               fi ;;
        esac
    done
}

node_restart() {
    [[ -f /opt/remnanode/docker-compose.yml ]] || { echo -e "${R}Нода не установлена (/opt/remnanode).${N}"; return 1; }
    echo -e "${C}Перезапускаю ноду...${N}"
    if ( cd /opt/remnanode && docker compose restart ) >/dev/null 2>&1; then
        echo -e "${G}Нода перезапущена.${N}"
    else
        echo -e "${R}Не удалось перезапустить (см. docker compose logs).${N}"
    fi
}

node_update() {
    [[ -f /opt/remnanode/docker-compose.yml ]] || { echo -e "${R}Нода не установлена (/opt/remnanode).${N}"; return 1; }
    echo -e "${C}Обновляю образ ноды (тег из docker-compose.yml)...${N}"
    if ( cd /opt/remnanode && docker compose pull && docker compose up -d ) >/dev/null 2>&1; then
        echo -e "${G}Готово.${N} Тег latest → нода обновлена до свежей; фиксированная версия (напр. 2.8.0) → осталась на ней."
    else
        echo -e "${R}Обновление не удалось (см. cd /opt/remnanode && docker compose logs).${N}"
    fi
}

node_uninstall() {
    if [[ ! -d /opt/remnanode ]] && ! docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^remnanode$'; then
        echo -e "${Y}Нода не обнаружена.${N}"; return
    fi
    echo -e "${R}Полное удаление ноды: контейнер remnanode, образ remnawave/node, /opt/remnanode.${N}"
    read -rp "Введите 'yes' для подтверждения: " ans </dev/tty || return
    [[ "${ans:-}" == "yes" ]] || { echo "Отменено."; return; }
    if [[ -f /opt/remnanode/docker-compose.yml ]]; then
        ( cd /opt/remnanode && docker compose down ) >/dev/null 2>&1 || true
    fi
    docker rm -f remnanode >/dev/null 2>&1 || true
    local imgs; imgs=$(docker images 'remnawave/node' -q 2>/dev/null | sort -u)
    [[ -n "$imgs" ]] && docker image rm -f $imgs >/dev/null 2>&1 || true
    rm -rf /opt/remnanode
    echo -e "${G}Нода полностью удалена.${N}"
    echo -e "${GR}Порт ноды в UFW оставлен (закрыть вручную при желании: ufw status).${N}"
}

show_logs() {
    echo -e "${C}Последние блокировки UFW:${N}"
    grep -i 'BLOCK' /var/log/ufw.log 2>/dev/null | tail -20 || echo "лог UFW пуст/недоступен"
}

usage() {
    cat <<U
nodectl — управление нодой и безопасностью
  nodectl            интерактивное меню (по умолчанию)
  nodectl status     показать статус
  nodectl restart    перезапустить ноду
  nodectl update     обновить ноду (до тега из docker-compose.yml)
U
}

main_menu() {
    local psi_c ss_c
    while true; do
        clear
        command -v vps-psiphon >/dev/null 2>&1 && psi_c="$G" || psi_c="$R"
        command -v selfsteal   >/dev/null 2>&1 && ss_c="$G"  || ss_c="$R"
        echo -e "${C}============= nodectl =============${N}"
        show_status
        echo ""
        echo -e "${GR}──── 🔒 Безопасность ────${N}"
        echo "  1) 🛡️  Fail2Ban (баны SSH)"
        echo "  2) 🌍 Геоблокировка по странам"
        echo "  3) 🔀 IPv6 вкл/выкл"
        echo "  4) 📡 ICMP пинг вкл/выкл"
        echo "  5) 🧱 SYNPROXY (анти-SYN-флуд)"
        echo ""
        echo "  6) 📜 Логи firewall"
        echo ""
        echo -e "${GR}──── 📦 Установки ────${N}"
        echo -e "  7) ${psi_c}🌀 Psiphon (обход RU-метки, для Gemini)${N}"
        echo -e "  8) ${ss_c}🎭 Selfsteal (маскировка Reality)${N}"
        echo ""
        echo -e "${GR}──── 🖥️  Нода ────${N}"
        echo "  9) 🧬 Xray-core (своя версия / дефолт)"
        echo "  u) 🗑️  Удалить ноду (полностью)"
        echo -e "${GR}     перезапуск/обновление: nodectl restart | nodectl update${N}"
        echo ""
        echo "  0) Выход"
        read -rp "> " ch || exit 0
        case "${ch:-}" in
            1) menu_fail2ban; pause ;;
            2) menu_geoblock; pause ;;
            3) toggle_ipv6; pause ;;
            4) toggle_icmp; pause ;;
            5) toggle_synproxy; pause ;;
            6) show_logs; pause ;;
            7) menu_psiphon; pause ;;
            8) menu_selfsteal; pause ;;
            9) menu_xray ;;
            u|U) node_uninstall; pause ;;
            0|q) exit 0 ;;
            *) : ;;
        esac
    done
}

cmd="${1:-menu}"
case "$cmd" in
    status)      need_root; show_status ;;
    menu|"")     need_root; main_menu ;;
    restart)     need_root; node_restart ;;
    update)      need_root; node_update ;;
    geo-reapply) need_root; geo_reapply ;;
    -h|--help)   usage ;;
    *)           usage; exit 1 ;;
esac
NODECTL_EOF
chmod 0755 /usr/local/bin/nodectl
# Порт ноды сохраняем, чтобы nodectl знал, что защищать SYNPROXY.
echo "$NODE_PORT" > "/etc/$(tok np).port"; chmod 0600 "/etc/$(tok np).port"
SETUP_DONE+=("nodectl установлен")
success "Команда nodectl установлена (наберите: nodectl)"

# Если админ ранее настраивал geoblock через nodectl, ufw reset (шаг 2) стёр его
# DROP-правило из before.rules — восстанавливаем синхронно с сохранённым ipset.
/usr/local/bin/nodectl geo-reapply >/dev/null 2>&1 || true


#===============================================================================
# ИТОГ
#===============================================================================
echo ""
echo -e "${GREEN}========================================${RESET}"
echo -e "${GREEN}         ИТОГ АВТО-УСТАНОВКИ            ${RESET}"
echo -e "${GREEN}========================================${RESET}"
echo ""
echo -e "${GREEN}Успешные шаги (${#SETUP_DONE[@]}):${RESET}"
if [[ ${#SETUP_DONE[@]} -gt 0 ]]; then
    for s in "${SETUP_DONE[@]}"; do echo -e "  ${GREEN}✓${RESET} ${s}"; done
fi
if [[ ${#SETUP_FAIL[@]} -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}Шаги с ошибками / не выполнены (${#SETUP_FAIL[@]}):${RESET}"
    for s in "${SETUP_FAIL[@]}"; do echo -e "  ${RED}✗${RESET} ${s}"; done
fi

echo ""
echo -e "${YELLOW}========================================${RESET}"
echo -e "${BLUE}Полезные команды:${RESET}"
echo -e "  Меню управления:   ${CYAN}nodectl${RESET}"
echo -e "  Статус:            ${CYAN}nodectl status${RESET}"
echo -e "  Статус UFW:        ${CYAN}ufw status verbose${RESET}"
echo -e "  Статус Fail2Ban:   ${CYAN}fail2ban-client status sshd${RESET}"
echo -e "  Congestion/qdisc:  ${CYAN}sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc${RESET}"
echo -e "${YELLOW}========================================${RESET}"
echo ""
info "Маскировка Reality (Selfsteal), Psiphon и прочее — через команду: nodectl"
echo ""
