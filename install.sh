#!/usr/bin/env bash
#===============================================================================
# nodectl — Node Auto-Installer
# Description: Подготовка сервера под ноду Remnawave «под ключ»:
#              firewall, fail2ban, kernel hardening, сеть/лимиты, авто-обновления,
#              анти-флуд, установка Docker + ноды Remnawave, Docker+UFW fix,
#              и команда управления `nodectl` (geoblock, IPv6/ICMP, SYNPROXY,
#              Psiphon для Gemini, WARP Native, Selfsteal для Reality).
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
# Установка команды nodectl (используется и при полной установке, и в режиме
# `install.sh --update-nodectl`, который вызывает `nodectl update-self`).
#===============================================================================
install_nodectl() {
    # Пишем во временный файл и подменяем через mv: запущенный `nodectl update-self`
    # продолжает читать свою старую копию (старый inode), а не новый файл.
    cat > /usr/local/bin/nodectl.new <<'NODECTL_EOF'
#!/usr/bin/env bash
# nodectl — управление безопасностью сервера-ноды
set -uo pipefail

G='\033[0;32m'; B='\033[0;34m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[0;36m'; GR='\033[0;90m'; N='\033[0m'

# Те же обфусцированные имена файлов, что создал установщик (детерминированы от machine-id).
_SEED="$(cat /etc/machine-id 2>/dev/null || hostname 2>/dev/null || echo seed)"
tok() { printf '%s' "${_SEED}:$1" | sha256sum | cut -c1-12; }
IPV6_CONF="/etc/sysctl.d/98-$(tok ipv6).conf"
BEFORE_RULES="/etc/ufw/before.rules"

# Geoblock (весь сервер, все порты; RU/IR НЕ включаем — это целевая аудитория VPN).
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
VOL_MARK="$(tok vol)"

# Логи ноды в файлах: Xray пишет access.log/error.log в /var/log/remnanode (путь задаёт
# конфиг панели), каталог монтируется в контейнер, ротацию делает logrotate.
LOG_DIR="/var/log/remnanode"
LOG_MOUNT="${LOG_DIR}:${LOG_DIR}"
LOGROTATE_CONF="/etc/logrotate.d/remnanode"

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
        printf "  %-24s %b\n" "геоблок (все порты)" "${G}включён${N}"
    else
        printf "  %-24s %b\n" "геоблок (все порты)" "${GR}выключен${N}"
    fi
    if _syn_enabled; then
        printf "  %-24s %b\n" "SYNPROXY" "${G}включён${N}"
    else
        printf "  %-24s %b\n" "SYNPROXY" "${GR}выключен${N}"
    fi
    if _warp_installed; then
        if systemctl is-active --quiet wg-quick@warp 2>/dev/null; then
            printf "  %-24s %b\n" "WARP" "${G}активен${N}"
        else
            printf "  %-24s %b\n" "WARP" "${R}не активен${N}"
        fi
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
    _geo_del_rule
    # Полный блок выбранных стран: дроп ВСЕГО входящего с этих подсетей (все порты/протоколы).
    python3 - "$BEFORE_RULES" "$GEO_MARK" "$GEO_SET" <<'PY'
import sys, re
f, mark, s = sys.argv[1], sys.argv[2], sys.argv[3]
begin="# %s-geo-begin"%mark; end="# %s-geo-end"%mark
c=open(f).read()
c=re.sub(r'\n'+re.escape(begin)+r'.*?'+re.escape(end)+r'\n','\n',c,flags=re.DOTALL)
block="\n%s\n-A ufw-before-input -m set --match-set %s src -j DROP\n%s\n"%(begin,s,end)
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
        echo -e "  Геоблок: ${G}включён${N} (${n:-0} подсетей, весь сервер — все порты)"
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
    echo -e "${G}Геоблокировка включена (весь сервер, все порты).${N}"
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
        hdr "Геоблокировка (весь сервер)"
        geo_status
        echo ""
        echo -e "  ${GR}Полностью блокирует выбранные страны на ВСЕХ портах сервера.${N}"
        echo -e "  ${R}НЕ добавляйте страны своих VPN-клиентов — иначе отрежете их совсем${N}"
        echo -e "  ${R}(RU и IR в рекомендованный набор НЕ входят).${N}"
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

# ---------- WARP Native (выход через Cloudflare WARP, distillium/warp-native) ----------
WARP_URL="https://raw.githubusercontent.com/distillium/warp-native/main/install.sh"
WARP_UNINSTALL_URL="https://raw.githubusercontent.com/distillium/warp-native/main/uninstall.sh"
WARP_WATCHDOG_LOG="/opt/warp-native/logs/watchdog.log"

_warp_installed() { [[ -x /usr/local/bin/warp && -f /etc/wireguard/warp.conf ]]; }

warp_install() {
    local a
    if _warp_installed; then
        echo -e "${Y}WARP уже установлен.${N} Аккаунт WARP сохранится, интерфейс и watchdog настроятся заново."
        read -rp "  Переустановить? [y/N]: " a || return 0
        case "${a:-}" in y|Y|yes|YES|д|Д|да|Да|ДА) ;; *) return 0 ;; esac
    fi
    echo -e "${C}Скачиваю и ставлю WARP Native (интерфейс WireGuard «warp», без warp-cli)...${N}"
    echo -e "${GR}Установщик спросит: язык, ключ WARP+ (Enter — пропустить) и интервал проверки (Enter — 5 минут).${N}"
    local t; t=$(mktemp)
    if curl -fsSL "$WARP_URL" -o "$t"; then
        bash "$t"
        rm -f "$t"
        if _warp_installed; then
            echo -e "${G}WARP установлен.${N} Теперь добавьте outbound+routing в панель (пункт 3 меню)."
        else
            echo -e "${R}WARP не установился — смотрите вывод выше.${N}"
        fi
    else
        rm -f "$t"; echo -e "${R}Не удалось скачать установщик WARP.${N}"
    fi
}

warp_show_xray() {
    cat <<'XRAY'
--- Добавьте это в конфиг Xray на панели Remnawave ---

1) OUTBOUND (в массив "outbounds"):
{
  "tag": "warp-out",
  "protocol": "freedom",
  "settings": {
    "domainStrategy": "ForceIPv4"
  },
  "streamSettings": {
    "sockopt": {
      "interface": "warp",
      "mark": 51888,
      "tcpFastOpen": true
    }
  }
}

2) ROUTING-ПРАВИЛО (в "routing" -> "rules"; домены и теги inbound — примеры, замените на свои):
{
  "type": "field",
  "domain": [
    "netflix.com",
    "youtube.com",
    "twitter.com"
  ],
  "inboundTag": [
    "Node-1",
    "Node-2"
  ],
  "outboundTag": "warp-out"
}

Важно:
- "mark": 51888 включает kill-switch: если интерфейс warp упадёт, трафик по этому outbound
  не уйдёт на обычное подключение сервера (и не раскроет его IP), а будет отброшен.
  Не удаляйте mark.
- Заворачивайте в WARP только нужные домены, а не весь трафик.
XRAY
}

warp_status() {
    if ! _warp_installed; then echo -e "${Y}Не установлен.${N}"; return 1; fi
    /usr/local/bin/warp
}

warp_restart() {
    if ! _warp_installed; then echo -e "${Y}Не установлен.${N}"; return 1; fi
    echo -e "${C}Перезапускаю интерфейс warp...${N}"
    if systemctl restart wg-quick@warp; then
        echo -e "${G}Готово.${N}"
    else
        echo -e "${R}Не удалось перезапустить (см. journalctl -u wg-quick@warp -n 30).${N}"
    fi
}

warp_log() {
    if [[ -f "$WARP_WATCHDOG_LOG" ]]; then
        tail -n 50 "$WARP_WATCHDOG_LOG"
    else
        echo -e "${GR}Лог пока пуст — watchdog ещё не запускался.${N}"
    fi
}

warp_uninstall() {
    local a
    if ! _warp_installed; then echo -e "${Y}Не установлен.${N}"; return 0; fi
    echo -e "${Y}Сначала уберите outbound «warp-out» и его правило из конфига Xray на панели:${N}"
    echo -e "${GR}иначе трафик по этому правилу перестанет проходить — интерфейса warp больше не будет.${N}"
    read -rp "  Удалить WARP? [y/N]: " a || return 0
    case "${a:-}" in y|Y|yes|YES|д|Д|да|Да|ДА) ;; *) echo "Отменено."; return 0 ;; esac
    local t; t=$(mktemp)
    if curl -fsSL "$WARP_UNINSTALL_URL" -o "$t"; then
        bash "$t"
        rm -f "$t"
    else
        rm -f "$t"; echo -e "${R}Не удалось скачать скрипт удаления WARP.${N}"
    fi
}

menu_warp() {
    local a
    while true; do
        hdr "WARP Native — выход через Cloudflare WARP"
        if _warp_installed; then
            if systemctl is-active --quiet wg-quick@warp 2>/dev/null; then
                echo -e "  Статус: ${G}установлен, интерфейс warp активен${N}"
            else
                echo -e "  Статус: ${Y}установлен, интерфейс warp не активен${N}"
            fi
        else
            echo -e "  Статус: ${GR}не установлен${N}"
        fi
        echo ""
        echo -e "  ${GR}Интерфейс WireGuard «warp» на сервере (без warp-cli). Чтобы нужные домены${N}"
        echo -e "  ${GR}пошли через WARP, добавьте outbound+routing в конфиг Xray на панели (пункт 3).${N}"
        echo ""
        echo "  1) Установить"
        echo "  2) Статус и проверка выхода (IP, страна, ChatGPT)"
        echo "  3) Показать outbound+routing для панели"
        echo "  4) Перезапустить интерфейс"
        echo "  5) Лог watchdog"
        echo "  6) Удалить"
        echo ""
        echo "  0) Назад"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            1) warp_install; pause ;;
            2) warp_status; pause ;;
            3) warp_show_xray; pause ;;
            4) warp_restart; pause ;;
            5) warp_log; pause ;;
            6) warp_uninstall; pause ;;
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
# То же после пересоздания: контейнеру нужно несколько секунд, ждём до 20 с.
_xray_cver_wait() {
    local i v
    for i in 1 2 3 4 5 6 7 8 9 10; do
        v=$(_xray_cver); [[ -n "$v" ]] && { echo "$v"; return 0; }
        sleep 2
    done
}
# Единый блок томов в docker-compose.yml (маркер ${VOL_MARK}): пункты добавляются и убираются
# по одному, старый блок xray (xraybegin/xrayend) переносится в него автоматически.
# Два ключа volumes: в одном сервисе — невалидный YAML. Если ключ уже есть (ноду ставил другой
# скрипт), наш блок встаёт внутрь его списка. Второй том на тот же путь в контейнере Docker
# не примет — такой add отказывает. Коды: 2 — путь уже занят чужой строкой, 3 — del строки,
# которую вписал не nodectl, 4 — volumes записан в одну строку.
_compose_mount() {   # add|del "<host>:<container>"
    python3 - "$NODE_COMPOSE" "$VOL_MARK" "$1" "$2" <<'PY'
import sys, re
f, mark, action, item = sys.argv[1:5]
tgt = (item.split(':') + [''])[1]
c = open(f).read()
if not c.endswith('\n'):
    c += '\n'
items = []
def take(rx):
    global c, items
    m = re.search(rx, c, re.DOTALL)
    if m:
        items += [l.strip()[2:].strip() for l in m.group(m.lastindex).splitlines() if l.strip().startswith('- ')]
        c = c[:m.start()] + "\n" + c[m.end():]
take(r'\n[ \t]*# (\S+)-xraybegin\n(.*?)\n[ \t]*# \1-xrayend\n')
take(r'\n[ \t]*# ' + re.escape(mark) + r'-volbegin\n(.*?)\n[ \t]*# ' + re.escape(mark) + r'-volend\n')
own = [i for i in dict.fromkeys(items) if i != item]
if action == 'add':
    own.append(item)
# Чужой список volumes: в сервисе и его пункты.
vm = re.search(r'^    volumes:[ \t]*(#.*)?$', c, re.M)
if not vm and re.search(r'^    volumes:', c, re.M) and own:
    print("volumes в docker-compose.yml записан в одну строку — дописать в него не могу", file=sys.stderr); sys.exit(4)
foreign, ind = [], None
if vm:
    for l in c[vm.end() + 1:].split('\n'):
        s = l.strip()
        if not s or s.startswith('#'):
            continue
        if re.match(r'^ {4,}- ', l):
            ind = ind or re.match(r'^ *', l).group(0)
            foreign.append((re.sub(r'\s+#.*$', '', s[2:]).strip().strip('\'"'), s))
        elif not re.match(r'^ {5,}\S', l):
            break
if action == 'add':
    if any(v == item for v, s in foreign):
        own.remove(item)   # уже подключено чужой строкой — дублировать не нужно
    else:
        for v, s in foreign:
            if (v.split(':') + [''])[1] == tgt:
                print("путь %s в контейнере уже подключён строкой: %s" % (tgt, s), file=sys.stderr); sys.exit(2)
elif item not in items and any(v == item for v, s in foreign):
    print("строку %s вписал в docker-compose.yml не nodectl — уберите её вручную" % item, file=sys.stderr); sys.exit(3)
if own:
    if vm:
        ind = ind or "      "
        block = "%s# %s-volbegin\n%s\n%s# %s-volend\n" % (ind, mark, "\n".join(ind + "- " + i for i in own), ind, mark)
        p = vm.end() + 1
        c = c[:p] + block + c[p:]
    else:
        block = "    # %s-volbegin\n    volumes:\n%s\n    # %s-volend\n" % (mark, "\n".join("      - " + i for i in own), mark)
        mm = re.search(r'^    (environment|env_file):', c, re.M)
        sm = re.search(r'^  remnanode:[^\n]*\n', c, re.M)
        if mm:
            c = c[:mm.start()] + block + c[mm.start():]
        elif sm:
            c = c[:sm.end()] + block + c[sm.end():]
        else:
            c = c.rstrip() + "\n" + block
open(f, 'w').write(c); print("OK")
PY
}

# Пересоздаёт контейнер ноды. Сначала проверяет docker-compose.yml: с ошибкой в файле Docker
# контейнер не трогает — тогда код 2. Код 1 — Docker не смог пересоздать. Ошибку печатает.
_node_recreate() {
    local out
    if ! out=$(cd /opt/remnanode && docker compose config -q 2>&1); then
        echo -e "${R}Docker не принимает docker-compose.yml:${N}"; printf '%s\n' "$out" | tail -5
        return 2
    fi
    if ! out=$(cd /opt/remnanode && docker compose up -d --force-recreate 2>&1); then
        echo -e "${R}Не удалось пересоздать контейнер:${N}"; printf '%s\n' "$out" | tail -8
        return 1
    fi
}

# Возвращает docker-compose.yml из копии после неудачи _node_recreate (второй аргумент — её код)
# и, если контейнер уже трогали, поднимает ноду на прежнем файле.
_node_restore() {   # копия код
    [[ -f "$1" ]] && cp "$1" "$NODE_COMPOSE"
    if [[ "$2" -eq 2 ]]; then
        echo -e "${Y}docker-compose.yml возвращён как был, нода не тронута.${N}"
    elif ( cd /opt/remnanode && docker compose up -d --force-recreate ) >/dev/null 2>&1; then
        echo -e "${Y}docker-compose.yml возвращён как был, нода поднята на нём.${N}"
    else
        echo -e "${R}Нода не поднялась и на прежнем файле — проверьте: cd /opt/remnanode && docker compose up -d${N}"
    fi
}

# Откуда на хосте монтируется ядро (/usr/local/bin/xray в контейнере); пусто — встроенное из образа.
# Свой том nodectl — ${XRAY_BIN}. Если ноду ставил другой скрипт, ядро может идти из его файла
# (например /var/lib/remnanode/xray): такой путь главнее — второй том на тот же путь Docker не примет.
_xray_mount_src() {
    local s own=""
    while read -r s; do
        [[ "$s" == "$XRAY_BIN" ]] && { own=1; continue; }
        echo "$s"; return 0
    done < <(sed -nE "s|^[[:space:]]*-[[:space:]]*['\"]?([^:'\"[:space:]]+):/usr/local/bin/xray(:[a-z,]+)?['\"]?[[:space:]]*(#.*)?\$|\1|p" "$NODE_COMPOSE" 2>/dev/null)
    [[ -n "$own" ]] && echo "$XRAY_BIN"
    return 0
}
_xray_fver() { [[ -x "$1" ]] && "$1" version 2>/dev/null | head -1 | awk '{print $2}'; }
_xray_custom_on() { [[ -n "$(_xray_mount_src)" ]]; }
_xray_own_on() { grep -q -- "- ${XRAY_BIN}:/usr/local/bin/xray" "$NODE_COMPOSE" 2>/dev/null; }
_xray_add_mount() { _compose_mount add "${XRAY_BIN}:/usr/local/bin/xray"; }
_xray_del_mount() { _compose_mount del "${XRAY_BIN}:/usr/local/bin/xray"; }

#-------------------------------------------------------------------------------
# Логи ноды в файлах (/var/log/remnanode) + ротация logrotate
#-------------------------------------------------------------------------------
_logs_on() { grep -q -- "- ${LOG_MOUNT}" "$NODE_COMPOSE" 2>/dev/null; }

_logs_write_rotate() {
    if ! command -v logrotate >/dev/null 2>&1; then
        echo -e "${C}Устанавливаю logrotate...${N}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate >/dev/null 2>&1 || return 1
    fi
    # copytruncate: Xray держит файл открытым, переименовывать его нельзя — обрезаем на месте.
    cat > "$LOGROTATE_CONF" <<ROT
${LOG_DIR}/*.log {
    size 50M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
ROT
    chmod 0644 "$LOGROTATE_CONF"
    logrotate -d "$LOGROTATE_CONF" >/dev/null 2>&1
}

node_logs_enable() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; return 1; }
    mkdir -p "$LOG_DIR" && chmod 0755 "$LOG_DIR"
    local changed=0 bak rc
    if _logs_on; then
        echo -e "${G}✓${N} Каталог ${LOG_DIR} уже монтируется в контейнер."
    else
        bak="${NODE_COMPOSE}.bak.$(date +%s)"; cp "$NODE_COMPOSE" "$bak"
        _compose_mount add "$LOG_MOUNT" >/dev/null || { echo -e "${R}Не удалось изменить docker-compose.yml.${N}"; return 1; }
        echo -e "${G}✓${N} В docker-compose.yml добавлен том ${LOG_MOUNT}."
        changed=1
    fi
    if _logs_write_rotate; then
        echo -e "${G}✓${N} Ротация: ${LOGROTATE_CONF} (50 МБ × 5 архивов, сжатие)."
    else
        echo -e "${Y}⚠${N} logrotate не установился — логи будут расти без ротации."
    fi
    if [[ $changed -eq 1 ]]; then
        echo -e "${C}Пересоздаю контейнер ноды, чтобы подхватил том...${N}"
        _node_recreate; rc=$?
        if [[ $rc -eq 0 ]]; then
            echo -e "${G}✓${N} Нода перезапущена."
        else
            _node_restore "$bak" "$rc"; return 1
        fi
    fi
    echo -e "${G}Готово.${N} Логи: ${C}${LOG_DIR}/access.log${N} и ${C}${LOG_DIR}/error.log${N}"
    echo -e "${GR}Пути задаёт конфиг Xray в панели (log.access / log.error) — по умолчанию именно эти.${N}"
}

node_logs_disable() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; return 1; }
    _logs_on || { echo -e "${GR}Логи и так внутри контейнера.${N}"; return 0; }
    local bak rc
    bak="${NODE_COMPOSE}.bak.$(date +%s)"; cp "$NODE_COMPOSE" "$bak"
    _compose_mount del "$LOG_MOUNT" >/dev/null || { echo -e "${R}Не удалось изменить docker-compose.yml.${N}"; rm -f "$bak"; return 1; }
    _node_recreate; rc=$?
    [[ $rc -eq 0 ]] || { _node_restore "$bak" "$rc"; return 1; }
    rm -f "$LOGROTATE_CONF"
    echo -e "${G}✓${N} Том отключён, ротация снята. Файлы в ${LOG_DIR} не тронуты."
}

node_logs_tail() {   # access|error [строк]
    local f="${LOG_DIR}/${1:-access}.log" n="${2:-50}"
    [[ -f "$f" ]] || { echo -e "${Y}Файла ${f} ещё нет: нода не писала в него (проверьте пути логов в конфиге панели).${N}"; return 1; }
    echo -e "${C}${f} — последние ${n} строк (размер $(du -h "$f" | cut -f1)):${N}"
    tail -n "$n" "$f"
}

# Живые логи контейнера ноды: то же, что `cd /opt/remnanode && docker compose logs -f`.
# Ctrl+C останавливает просмотр и возвращает в меню (а не закрывает nodectl); лишние
# параметры уходят в docker compose logs (например: nodectl logs --tail 100).
node_logs_follow() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена (/opt/remnanode).${N}"; return 1; }
    echo -e "${GR}Логи контейнера remnanode (docker compose logs -f). Выход — Ctrl+C.${N}"
    trap ':' INT
    ( cd /opt/remnanode && exec docker compose logs -f "$@" )
    trap - INT
}

menu_node_logs() {
    local a st sz
    while true; do
        hdr "Логи ноды — файлы и ротация"
        if _logs_on; then st="${G}✅ в файлах ${LOG_DIR}${N}"; else st="${GR}⚪ внутри контейнера (docker logs)${N}"; fi
        sz=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)
        echo -e "  Сейчас: ${st}"
        [[ -n "$sz" ]] && echo -e "  Занято: ${C}${sz}${N}   ротация: $([[ -f "$LOGROTATE_CONF" ]] && echo -e "${G}настроена${N}" || echo -e "${GR}нет${N}")"
        echo ""
        echo "  1) Включить: писать в файлы + ротация (50 МБ × 5)"
        echo "  2) Показать хвост access.log"
        echo "  3) Показать хвост error.log"
        echo "  4) Выключить (вернуть логи в контейнер)"
        echo "  5) Живые логи контейнера (docker compose logs -f)"
        echo "  0) Назад"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            1) echo ""; node_logs_enable; pause ;;
            2) echo ""; node_logs_tail access 60; pause ;;
            3) echo ""; node_logs_tail error 60; pause ;;
            4) echo ""; node_logs_disable; pause ;;
            5) echo ""; node_logs_follow; echo "" ;;
            0) return ;;
        esac
    done
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
    if ! unzip -o "$tmp/x.zip" xray -d "$tmp" >/dev/null 2>&1; then rm -rf "$tmp"; echo -e "${R}В архиве нет бинарника xray (или архив повреждён).${N}"; return 1; fi
    chmod +x "$tmp/xray"
    # Проверяем ядро до того, как что-то менять: запускается ли оно на этом сервере.
    local nv; nv=$(_xray_fver "$tmp/xray")
    if [[ -z "$nv" ]]; then rm -rf "$tmp"; echo -e "${R}Скачанный xray не запускается на этом сервере.${N}"; return 1; fi

    # Куда класть: если ядро уже подключено из файла другого скрипта — в этот же файл
    # (второй том на тот же путь Docker не примет), иначе — свой ${XRAY_BIN} и том на него.
    local src dst bak rc orig=""
    src=$(_xray_mount_src); dst="${src:-$XRAY_BIN}"
    bak="${NODE_COMPOSE}.bak.$(date +%s)"; cp "$NODE_COMPOSE" "$bak"
    if [[ "$dst" != "$XRAY_BIN" ]]; then
        # Прошлые версии nodectl дописывали тут второй ключ volumes — убираем его.
        if _xray_own_on && ! _xray_del_mount >/dev/null; then
            rm -rf "$tmp"; echo -e "${R}Не удалось изменить docker-compose.yml.${N}"; return 1
        fi
        [[ -f "$dst" && ! -e "${dst}.orig" ]] && cp -p "$dst" "${dst}.orig" && orig="${dst}.orig"
        echo -e "${GR}Ядро подключено из ${dst} (так ноду настроил другой скрипт) — кладу новое туда же; прежнее сохранено в ${dst}.orig.${N}"
    fi
    cp "$NODE_COMPOSE" "$tmp/compose"   # откат — к этому состоянию (лишний том уже убран)
    [[ -f "$dst" ]] && cp -p "$dst" "$tmp/prev"
    mkdir -p "$(dirname "$dst")"
    # install, а не cp: поверх файла, который сейчас запущен в контейнере, cp выдаёт «Text file busy».
    if ! install -m 0755 "$tmp/xray" "$dst"; then
        rm -rf "$tmp"; [[ -n "$orig" ]] && rm -f "$orig"; echo -e "${R}Не удалось записать ${dst}.${N}"; return 1
    fi
    if [[ -z "$src" ]] && ! _xray_add_mount >/dev/null; then
        if [[ -f "$tmp/prev" ]]; then install -m 0755 "$tmp/prev" "$dst"; else rm -f "$dst"; fi
        cp "$tmp/compose" "$NODE_COMPOSE"; rm -rf "$tmp"
        echo -e "${R}Не удалось изменить docker-compose.yml — ничего не поменял.${N}"; return 1
    fi
    echo -e "${C}Пересоздаю контейнер...${N}"
    _node_recreate; rc=$?
    if [[ $rc -ne 0 ]]; then
        if [[ -f "$tmp/prev" ]]; then install -m 0755 "$tmp/prev" "$dst"; else rm -f "$dst"; fi
        _node_restore "$tmp/compose" "$rc"; rm -rf "$tmp"; [[ -n "$orig" ]] && rm -f "$orig"
        echo -e "${GR}Ядро тоже возвращено прежнее.${N}"; return 1
    fi
    rm -rf "$tmp"
    local cv; cv=$(_xray_cver_wait)
    if [[ "$cv" == "$nv" ]]; then
        echo -e "${G}Готово. Версия Xray в контейнере: ${cv}.${N}"
    elif [[ -n "$cv" ]]; then
        echo -e "${R}В контейнере Xray ${cv}, а положено ${nv} — ядро не подхватилось (см. nodectl logs).${N}"; return 1
    else
        echo -e "${R}Контейнер не поднялся / Xray не отвечает (см. nodectl logs).${N}"; return 1
    fi
}

xray_revert() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; return 1; }
    local src bak rb rc; src=$(_xray_mount_src)
    if [[ -z "$src" ]]; then echo -e "${Y}Уже используется встроенная версия.${N}"; return; fi
    if [[ "$src" != "$XRAY_BIN" && ! -f "${src}.orig" ]]; then
        echo -e "${Y}Ядро подключено не nodectl, а из ${src} (так ноду настроил другой скрипт), и nodectl его не менял.${N}"
        echo -e "${GR}Перейти на встроенное: уберите строку с ${src} из ${NODE_COMPOSE}, затем cd /opt/remnanode && docker compose up -d${N}"
        return 0
    fi
    bak="${NODE_COMPOSE}.bak.$(date +%s)"; cp "$NODE_COMPOSE" "$bak"
    rb=$(mktemp)
    if [[ "$src" == "$XRAY_BIN" ]]; then
        cp "$NODE_COMPOSE" "$rb"
        _xray_del_mount >/dev/null || { echo -e "${R}Не удалось изменить docker-compose.yml.${N}"; rm -f "$rb"; return 1; }
    else
        _xray_own_on && _xray_del_mount >/dev/null   # лишний том от прошлых версий nodectl
        cp "$NODE_COMPOSE" "$rb"
        install -m 0755 "${src}.orig" "$src" || { echo -e "${R}Не удалось записать ${src}.${N}"; rm -f "$rb"; return 1; }
    fi
    echo -e "${C}Пересоздаю контейнер...${N}"
    _node_recreate; rc=$?
    if [[ $rc -ne 0 ]]; then _node_restore "$rb" "$rc"; rm -f "$rb"; return 1; fi
    rm -f "$rb"
    if [[ "$src" == "$XRAY_BIN" ]]; then
        rm -f "$XRAY_BIN"
        echo -e "${G}Возврат к встроенной. Версия Xray: $(_xray_cver_wait).${N}"
        echo -e "${GR}Теперь после «nodectl update» будет ядро из нового образа ноды.${N}"
    else
        rm -f "${src}.orig"
        echo -e "${G}Вернул ядро, которое стояло до nodectl. Версия Xray: $(_xray_cver_wait).${N}"
    fi
}

menu_xray() {
    [[ -f "$NODE_COMPOSE" ]] || { echo -e "${R}Нода не установлена.${N}"; pause; return 1; }
    command -v python3 >/dev/null 2>&1 || { echo -e "${R}Нужен python3.${N}"; pause; return 1; }
    local mode="stable" versions=() a i v mv arch cver cmode src fver cerr
    mapfile -t versions < <(_xray_list "$mode")
    while true; do
        clear
        arch=$(_xray_arch); [[ -n "$arch" ]] || arch="?"
        cver=$(_xray_cver); [[ -n "$cver" ]] || cver="—"
        src=$(_xray_mount_src); fver=""
        if [[ -z "$src" ]]; then cmode="${G}⚪ встроенная (из образа)${N}"
        elif [[ "$src" == "$XRAY_BIN" ]]; then cmode="${Y}🟢 своя версия (nodectl)${N}"; fver=$(_xray_fver "$src")
        else cmode="${Y}🟢 своя версия из ${src}${N} ${GR}(подключил другой скрипт)${N}"; fver=$(_xray_fver "$src"); fi
        cerr=$(cd /opt/remnanode && docker compose config -q 2>&1 | head -1)
        echo -e "${C}══════════════ Xray-core ══════════════${N}"
        echo ""
        echo -e "  ${C}🌐 Текущее состояние${N}"
        echo -e "     Версия Xray:   ${cver}"
        echo -e "     Архитектура:   ${arch}"
        echo -e "     Режим ядра:    ${cmode}"
        if [[ -n "$fver" && "$cver" != "—" && "$fver" != "$cver" ]]; then
            echo -e "     ${Y}⚠ В файле ядра ${fver}, а в контейнере ${cver}: контейнер не пересоздан после смены ядра.${N}"
        fi
        if [[ -n "$cerr" ]]; then
            echo -e "     ${R}⚠ Docker не принимает docker-compose.yml — ноду сейчас не пересоздать:${N}"
            echo -e "       ${GR}${cerr}${N}"
        fi
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
        if [[ -z "$src" || "$src" == "$XRAY_BIN" ]]; then
            echo "     d) вернуть встроенную версию (из образа)"
        elif [[ -f "${src}.orig" ]]; then
            echo "     d) вернуть прежнее ядро (стояло до nodectl)"
        fi
        echo "     0) назад"
        echo -e "${C}═══════════════════════════════════════${N}"
        read -rp "$PROMPT" a || return
        case "${a:-}" in
            0|q|Q|"") return ;;
            m|M) echo ""; read -rp "  Версия (напр. v26.3.27): " mv || continue
                 if [[ -n "${mv:-}" ]]; then xray_install_version "$mv"; pause; else echo -e "${Y}Ничего не введено.${N}"; sleep 1; fi ;;
            a|A) mode="all";    mapfile -t versions < <(_xray_list "$mode") ;;
            s|S) mode="stable"; mapfile -t versions < <(_xray_list "$mode") ;;
            r|R) mapfile -t versions < <(_xray_list "$mode") ;;
            d|D) xray_revert; pause ;;
            *) if [[ "$a" =~ ^[0-9]+$ ]] && (( a >= 1 && a <= ${#versions[@]} )); then
                   xray_install_version "${versions[$((a-1))]}"; pause
               else
                   echo -e "${Y}Неверный выбор.${N}"; sleep 1
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
    clear
    echo -e "${C}Последние блокировки UFW:${N}"
    grep -i 'BLOCK' /var/log/ufw.log 2>/dev/null | tail -20 || echo "лог UFW пуст/недоступен"
}

# Обновление самого скрипта: скачивает свежий install.sh и запускает его в режиме
# --update-nodectl. Этот режим переустанавливает ТОЛЬКО команду nodectl: закалка,
# UFW (включая ручные правила), fail2ban и нода не трогаются.
SELF_URL="https://raw.githubusercontent.com/feauche/remnanode-installer/main/install.sh"
node_selfupdate() {
    echo -e "${C}Обновляю команду nodectl из GitHub (закалка и firewall не трогаются)...${N}"
    local t; t=$(mktemp)
    if ! curl -fsSL "$SELF_URL" -o "$t"; then rm -f "$t"; echo -e "${R}Не удалось скачать install.sh.${N}"; return 1; fi
    if ! grep -q -- '--update-nodectl' "$t"; then
        rm -f "$t"
        echo -e "${R}Скачанный install.sh не поддерживает режим --update-nodectl. Обновите вручную:${N}"
        echo -e "${GR}bash <(curl -sL $SELF_URL)${N}"
        return 1
    fi
    bash "$t" --update-nodectl </dev/tty
    rm -f "$t"
    echo ""
    echo -e "${G}nodectl обновлён.${N} Запустите ${C}nodectl${N} заново."
    # Выходим сразу: файл nodectl только что перезаписан, дочитывать старый
    # процесс из нового файла нельзя (bash читает скрипт по мере выполнения).
    exit 0
}

usage() {
    cat <<U
nodectl — управление нодой и безопасностью
  nodectl              интерактивное меню (по умолчанию)
  nodectl status       показать статус
  nodectl restart      перезапустить ноду
  nodectl update       обновить ноду (до тега из docker-compose.yml)
  nodectl logs         живые логи контейнера ноды (docker compose logs -f в /opt/remnanode), выход — Ctrl+C
  nodectl logs access|error [N]   хвост файлов логов ноды из /var/log/remnanode (если включены)
  nodectl logs-enable  вывести логи ноды в файлы + ротация (то же, что пункт «l» меню)
  nodectl update-self  обновить только сам nodectl из GitHub (закалка и UFW не трогаются)
Все команды доступны и как пункты меню.
Полная закалка заново: bash <(curl -sL $SELF_URL)
U
}

main_menu() {
    local psi_c ss_c warp_c ch geo_b ipv6_b icmp_b psi_b ss_b warp_b xray_b logs_b
    while true; do
        clear
        # Psiphon / Selfsteal: цвет пункта + метка справа.
        if command -v vps-psiphon >/dev/null 2>&1; then psi_c="$G"; psi_b="${G}(установлено)${N}"; else psi_c="$R"; psi_b="${R}(не установлено)${N}"; fi
        if command -v selfsteal   >/dev/null 2>&1; then ss_c="$G";  ss_b="${G}(установлено)${N}";  else ss_c="$R";  ss_b="${R}(не установлено)${N}"; fi
        if _warp_installed; then warp_c="$G"; warp_b="${G}(установлено)${N}"; else warp_c="$R"; warp_b="${R}(не установлено)${N}"; fi
        # Геоблок.
        if ipset list "$GEO_SET" -terse &>/dev/null; then geo_b="${G}✅ включён${N}"; else geo_b="${GR}⚪ выключен${N}"; fi
        # IPv6: ✅ если включён, ❌ если отключён.
        if sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q 1; then ipv6_b="${R}❌ отключён${N}"; else ipv6_b="${G}✅ включён${N}"; fi
        # ICMP: ✅ если пинг разрешён, ❌ если ограничен.
        if grep -q 'icmp-type echo-request -j DROP' "$BEFORE_RULES" 2>/dev/null; then icmp_b="${R}❌ ограничен${N}"; else icmp_b="${G}✅ разрешён${N}"; fi
        # Xray-core: из образа / вручную / нет ноды.
        if [[ ! -f "$NODE_COMPOSE" ]]; then xray_b="${GR}(нет ноды)${N}"
        elif _xray_custom_on; then xray_b="${Y}(вручную)${N}"
        else xray_b="${G}(из образа)${N}"; fi
        # Логи ноды: файлы с ротацией / внутри контейнера.
        if [[ ! -f "$NODE_COMPOSE" ]]; then logs_b="${GR}(нет ноды)${N}"
        elif _logs_on; then logs_b="${G}✅ файлы + ротация${N}"
        else logs_b="${GR}⚪ в контейнере${N}"; fi

        echo ""
        echo -e "  ${C}N O D E C T L${N}"
        echo -e "  ${GR}управление нодой и безопасностью${N}"
        echo ""
        echo -e "${GR}──── 🔒 Безопасность ────${N}"
        echo -e "  1) 🛡️  Fail2Ban (баны SSH)"
        echo -e "  2) 🌍 Геоблокировка по странам   ${geo_b}"
        echo -e "  3) 🔀 IPv6 вкл/выкл   ${ipv6_b}"
        echo -e "  4) 📡 ICMP пинг вкл/выкл   ${icmp_b}"
        echo -e "  5) 🧱 SYNPROXY (анти-SYN-флуд)"
        echo ""
        echo -e "  6) 📜 Логи firewall"
        echo ""
        echo -e "${GR}──── 📦 Установки ────${N}"
        echo -e "  7) ${psi_c}🌀 Psiphon (обход RU-метки, для Gemini)${N}   ${psi_b}"
        echo -e "  8) ${ss_c}🎭 Selfsteal (маскировка Reality)${N}   ${ss_b}"
        echo -e "  w) ${warp_c}☁️  WARP Native (выход через Cloudflare WARP)${N}   ${warp_b}"
        echo ""
        echo -e "${GR}──── 🖥️  Нода ────${N}"
        echo -e "  9) 🧬 Xray-core (своя версия / дефолт)   ${xray_b}"
        echo -e "  l) 📝 Логи ноды (файлы + ротация)   ${logs_b}"
        echo -e "  r) 🔄 Перезапустить ноду"
        echo -e "  n) ⬆️  Обновить ноду (образ, тег из docker-compose.yml)"
        echo -e "  u) 🗑️  Удалить ноду (полностью)"
        echo ""
        echo -e "${GR}──── 🧰 Скрипт ────${N}"
        echo -e "  i) 📊 Статус сервера"
        echo -e "  s) ⬇️  Обновить nodectl (только скрипт, из GitHub)"
        echo ""
        echo "  0) Выход"
        read -rp "$PROMPT" ch || exit 0
        case "${ch:-}" in
            1) menu_fail2ban ;;
            2) menu_geoblock ;;
            3) toggle_ipv6; pause ;;
            4) toggle_icmp; pause ;;
            5) toggle_synproxy ;;
            6) show_logs; pause ;;
            7) menu_psiphon ;;
            8) menu_selfsteal ;;
            w|W) menu_warp ;;
            9) menu_xray ;;
            l|L) menu_node_logs ;;
            r|R) node_restart; pause ;;
            n|N) node_update; pause ;;
            u|U) node_uninstall; pause ;;
            i|I) show_status; pause ;;
            s|S) node_selfupdate ;;
            0|q) exit 0 ;;
            *) echo -e "${Y}Неверный выбор.${N}"; sleep 1 ;;
        esac
    done
}

cmd="${1:-menu}"
case "$cmd" in
    status)      need_root; show_status ;;
    menu|"")     need_root; main_menu ;;
    restart)     need_root; node_restart ;;
    update)      need_root; node_update ;;
    logs)        need_root
                 case "${2:-}" in
                     access|error) node_logs_tail "$2" "${3:-50}" ;;
                     *)            node_logs_follow "${@:2}" ;;
                 esac ;;
    logs-enable) need_root; node_logs_enable ;;
    update-self) need_root; node_selfupdate ;;
    geo-reapply) need_root; geo_reapply ;;
    -h|--help)   usage ;;
    *)           usage; exit 1 ;;
esac
NODECTL_EOF
    chmod 0755 /usr/local/bin/nodectl.new
    mv -f /usr/local/bin/nodectl.new /usr/local/bin/nodectl

    # Порт ноды сохраняем, чтобы nodectl знал, что защищать SYNPROXY.
    # В режиме --update-nodectl NODE_PORT не опрашивается: берём его из compose ноды,
    # и только если файла ещё нет.
    local port_file="/etc/$(tok np).port" p=""
    if [[ -n "${NODE_PORT:-}" ]]; then
        p="$NODE_PORT"
    elif [[ ! -f "$port_file" && -f /opt/remnanode/docker-compose.yml ]]; then
        p=$(grep -oE 'NODE_PORT=[0-9]+' /opt/remnanode/docker-compose.yml | head -1 | cut -d= -f2)
    fi
    if [[ -n "$p" ]]; then
        echo "$p" > "$port_file"; chmod 0600 "$port_file"
    fi
}


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

# --- Логи ноды в файлах: том в docker-compose.yml + logrotate. Идемпотентно; та же логика,
#     что в nodectl (пункт «l»). Контейнер пересоздаётся только если том действительно добавлен.
install_node_logs() {
    local compose="/opt/remnanode/docker-compose.yml" dir="/var/log/remnanode" mark bak out changed=0
    mark="$(tok vol)"
    mkdir -p "$dir" && chmod 0755 "$dir"
    if ! grep -q -- "- ${dir}:${dir}" "$compose" 2>/dev/null; then
        bak="${compose}.bak.$(date +%s)"; cp "$compose" "$bak"
        command -v python3 >/dev/null 2>&1 || apt-get install -y -qq python3 >/dev/null 2>&1 || true
        python3 - "$compose" "$mark" add "${dir}:${dir}" >/dev/null <<'PY' || { warn "Не удалось изменить docker-compose.yml."; return 1; }
import sys, re
f, mark, action, item = sys.argv[1:5]
tgt = (item.split(':') + [''])[1]
c = open(f).read()
if not c.endswith('\n'):
    c += '\n'
items = []
def take(rx):
    global c, items
    m = re.search(rx, c, re.DOTALL)
    if m:
        items += [l.strip()[2:].strip() for l in m.group(m.lastindex).splitlines() if l.strip().startswith('- ')]
        c = c[:m.start()] + "\n" + c[m.end():]
take(r'\n[ \t]*# (\S+)-xraybegin\n(.*?)\n[ \t]*# \1-xrayend\n')
take(r'\n[ \t]*# ' + re.escape(mark) + r'-volbegin\n(.*?)\n[ \t]*# ' + re.escape(mark) + r'-volend\n')
own = [i for i in dict.fromkeys(items) if i != item]
if action == 'add':
    own.append(item)
# Чужой список volumes: в сервисе и его пункты.
vm = re.search(r'^    volumes:[ \t]*(#.*)?$', c, re.M)
if not vm and re.search(r'^    volumes:', c, re.M) and own:
    print("volumes в docker-compose.yml записан в одну строку — дописать в него не могу", file=sys.stderr); sys.exit(4)
foreign, ind = [], None
if vm:
    for l in c[vm.end() + 1:].split('\n'):
        s = l.strip()
        if not s or s.startswith('#'):
            continue
        if re.match(r'^ {4,}- ', l):
            ind = ind or re.match(r'^ *', l).group(0)
            foreign.append((re.sub(r'\s+#.*$', '', s[2:]).strip().strip('\'"'), s))
        elif not re.match(r'^ {5,}\S', l):
            break
if action == 'add':
    if any(v == item for v, s in foreign):
        own.remove(item)   # уже подключено чужой строкой — дублировать не нужно
    else:
        for v, s in foreign:
            if (v.split(':') + [''])[1] == tgt:
                print("путь %s в контейнере уже подключён строкой: %s" % (tgt, s), file=sys.stderr); sys.exit(2)
elif item not in items and any(v == item for v, s in foreign):
    print("строку %s вписал в docker-compose.yml не nodectl — уберите её вручную" % item, file=sys.stderr); sys.exit(3)
if own:
    if vm:
        ind = ind or "      "
        block = "%s# %s-volbegin\n%s\n%s# %s-volend\n" % (ind, mark, "\n".join(ind + "- " + i for i in own), ind, mark)
        p = vm.end() + 1
        c = c[:p] + block + c[p:]
    else:
        block = "    # %s-volbegin\n    volumes:\n%s\n    # %s-volend\n" % (mark, "\n".join("      - " + i for i in own), mark)
        mm = re.search(r'^    (environment|env_file):', c, re.M)
        sm = re.search(r'^  remnanode:[^\n]*\n', c, re.M)
        if mm:
            c = c[:mm.start()] + block + c[mm.start():]
        elif sm:
            c = c[:sm.end()] + block + c[sm.end():]
        else:
            c = c.rstrip() + "\n" + block
open(f, 'w').write(c); print("OK")
PY
        changed=1
        info "В docker-compose.yml добавлен том ${dir}:${dir}."
    fi
    if ! command -v logrotate >/dev/null 2>&1; then
        info "Устанавливаю logrotate..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate >/dev/null 2>&1 || { warn "logrotate не установился."; return 1; }
    fi
    # copytruncate: Xray держит файл открытым, переименовывать его нельзя — обрезаем на месте.
    cat > /etc/logrotate.d/remnanode <<'ROT'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
ROT
    chmod 0644 /etc/logrotate.d/remnanode
    logrotate -d /etc/logrotate.d/remnanode >/dev/null 2>&1 || { warn "Конфиг logrotate не прошёл проверку."; return 1; }
    if [[ $changed -eq 1 ]] && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^remnanode$'; then
        info "Пересоздаю контейнер ноды, чтобы подхватил том..."
        # С ошибкой в файле Docker контейнер не трогает — возвращаем файл, нода работает как была.
        if ! out=$(cd /opt/remnanode && docker compose config -q 2>&1); then
            cp "$bak" "$compose"
            warn "Docker не принял docker-compose.yml, файл возвращён как был: $(printf '%s' "$out" | head -1)"; return 1
        fi
        if ! out=$(cd /opt/remnanode && docker compose up -d --force-recreate 2>&1); then
            cp "$bak" "$compose"; ( cd /opt/remnanode && docker compose up -d --force-recreate ) >/dev/null 2>&1
            warn "Контейнер не пересоздался, docker-compose.yml возвращён как был: $(printf '%s' "$out" | tail -1)"; return 1
        fi
    fi
    return 0
}

# --- Режим «только обновить nodectl» (его вызывает `nodectl update-self`) ---
# Закалку, UFW, fail2ban и ноду не трогает: переустанавливает лишь команду nodectl.
if [[ "${1:-}" == "--update-nodectl" ]]; then
    step "Обновление команды nodectl (закалка и firewall не трогаются)"
    install_nodectl
    success "Команда nodectl обновлена."
    info "Полная закалка заново (все шаги): запустите установщик без параметров."
    exit 0
fi

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
    info "Саму ноду установщик не тронет: второй экземпляр не ставится, ключ, порт и версия остаются прежними."
    echo ""
    if ! confirm "Продолжить установку?" "y"; then
        info "Отмена. Ничего не изменено."
        exit 0
    fi
    echo ""
    info "Дальше два варианта:"
    info "  да  — обновить закалку сервера: firewall (включая Docker UFW Fix), SSH, Fail2Ban, ядро и сеть, лимиты,"
    info "        анти-флуд, авто-обновления, а затем команду nodectl. Ручные правила UFW сохраняются."
    info "  нет — только установить (обновить) команду nodectl, как делает команда nodectl update-self."
    info "        На сервере больше ничего не меняется."
    if ! confirm "Выполнить обновление и закалку сервера?" "y"; then
        step "Установка команды nodectl (сервер не меняется)"
        install_nodectl
        success "Команда nodectl установлена (наберите: nodectl)"
        info "Закалка, firewall и нода не тронуты. Полная закалка позже: запустите установщик снова и ответьте «да»."
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
# latest (ветка 3.x, для панели 3+) либо конкретную 2.8.0 (последняя в ветке 2.x,
# для панели до версии 3). Выбор зависит от версии панели, а не от «стабильности».
NODE_VERSION="latest"
if [[ $NODE_EXISTS -eq 0 ]]; then
    echo ""
    info "Версия ноды (должна соответствовать версии панели Remnawave):"
    info "  1) latest — для новой панели версии 3 и выше"
    info "  2) 2.8.0  — для панели версии до 3 (ветка 2.x)"
    _vchoice=$(ask "Выберите версию (1/2)" "1")
    case "$_vchoice" in
        2|2.8|2.8.0) NODE_VERSION="2.8.0" ;;
        *)           NODE_VERSION="latest" ;;
    esac
    success "Версия ноды: ${NODE_VERSION}"
fi

# --- Логи ноды: файлы на сервере + ротация (по умолчанию да) ---
NODE_LOGS=1
if grep -q -- '- /var/log/remnanode:/var/log/remnanode' /opt/remnanode/docker-compose.yml 2>/dev/null; then
    info "Логи ноды уже выводятся в файлы /var/log/remnanode — ротация будет проверена."
else
    echo ""
    info "Логи Xray (access.log, error.log) можно писать в файлы на сервере: ${CYAN}/var/log/remnanode${RESET}"
    info "с ротацией logrotate (50 МБ × 5 архивов). Иначе они остаются только внутри контейнера."
    if confirm "Выводить логи ноды в файлы с ротацией?" "y"; then NODE_LOGS=1; else NODE_LOGS=0; fi
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
if [[ $NODE_LOGS -eq 1 ]]; then
    echo -e "  Логи ноды:       ${CYAN}/var/log/remnanode${RESET} ${GRAY}+ ротация 50 МБ × 5${RESET}"
else
    echo -e "  Логи ноды:       ${GRAY}внутри контейнера (docker logs)${RESET}"
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

if [[ $NODE_EXISTS -eq 1 ]]; then
    info "Режим обновления: существующие правила UFW (в т.ч. добавленные вручную) сохраняю."
else
    info "Сбрасываю старые правила UFW..."
    ufw --force reset >/dev/null
fi
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
        # Том логов — тем же маркированным блоком, которым потом управляет nodectl (пункт «l»).
        LOGS_VOLUME_BLOCK=""
        if [[ $NODE_LOGS -eq 1 ]]; then
            LOGS_VOLUME_BLOCK=$(printf '    # %s-volbegin\n    volumes:\n      - /var/log/remnanode:/var/log/remnanode\n    # %s-volend\n' "$(tok vol)" "$(tok vol)")$'\n'
        fi
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
${LOGS_VOLUME_BLOCK}    environment:
      - NODE_PORT=${NODE_PORT}
      - SECRET_KEY="${SECRET_KEY}"
EOF
        chmod 0600 /opt/remnanode/docker-compose.yml
        [[ $NODE_LOGS -eq 1 ]] && { mkdir -p /var/log/remnanode; chmod 0755 /var/log/remnanode; }

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

# --- Логи ноды в файлах + ротация (та же логика, что в nodectl → пункт «l») ---
if [[ $NODE_LOGS -eq 1 && -f /opt/remnanode/docker-compose.yml ]]; then
    info "Логи ноды: файлы /var/log/remnanode + ротация logrotate..."
    if install_node_logs; then
        success "Логи ноды пишутся в /var/log/remnanode (access.log, error.log), ротация 50 МБ × 5."
        step_ok "9/10 Логи ноды (файлы + ротация)"
    else
        step_fail "9/10 Логи ноды (см. сообщения выше)"
    fi
elif [[ $NODE_LOGS -eq 1 ]]; then
    warn "Логи ноды: нода не установлена — пропуск."
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

    # Дописываем блок ОТДЕЛЬНОЙ секцией *filter ... COMMIT в конец файла.
    # Почему так: ufw-init грузит файлы в порядке before.rules → after.rules → user.rules,
    # а свои цепочки ufw-user-* создаёт только ПОСЛЕ after.rules. Если сослаться на
    # ufw-user-forward, не объявив её, `ufw enable` после `ufw disable` падает с
    # "Chain 'ufw-user-forward' does not exist". Объявление `:ufw-user-forward - [0:0]`
    # при restore с -n безопасно: существующая цепочка не сбрасывается (как в ufw-docker).
    python3 - "$after_rules" "$marker_start" "$marker_end" "$iface" <<'PYEOF'
import sys
rules_file, marker_s, marker_e, iface = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(rules_file, 'r') as f:
    content = f.read()

docker_block = f"""
{marker_s}
# Эти правила заставляют Docker-трафик проходить через фильтрацию UFW.
# Отдельная секция *filter: ufw создаёт ufw-user-forward уже после after.rules,
# поэтому цепочку объявляем сами (с -n существующая цепочка не сбрасывается).
*filter
:ufw-user-forward - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -i {iface} -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN
-A DOCKER-USER -i {iface} -j ufw-user-forward
-A DOCKER-USER -i {iface} -j DROP
-A DOCKER-USER -j RETURN
COMMIT
{marker_e}
"""

content = content.rstrip('\n') + '\n' + docker_block
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
    local reload_out
    if reload_out=$(ufw reload 2>&1); then
        return 0
    else
        warn "ufw reload завершился с ошибкой, блок Docker UFW Fix мог не примениться:"
        echo "$reload_out" | sed 's/^/    /'
        return 1
    fi
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
install_nodectl
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
info "Маскировка Reality (Selfsteal), Psiphon, WARP и прочее — через команду: nodectl"
echo ""
