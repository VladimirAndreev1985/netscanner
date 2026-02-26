#!/bin/bash
# NetScanner Installation Script
# Autonomous installer — works without git
# Usage: sudo bash install.sh [--uninstall]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$INSTALL_DIR/venv"
BIN_LINK="/usr/local/bin/netscanner"

banner() {
    echo -e "${GREEN}"
    echo "  _   _      _   ____                                  "
    echo " | \ | | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __ "
    echo " |  \| |/ _ \ __\___ \ / __/ _\` | '_ \| '_ \ / _ \ '__|"
    echo " | |\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |   "
    echo " |_| \_|\___|\__|____/ \___\__,_|_| |_|_| |_|\___|_|   "
    echo -e "${NC}"
    echo -e "${CYAN}  Professional Network Scanner for Kali Linux${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root (sudo bash install.sh)${NC}"
        exit 1
    fi
}

uninstall() {
    echo -e "${YELLOW}[*] Uninstalling NetScanner...${NC}"
    rm -f "$BIN_LINK"
    rm -rf "$VENV_DIR"
    echo -e "${GREEN}[+] NetScanner uninstalled. Project files kept in $INSTALL_DIR${NC}"
    echo -e "${YELLOW}    To fully remove: rm -rf $INSTALL_DIR${NC}"
    exit 0
}

install_system_packages() {
    echo -e "${CYAN}[*] Updating package lists...${NC}"
    apt-get update -qq 2>/dev/null

    # Critical packages (required)
    local critical_pkgs=("nmap" "python3" "python3-pip" "python3-venv" "curl" "wget")
    # Recommended packages (optional but useful)
    local recommended_pkgs=("masscan" "arp-scan" "nbtscan" "snmp" "ffmpeg" "hydra" "net-tools")
    # Metasploit (usually pre-installed in Kali)
    local msf_pkgs=("metasploit-framework" "postgresql")

    echo -e "${CYAN}[*] Installing critical packages...${NC}"
    for pkg in "${critical_pkgs[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $pkg already installed"
        else
            echo -e "  ${YELLOW}[+]${NC} Installing $pkg..."
            apt-get install -y -qq "$pkg" 2>/dev/null || echo -e "  ${RED}[!]${NC} Failed to install $pkg"
        fi
    done

    echo ""
    echo -e "${CYAN}[*] Installing recommended packages...${NC}"
    for pkg in "${recommended_pkgs[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $pkg already installed"
        else
            echo -e "  ${YELLOW}[+]${NC} Installing $pkg..."
            apt-get install -y -qq "$pkg" 2>/dev/null || echo -e "  ${RED}[!]${NC} Failed to install $pkg (optional)"
        fi
    done

    echo ""
    echo -e "${CYAN}[*] Checking Metasploit Framework...${NC}"
    for pkg in "${msf_pkgs[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $pkg already installed"
        else
            echo -e "  ${YELLOW}[+]${NC} Installing $pkg..."
            apt-get install -y -qq "$pkg" 2>/dev/null || echo -e "  ${RED}[!]${NC} Failed to install $pkg (optional)"
        fi
    done

    # Check for searchsploit (exploit-db)
    if command -v searchsploit &>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} searchsploit (exploit-db) available"
    else
        echo -e "  ${YELLOW}[+]${NC} Installing exploitdb..."
        apt-get install -y -qq exploitdb 2>/dev/null || echo -e "  ${RED}[!]${NC} exploitdb not available"
    fi

    # Check for testssl.sh
    if command -v testssl &>/dev/null || command -v testssl.sh &>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} testssl.sh available"
    else
        echo -e "  ${YELLOW}[+]${NC} Installing testssl.sh..."
        apt-get install -y -qq testssl.sh 2>/dev/null || echo -e "  ${RED}[!]${NC} testssl.sh not available"
    fi
}

setup_python_venv() {
    echo ""
    echo -e "${CYAN}[*] Setting up Python virtual environment...${NC}"

    if [ -d "$VENV_DIR" ]; then
        echo -e "  ${YELLOW}[*]${NC} Removing old venv..."
        rm -rf "$VENV_DIR"
    fi

    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    echo -e "  ${GREEN}[+]${NC} Upgrading pip..."
    pip install --upgrade pip -q

    echo -e "  ${GREEN}[+]${NC} Installing Python dependencies..."
    pip install -r "$INSTALL_DIR/requirements.txt" -q

    deactivate
    echo -e "  ${GREEN}[✓]${NC} Python environment ready"
}

create_launcher() {
    echo ""
    echo -e "${CYAN}[*] Creating launcher script...${NC}"

    cat > "$BIN_LINK" << 'LAUNCHER'
#!/bin/bash
SCRIPT_DIR="INSTALL_DIR_PLACEHOLDER"
source "$SCRIPT_DIR/venv/bin/activate"
exec python3 "$SCRIPT_DIR/netscanner.py" "$@"
LAUNCHER

    sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g" "$BIN_LINK"
    chmod +x "$BIN_LINK"
    echo -e "  ${GREEN}[✓]${NC} Launcher created: $BIN_LINK"
    echo -e "  ${GREEN}[✓]${NC} You can now run: ${BOLD}sudo netscanner${NC}"
}

setup_msfdb() {
    echo ""
    echo -e "${CYAN}[*] Checking Metasploit database...${NC}"
    if command -v msfdb &>/dev/null; then
        if ! sudo -u postgres psql -lqt 2>/dev/null | grep -q msf; then
            echo -e "  ${YELLOW}[+]${NC} Initializing msfdb..."
            msfdb init 2>/dev/null || echo -e "  ${RED}[!]${NC} msfdb init failed (non-critical)"
        else
            echo -e "  ${GREEN}[✓]${NC} msfdb already initialized"
        fi
    else
        echo -e "  ${YELLOW}[!]${NC} msfdb not found (Metasploit may not be installed)"
    fi
}

create_directories() {
    echo ""
    echo -e "${CYAN}[*] Setting up directories...${NC}"
    mkdir -p "$INSTALL_DIR/reports"
    mkdir -p "$INSTALL_DIR/data"
    chmod -R 755 "$INSTALL_DIR"
    echo -e "  ${GREEN}[✓]${NC} Directories ready"
}

main() {
    banner

    if [ "$1" = "--uninstall" ]; then
        check_root
        uninstall
    fi

    check_root

    echo -e "${BOLD}[*] Installing NetScanner to: $INSTALL_DIR${NC}"
    echo ""

    install_system_packages
    setup_python_venv
    create_launcher
    create_directories
    setup_msfdb

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  NetScanner installed successfully!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Run:  ${BOLD}sudo netscanner${NC}           — Launch TUI"
    echo -e "  Run:  ${BOLD}sudo netscanner --help${NC}     — Show help"
    echo -e "  Run:  ${BOLD}sudo netscanner --update${NC}   — Update CVE database"
    echo ""
}

main "$@"
