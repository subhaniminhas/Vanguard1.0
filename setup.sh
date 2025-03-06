#!/bin/bash
# Vanguard Elite - Setup Script
# This script installs all dependencies and applies base hardening measures on Debian‑based servers.
# It installs system packages, Python libraries, configures UFW, Fail2Ban, AppArmor,
# sets up cron jobs, and applies additional security measures.
#
# Core libraries: shlex, subprocess, sys, os, logging, threading, datetime, pexpect, shutil
# GUI: tkinter (with ttk)
# SEC/MONITOR: lynis, selinux, fail2ban, ufw, apparmor, firejail, debsums, tcpd
# PKG MANAGER/TOOLS: requests, setuptools
#
# Project: Vanguard Elite
# Improved by AI
#
# Run this script as root (sudo ./setup.sh)

set -euo pipefail
IFS=$'\n\t'

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Verify Debian‑based system
if ! grep -qiE "debian|ubuntu" /etc/os-release; then
    echo "This script is intended for Debian‑based systems only."
    exit 1
fi

echo "---------------------------------------------"
echo " Vanguard Elite Setup Initialization"
echo "---------------------------------------------"

echo "[+] Updating package repositories..."
apt-get update

echo "[+] Installing essential system packages..."
ESSENTIAL_PACKAGES=(
    python3
    python3-pip
    python3-tk
    ufw
    fail2ban
    apparmor
    apparmor-utils
    firejail
    tcpd
    lynis
    debsums
    rkhunter
    wget
    curl
    git
    selinux-basics
    selinux-policy-default
    macchanger
)
for pkg in "${ESSENTIAL_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo "Installing $pkg..."
        apt-get install -y "$pkg"
    else
        echo "$pkg is already installed."
    fi
done

echo "[+] Upgrading pip and installing required Python libraries..."
python3 -m pip install --upgrade pip setuptools requests pexpect

# Generate a requirements.txt file for record-keeping
python3 -m pip freeze > requirements.txt
echo "[+] Python dependencies installed. See requirements.txt for details."

# Configure UFW firewall with secure defaults
echo "[+] Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing
# Allow essential services: SSH (port 22)
ufw allow 22/tcp
ufw --force enable
ufw reload

# Enable Fail2Ban and AppArmor services
echo "[+] Enabling Fail2Ban and AppArmor..."
systemctl enable --now fail2ban
systemctl enable --now apparmor

# Setup cron jobs for regular security audits and system updates
echo "[+] Configuring cron jobs..."
CRON_JOB_FILE="/tmp/vanguard_cron_jobs"
cat <<EOF > "$CRON_JOB_FILE"
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 2 * * * apt-get update && apt-get upgrade -y
EOF
crontab "$CRON_JOB_FILE"
rm -f "$CRON_JOB_FILE"

# Disable USB storage by blacklisting the module (optional but recommended)
echo "[+] Disabling USB storage..."
echo 'blacklist usb-storage' > /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage || echo "[-] USB storage module could not be unloaded; it might be in use."

# Perform a final system update and upgrade
echo "[+] Performing final system update..."
apt-get update && apt-get upgrade -y

echo "---------------------------------------------"
echo "[+] Vanguard Elite Setup Complete!"
echo "     You can now run the interactive tool with: python3 elite.py"
echo "---------------------------------------------"
