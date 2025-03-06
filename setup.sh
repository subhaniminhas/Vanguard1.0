#!/bin/bash
# Vanguard Elite - Setup Script (Updated for Enhanced Security)
# This script installs dependencies and applies base hardening measures on Debian‑based servers.
# It enforces secure file permissions, minimizes unnecessary package installation,
# and creates secure cron jobs for system audits and updates.

set -euo pipefail
IFS=$'\n\t'

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Verify Debian‑based system
if ! grep -qiE "debian|ubuntu" /etc/os-release; then
    echo "This script is intended for Debian‑based systems only."
    exit 1
fi

# Secure the script file itself
chmod 700 "${BASH_SOURCE[0]}"

echo "---------------------------------------------"
echo " Vanguard Elite Setup Initialization"
echo "---------------------------------------------"

echo "[+] Updating package repositories..."
# (APT by default verifies packages using GPG; ensure your sources list is secure.)
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
        apt-get install -y --no-install-recommends "$pkg"
    else
        echo "$pkg is already installed."
    fi
done

echo "[+] Upgrading pip and installing required Python libraries securely..."
python3 -m pip install --upgrade pip setuptools requests pexpect

# Save Python dependencies with restricted permissions
python3 -m pip freeze > requirements.txt
chmod 600 requirements.txt
echo "[+] Python dependencies installed. See requirements.txt for details."

echo "[+] Configuring UFW firewall with secure defaults..."
ufw default deny incoming
ufw default allow outgoing
# Allow SSH (port 22) only:
ufw allow 22/tcp
ufw --force enable
ufw reload || echo "Warning: UFW reload may have encountered an issue."

echo "[+] Enabling Fail2Ban and AppArmor services..."
systemctl enable --now fail2ban
systemctl enable --now apparmor

echo "[+] Configuring secure cron jobs..."
# Use a secure location for temporary cron configuration
CRON_JOB_FILE="/root/vanguard_cron_jobs"
cat <<EOF > "$CRON_JOB_FILE"
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 2 * * * apt-get update && apt-get upgrade -y
EOF
chmod 600 "$CRON_JOB_FILE"
crontab "$CRON_JOB_FILE"
rm -f "$CRON_JOB_FILE"

echo "[+] Disabling USB storage (if not required)..."
echo 'blacklist usb-storage' > /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage || echo "[-] Warning: Could not unload USB storage module; it may be in active use."

echo "[+] Performing final system update..."
apt-get update && apt-get upgrade -y

echo "---------------------------------------------"
echo "[+] Vanguard Elite Setup Complete!"
echo "     You can now run the interactive tool with: python3 elite.py"
echo "---------------------------------------------"
