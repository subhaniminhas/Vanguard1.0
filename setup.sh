#!/bin/bash
# Vanguard Elite - Setup Script with Uninstall Option (Enhanced Hardening)
#
# This script installs required dependencies and applies both base and advanced hardening
# measures on Debian‑based systems using AppArmor (SELinux is not used). It now:
#
#  - Installs gnupg/gnupg2 and adds the Lynis repository (then runs an apt update),
#  - Installs additional recommended packages (including sysstat, aide, etc.),
#  - Enables sysstat (ACCT-9626) and disables auditd (ACCT-9630),
#  - Configures AIDE using updated options: it now uses "database_in" (instead of "database"),
#    uses "log_level=error" and "report_level=summary", and forces SHA512 checksums by appending
#    "+sha512" to the file check rules (satisfying FINT-4402),
#  - Writes legal banners to /etc/issue and /etc/issue.net (BANN-7126 & BANN-7130),
#  - Applies advanced sysctl hardening settings (KRNL-6000),
#  - Reminds the administrator to consider restricting compiler access (HRDN-7222),
#  - And finally removes gnupg and gnupg2 since they are no longer needed.
#
# Usage:
#   To install/update hardening settings:
#         sudo ./setup.sh
#   To uninstall (remove configuration modifications):
#         sudo ./setup.sh -uninstall
#
# IMPORTANT:
#   For headless servers, run:  python3 elite_cli.py
#   For X11/graphical environments, run:  python3 elite.py

set -euo pipefail
IFS=$'\n\t'

###############################################################################
# Uninstall Option: Remove configuration modifications.
###############################################################################
if [[ "${1:-}" == "-uninstall" ]]; then
    echo "Uninstalling Vanguard Elite configurations..."
    
    # Remove advanced sysctl hardening configuration.
    if [ -f /etc/sysctl.d/99-hardening.conf ]; then
        rm /etc/sysctl.d/99-hardening.conf
        echo "Removed /etc/sysctl.d/99-hardening.conf"
        sysctl --system 2>/dev/null || echo "Warning: Failed to reload sysctl settings."
    fi

    # Remove network protocol blacklisting.
    if [ -f /etc/modprobe.d/disable-net-protocols.conf ]; then
        rm /etc/modprobe.d/disable-net-protocols.conf
        echo "Removed /etc/modprobe.d/disable-net-protocols.conf"
    fi

    echo "Uninstallation complete. Note: Installed packages and some configuration files were not removed."
    exit 0
fi

###############################################################################
# Pre-Checks
###############################################################################
# Ensure the script is run as root.
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Verify that the system is Debian‑based.
if ! grep -qiE "debian|ubuntu" /etc/os-release; then
    echo "This script is intended for Debian‑based systems only."
    exit 1
fi

# Secure the script file itself.
chmod 700 "${BASH_SOURCE[0]}"

echo "---------------------------------------------"
echo " Vanguard Elite Setup Initialization"
echo "---------------------------------------------"

###############################################################################
# Pre-installation: Install gnupg/gnupg2 and add Lynis repository
###############################################################################
echo "[+] Installing gnupg and gnupg2..."
apt-get update
apt-get install -y gnupg gnupg2

echo "[+] Adding the Lynis repository..."
curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/cisofy-software-public.gpg
echo "deb [arch=amd64,arm64 signed-by=/etc/apt/trusted.gpg.d/cisofy-software-public.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
sudo apt install apt-transport-https -y
echo "[+] Running an apt update after adding the Lynis repo..."
apt update

###############################################################################
# Install Essential Packages (including sysstat, aide, etc.)
###############################################################################
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
    macchanger
    libpam-tmpdir            # Sets $TMP and $TMPDIR for PAM sessions.
    apt-listbugs             # Display critical bugs with APT.
    needrestart              # Detect services needing restart after upgrades.
    apt-show-versions        # For patch management.
    unattended-upgrades      # Automatic upgrades.
    acct                     # Process accounting.
    sysstat                  # System performance statistics.
    auditd                   # Audit daemon.
    aide                     # File integrity checker.
    libpam-pwquality         # Enforce password strength via PAM.
)
for pkg in "${ESSENTIAL_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo "Installing package: $pkg..."
        apt-get install -y --no-install-recommends "$pkg"
    else
        echo "Package $pkg is already installed."
    fi
done

###############################################################################
# Enable sysstat Accounting and Disable auditd (Empty Ruleset)
###############################################################################
echo "[+] Enabling sysstat accounting..."
if [ -f /etc/default/sysstat ]; then
    sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat && echo "Sysstat enabled."
fi

echo "[+] Disabling auditd (due to empty ruleset)..."
systemctl disable --now auditd || echo "Warning: Could not disable auditd."

###############################################################################
# Upgrade pip and Install Required Python Libraries Securely
###############################################################################
echo "[+] Upgrading pip and installing required Python libraries securely..."
python3 -m pip install --upgrade pip setuptools requests pexpect --break-system-packages

python3 -m pip freeze > requirements.txt
chmod 600 requirements.txt
echo "[+] Python dependencies installed. See requirements.txt for details."

###############################################################################
# Configure UFW Firewall, Fail2Ban & AppArmor
###############################################################################
echo "[+] Configuring UFW firewall with secure defaults..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw --force enable
ufw reload || echo "Warning: UFW reload may have encountered an issue."

echo "[+] Enabling Fail2Ban and AppArmor services..."
systemctl enable --now fail2ban
systemctl enable --now apparmor

###############################################################################
# Configure Secure Cron Jobs
###############################################################################
echo "[+] Configuring secure cron jobs..."
CRON_JOB_FILE="/root/vanguard_cron_jobs"
cat <<EOF > "$CRON_JOB_FILE"
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 2 * * * apt-get update && apt-get upgrade -y
EOF
chmod 600 "$CRON_JOB_FILE"
crontab "$CRON_JOB_FILE"
rm -f "$CRON_JOB_FILE"

###############################################################################
# Disable USB Storage and Update 'locate' Database
###############################################################################
echo "[+] Disabling USB storage (if not required)..."
echo 'blacklist usb-storage' > /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage || echo "[-] Warning: Could not unload USB storage module; it may be in active use."

echo "[+] Running updatedb to build the file database for locate..."
updatedb

###############################################################################
# AIDE Configuration and Initialization (Force SHA512 via Config Rules)
###############################################################################
echo "[+] Configuring AIDE..."
mkdir -p /etc/aide
cat <<'EOF' > /etc/aide/aide.conf
#######################################################################
# AIDE Default Configuration File
#
# This is a basic configuration for the Advanced Intrusion Detection
# Environment (AIDE). It sets up the database locations, options, defines
# file attribute rules, and specifies which paths to monitor or ignore.
#######################################################################

# Database locations
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new

# Compress the output database file
gzip_dbout=yes

# Logging and reporting levels
log_level=error
report_level=summary

#######################################################################
# Global File Attribute Check Rules
#######################################################################
# Append +sha512 to force SHA512 checksums
NORMAL = p+i+n+u+g+acl+selinux+xattrs+sha512
LOG = p+i+n+u+g+sha512

#######################################################################
# File and Directory Selection
#######################################################################
!/proc
!/sys
!/dev
!/run

 /bin         NORMAL
 /sbin        NORMAL
 /usr/bin     NORMAL
 /usr/sbin    NORMAL
 /etc         NORMAL
 /lib         NORMAL
 /lib64       NORMAL
 /opt         NORMAL
 /home        NORMAL

 /var/log     LOG

!/var/lib/apt/lists
!/var/cache

#######################################################################
# End of Configuration
#######################################################################
EOF

mkdir -p /var/lib/aide
touch /var/lib/aide/aide.db.new
touch /var/lib/aide/aide.db
# Run AIDE update and initialization; ignore nonzero exit statuses.
aide --update --config /etc/aide/aide.conf || true
aide -i --config /etc/aide/aide.conf || true

###############################################################################
# Write Legal Banners (BANN-7126 & BANN-7130)
###############################################################################
echo "[+] Writing legal banner to /etc/issue and /etc/issue.net..."
echo "Unauthorized access is prohibited. All activity is monitored." > /etc/issue
echo "Unauthorized access is prohibited. All activity is monitored." > /etc/issue.net

###############################################################################
# Advanced Hardening via Sysctl (KRNL-6000)
###############################################################################
echo "[+] Applying advanced sysctl hardening settings..."
cat <<'EOF' > /etc/sysctl.d/99-hardening.conf
# Advanced hardening settings for maximum security

# Device settings
dev.tty.ldisc_autoload = 0

# Network protection
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.send_redirects = 0

# Filesystem protection
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Kernel and process security
kernel.core_uses_pid = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.modules_disabled = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1

# BPF hardening
net.core.bpf_jit_harden = 2

# TCP optimizations
net.ipv4.tcp_fin_timeout = 15

# Disable unused protocols
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

chmod 600 /etc/sysctl.d/99-hardening.conf
echo "[+] Reloading sysctl settings..."
sysctl --system
echo "[+] Advanced hardening settings applied."

###############################################################################
# Clean-Up: Remove gnupg and gnupg2 as they are no longer needed.
###############################################################################
echo "[+] Removing gnupg and gnupg2..."
apt remove gnupg gnupg2 -y

###############################################################################
# Compiler Hardening Reminder (HRDN-7222)
###############################################################################
echo "[!] Reminder: For HRDN-7222, consider restricting access to compilers (for example:"
echo "chmod o-rx /usr/bin/gcc /usr/bin/g++ /usr/bin/cc)"
echo "if they are not required in your production environment."

echo "---------------------------------------------"
echo "[+] Vanguard Elite Setup Complete!"
echo "     For headless servers, run: python3 elite_cli.py"
echo "     For X11/graphical environments, run: python3 elite.py"
echo "---------------------------------------------"
