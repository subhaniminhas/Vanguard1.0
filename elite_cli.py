#!/usr/bin/env python3
"""
Vanguard Elite Command Line Tool (Enhanced Hardening)
This tool applies runtime hardening measures and runs system audits on a Debian‑based server.
Features include:
  • Reloading UFW firewall rules
  • Restarting Fail2Ban service
  • Reloading AppArmor profiles
  • Running a Lynis system audit
  • Configuring GRUB secure settings (with secure credentials)
  • Applying Advanced Hardening Settings (sysctl‑based)
  • Applying SSH Hardening Settings (modifying /etc/ssh/sshd_config)
"""

import os
import sys
import subprocess
import logging
import glob
from datetime import datetime
import getpass
import shutil

# Setup secure logging.
LOG_FILE = "/var/log/vanguard_tool_cli.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a'),
        logging.StreamHandler()
    ]
)

def ensure_root():
    if os.geteuid() != 0:
        sys.stderr.write("This tool must be run as root.\n")
        sys.exit(1)
ensure_root()

def update_status(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    output = f"{timestamp} - {message}"
    print(output)
    logging.info(message)

def run_command(command):
    update_status("Executing: " + " ".join(command))
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stdout:
            update_status(result.stdout.strip())
        if result.returncode != 0:
            err_msg = f"Error: {result.stderr.strip()}"
            update_status(err_msg)
            logging.error(err_msg)
    except Exception as e:
        update_status("Exception: " + str(e))
        logging.error(e)

def reload_firewall():
    update_status("Reloading UFW firewall...")
    run_command(["ufw", "reload"])
    update_status("UFW firewall has been reloaded.")

def restart_fail2ban():
    update_status("Restarting Fail2Ban service...")
    run_command(["systemctl", "restart", "fail2ban"])
    update_status("Fail2Ban has been restarted.")

def reload_apparmor():
    update_status("Reloading AppArmor profiles...")
    profiles = glob.glob("/etc/apparmor.d/*")
    if not profiles:
        update_status("No AppArmor profiles found.")
        return
    for profile in profiles:
        run_command(["apparmor_parser", "-r", profile])
    update_status("AppArmor profiles have been reloaded.")

def run_audit():
    update_status("Running Lynis system audit...")
    run_command(["lynis", "audit", "system", "--quick"])
    update_status("Lynis audit completed.")

def configure_grub():
    update_status("Configuring GRUB secure settings...")
    try:
        import pexpect
    except ImportError:
        update_status("Error: pexpect module not found. Install with 'pip install pexpect'.")
        return
    password = getpass.getpass("Enter a secure GRUB password: ")
    confirm = getpass.getpass("Confirm GRUB password: ")
    if password != confirm:
        update_status("Passwords do not match. Aborting GRUB configuration.")
        return
    try:
        child = pexpect.spawn("grub-mkpasswd-pbkdf2", encoding="utf-8")
        child.expect("Enter password:")
        child.sendline(password)
        child.expect("Reenter password:")
        child.sendline(password)
        child.expect(pexpect.EOF)
        output = child.before
    except Exception as e:
        update_status("Error generating GRUB hash: " + str(e))
        logging.error(e)
        return
    hashed_password = ""
    for line in output.splitlines():
        if "PBKDF2 hash of your password is" in line:
            hashed_password = line.split("is ")[1].strip()
            break
    if not hashed_password:
        update_status("Failed to generate GRUB hash.")
        return
    grub_config = f'set superusers="admin"\npassword_pbkdf2 admin {hashed_password}\n'
    config_path = "/etc/grub.d/00_password"
    try:
        with open(config_path, "w") as f:
            f.write(grub_config)
        os.chmod(config_path, 0o600)
        run_command(["update-grub"])
        update_status("GRUB has been secured with a password.")
    except Exception as e:
        update_status("Error configuring GRUB: " + str(e))
        logging.error(e)

def apply_advanced_hardening():
    update_status("Applying advanced hardening settings...")
    sysctl_conf = (
        "# Advanced hardening settings for maximum security\n"
        "dev.tty.ldisc_autoload = 0\n"
        "net.ipv4.tcp_syncookies = 1\n"
        "net.ipv4.conf.all.rp_filter = 1\n"
        "net.ipv4.conf.default.rp_filter = 1\n"
        "net.ipv4.conf.all.accept_source_route = 0\n"
        "net.ipv4.conf.default.accept_source_route = 0\n"
        "net.ipv4.conf.all.accept_redirects = 0\n"
        "net.ipv4.conf.default.accept_redirects = 0\n"
        "net.ipv4.conf.all.secure_redirects = 0\n"
        "net.ipv4.conf.default.secure_redirects = 0\n"
        "net.ipv4.icmp_echo_ignore_broadcasts = 1\n"
        "net.ipv4.icmp_ignore_bogus_error_responses = 1\n"
        "net.ipv4.conf.all.log_martians = 1\n"
        "net.ipv4.conf.default.log_martians = 1\n"
        "net.ipv4.conf.all.send_redirects = 0\n"
        "fs.protected_fifos = 2\n"
        "fs.protected_hardlinks = 1\n"
        "fs.protected_regular = 2\n"
        "fs.protected_symlinks = 1\n"
        "fs.suid_dumpable = 0\n"
        "kernel.core_uses_pid = 1\n"
        "kernel.randomize_va_space = 2\n"
        "kernel.kptr_restrict = 2\n"
        "kernel.modules_disabled = 1\n"
        "kernel.sysrq = 0\n"
        "kernel.unprivileged_bpf_disabled = 1\n"
        "kernel.yama.ptrace_scope = 1\n"
        "net.core.bpf_jit_harden = 2\n"
        "net.ipv4.tcp_fin_timeout = 15\n"
        "net.ipv6.conf.all.disable_ipv6 = 1\n"
        "net.ipv6.conf.default.disable_ipv6 = 1\n"
    )
    try:
        with open("/etc/sysctl.d/99-hardening.conf", "w") as f:
            f.write(sysctl_conf)
        os.chmod("/etc/sysctl.d/99-hardening.conf", 0o600)
        run_command(["sysctl", "--system"])
        update_status("Advanced hardening settings applied successfully!")
    except Exception as e:
        update_status("Error applying advanced hardening: " + str(e))
        logging.error(e)

def apply_ssh_hardening():
    update_status("Applying SSH hardening settings...")
    choice = input("This will modify /etc/ssh/sshd_config to disable root login, disable password authentication, and adjust additional parameters.\nProceed? (y/n): ").strip().lower()
    if choice != "y":
        update_status("SSH hardening aborted.")
        return
    try:
        shutil.copy("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.bak")
        with open("/etc/ssh/sshd_config", "r") as f:
            lines = f.readlines()
        new_lines = []
        keys = {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PermitEmptyPasswords": "no",
            "ChallengeResponseAuthentication": "no",
            "AllowTcpForwarding": "no",
            "ClientAliveCountMax": "2",
            "Compression": "no",
            "LogLevel": "VERBOSE",
            "MaxAuthTries": "3",
            "MaxSessions": "2",
            "TCPKeepAlive": "no",
            "X11Forwarding": "no",
            "AllowAgentForwarding": "no"
        }
        keys_set = {k: False for k in keys}
        for line in lines:
            stripped = line.strip()
            for key in keys:
                if stripped.lower().startswith(key.lower()):
                    line = f"{key} {keys[key]}\n"
                    keys_set[key] = True
            new_lines.append(line)
        for key, value in keys.items():
            if not keys_set[key]:
                new_lines.append(f"{key} {value}\n")
        with open("/etc/ssh/sshd_config", "w") as f:
            f.writelines(new_lines)
        run_command(["systemctl", "restart", "ssh"])
        update_status("SSH hardening applied. Backup saved as /etc/ssh/sshd_config.bak")
    except Exception as e:
        update_status("Error applying SSH hardening: " + str(e))
        logging.error(e)

def main_menu():
    update_status("Welcome to Vanguard Elite CLI Tool")
    menu = """
Select a task:
  1. Reload Firewall (UFW)
  2. Restart Fail2Ban
  3. Reload AppArmor Profiles
  4. Run Lynis Audit
  5. Configure GRUB Secure Settings
  6. Apply Advanced Hardening Settings
  7. Apply SSH Hardening Settings
  8. Exit
"""
    while True:
        print(menu)
        choice = input("Enter choice [1-8]: ").strip()
        if choice == "1":
            reload_firewall()
        elif choice == "2":
            restart_fail2ban()
        elif choice == "3":
            reload_apparmor()
        elif choice == "4":
            run_audit()
        elif choice == "5":
            configure_grub()
        elif choice == "6":
            apply_advanced_hardening()
        elif choice == "7":
            apply_ssh_hardening()
        elif choice == "8":
            update_status("Exiting Vanguard Elite CLI Tool.")
            sys.exit(0)
        else:
            update_status("Invalid selection. Please choose a number between 1 and 8.")

if __name__ == "__main__":
    main_menu()
