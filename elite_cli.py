#!/usr/bin/env python3
"""
Vanguard Elite Command Line Tool
This tool applies runtime hardening measures and runs system audits on a Debian‑based server.
Features include:
  • Reloading UFW firewall rules
  • Restarting Fail2Ban service
  • Reloading AppArmor profiles
  • Running a Lynis system audit
  • Configuring GRUB secure settings (via secure, user-provided credentials)
"""

import os
import sys
import subprocess
import threading
import logging
import glob
from datetime import datetime
import getpass

# Setup secure logging; ensure the log file has proper permissions.
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
    """Ensure this script is run as root."""
    if os.geteuid() != 0:
        sys.stderr.write("This tool must be run as root.\n")
        sys.exit(1)

ensure_root()

def update_status(message):
    """Prints and logs the given message with a timestamp."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    full_message = f"{timestamp} - {message}"
    print(full_message)
    logging.info(message)

def run_command(command):
    """
    Runs a command securely without shell=True.
    Expects the command as a list.
    """
    update_status("Executing: " + " ".join(command))
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
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
    profile_files = glob.glob("/etc/apparmor.d/*")
    if not profile_files:
        update_status("No AppArmor profiles found.")
        return
    for profile in profile_files:
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
        update_status("Error: pexpect module not found. Please install it (pip install pexpect).")
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

def main_menu():
    """Displays a text-based menu for user interaction."""
    update_status("Welcome to Vanguard Elite CLI Tool")
    menu = """
Select a task:
  1. Reload Firewall (UFW)
  2. Restart Fail2Ban
  3. Reload AppArmor Profiles
  4. Run Lynis Audit
  5. Configure GRUB Secure Settings
  6. Exit
"""
    while True:
        print(menu)
        choice = input("Enter choice [1-6]: ").strip()
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
            update_status("Exiting Vanguard Elite CLI Tool.")
            sys.exit(0)
        else:
            update_status("Invalid selection. Please choose a number between 1 and 6.")

if __name__ == "__main__":
    main_menu()
