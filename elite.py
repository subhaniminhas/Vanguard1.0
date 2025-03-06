#!/usr/bin/env python3
"""
Vanguard Elite Interactive Tool (Updated for Enhanced Security)
An interactive GUI to apply runtime hardening measures and run system audits on a Debian‑based server.
Features include:
  • Reloading UFW firewall rules
  • Restarting Fail2Ban service
  • Reloading AppArmor profiles (securely processing each profile file)
  • Running a Lynis system audit
  • Configuring GRUB secure settings (using secure, user-provided credentials)
"""

import os
import sys
import subprocess
import threading
import logging
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import glob

# Setup secure logging: log file should be protected with appropriate permissions.
LOG_FILE = "/var/log/vanguard_tool.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a'),
        logging.StreamHandler()
    ]
)

def ensure_root():
    """Ensure the script is executed with root privileges."""
    if os.geteuid() != 0:
        messagebox.showerror("Permission Error", "This script must be run as root!")
        sys.exit(1)

# Secure the script file permissions if possible
try:
    os.chmod(__file__, 0o700)
except Exception as e:
    logging.warning(f"Could not set secure permissions on the script: {e}")

ensure_root()

class EliteGUI:
    """Main GUI class for the Vanguard Elite tool."""
    def __init__(self, master):
        self.master = master
        master.title("Vanguard Elite")
        master.geometry("600x500")
        master.configure(bg="#2d2d2d")

        self.status_var = tk.StringVar()
        self.status_var.set("Welcome to Vanguard Elite")

        self.status_label = ttk.Label(
            master, textvariable=self.status_var,
            foreground="white", background="#2d2d2d", font=("Arial", 12)
        )
        self.status_label.pack(pady=10)

        self.text_area = tk.Text(master, height=20, width=70, bg="#1e1e1e", fg="white")
        self.text_area.pack(pady=10)

        self.menu_frame = ttk.Frame(master)
        self.menu_frame.pack(pady=10)

        # Buttons for various security tasks
        self.button_firewall = ttk.Button(
            self.menu_frame, text="Reload Firewall", command=self.reload_firewall
        )
        self.button_firewall.grid(row=0, column=0, padx=5, pady=5)

        self.button_fail2ban = ttk.Button(
            self.menu_frame, text="Restart Fail2Ban", command=self.restart_fail2ban
        )
        self.button_fail2ban.grid(row=0, column=1, padx=5, pady=5)

        self.button_apparmor = ttk.Button(
            self.menu_frame, text="Reload AppArmor", command=self.reload_apparmor
        )
        self.button_apparmor.grid(row=1, column=0, padx=5, pady=5)

        self.button_audit = ttk.Button(
            self.menu_frame, text="Run Lynis Audit", command=self.run_audit
        )
        self.button_audit.grid(row=1, column=1, padx=5, pady=5)

        self.button_grub = ttk.Button(
            self.menu_frame, text="Configure GRUB", command=self.configure_grub
        )
        self.button_grub.grid(row=2, column=0, padx=5, pady=5)

        self.button_exit = ttk.Button(
            self.menu_frame, text="Exit", command=master.quit
        )
        self.button_exit.grid(row=2, column=1, padx=5, pady=5)

    def update_status(self, message):
        """Update status display and log the message securely."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"{timestamp} - {message}\n"
        self.text_area.insert(tk.END, full_message)
        self.text_area.see(tk.END)
        self.status_var.set(message)
        logging.info(message)

    def run_command(self, command):
        """
        Securely run a command using subprocess.run.
        Expects command as a list (avoids shell=True).
        """
        self.update_status(f"Executing: {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False  # We'll handle non-zero return codes manually.
            )
            if result.stdout:
                self.update_status(result.stdout)
            if result.returncode != 0:
                error_msg = f"Error: {result.stderr}"
                self.update_status(error_msg)
                logging.error(error_msg)
        except Exception as e:
            self.update_status(f"Exception occurred: {e}")
            logging.error(e)

    def reload_firewall(self):
        self.update_status("Reloading UFW firewall...")
        self.run_command(["ufw", "reload"])
        messagebox.showinfo("Firewall", "UFW firewall has been reloaded.")

    def restart_fail2ban(self):
        self.update_status("Restarting Fail2Ban service...")
        self.run_command(["systemctl", "restart", "fail2ban"])
        messagebox.showinfo("Fail2Ban", "Fail2Ban has been restarted.")

    def reload_apparmor(self):
        self.update_status("Reloading AppArmor profiles...")
        profile_files = glob.glob("/etc/apparmor.d/*")
        if not profile_files:
            self.update_status("No AppArmor profiles found.")
            return
        for profile in profile_files:
            # Reload each profile individually
            self.run_command(["apparmor_parser", "-r", profile])
        messagebox.showinfo("AppArmor", "AppArmor profiles have been reloaded.")

    def run_audit(self):
        self.update_status("Running Lynis system audit...")
        threading.Thread(target=self._run_audit, daemon=True).start()

    def _run_audit(self):
        self.run_command(["lynis", "audit", "system", "--quick"])
        messagebox.showinfo("Lynis Audit", "Lynis audit completed.")

    def configure_grub(self):
        self.update_status("Configuring GRUB secure settings...")
        # Prompt the user for a GRUB password securely.
        password = simpledialog.askstring("GRUB Password", "Enter a secure GRUB password:", show="*")
        if not password:
            self.update_status("GRUB configuration aborted (no password provided).")
            return
        confirm = simpledialog.askstring("GRUB Confirmation", "Confirm GRUB password:", show="*")
        if password != confirm:
            self.update_status("Passwords do not match. Aborting GRUB configuration.")
            messagebox.showerror("GRUB", "Passwords do not match. Please try again.")
            return

        # Use pexpect to generate a PBKDF2 hash of the GRUB password securely
        try:
            import pexpect
        except ImportError:
            self.update_status("pexpect module not found. Cannot configure GRUB securely.")
            logging.error("pexpect module required for GRUB configuration.")
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
            self.update_status(f"Error generating GRUB hash: {e}")
            logging.error(e)
            return

        hashed_password = ""
        for line in output.splitlines():
            if "PBKDF2 hash of your password is" in line:
                hashed_password = line.split("is ")[1].strip()
                break
        if not hashed_password:
            self.update_status("Failed to generate GRUB hash.")
            return

        grub_config = f'set superusers="admin"\npassword_pbkdf2 admin {hashed_password}\n'
        config_path = "/etc/grub.d/00_password"
        try:
            with open(config_path, "w") as f:
                f.write(grub_config)
            os.chmod(config_path, 0o600)
            self.run_command(["update-grub"])
            messagebox.showinfo("GRUB", "GRUB has been secured with a password.")
        except Exception as e:
            self.update_status(f"Error configuring GRUB: {e}")
            logging.error(e)

def main():
    root = tk.Tk()
    app = EliteGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
