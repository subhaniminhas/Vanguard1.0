#!/usr/bin/env python3
"""
Vanguard Elite Interactive Tool (Enhanced Hardening)
An interactive GUI to apply runtime hardening measures and run system audits on a Debian‑based server.
Features include:
  • Reloading UFW firewall rules
  • Restarting Fail2Ban service
  • Reloading AppArmor profiles
  • Running a Lynis system audit
  • Configuring GRUB secure settings (using secure, user‑provided credentials)
  • Applying Advanced Hardening Settings (sysctl‑based)
  • Applying SSH Hardening Settings (updating /etc/ssh/sshd_config)
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
import shutil

# Setup secure logging.
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
    if os.geteuid() != 0:
        messagebox.showerror("Permission Error", "This script must be run as root!")
        sys.exit(1)

try:
    os.chmod(__file__, 0o700)
except Exception as e:
    logging.warning(f"Could not set secure permissions on the script: {e}")

ensure_root()

def check_display():
    if not os.environ.get("DISPLAY"):
        sys.stderr.write("Error: No display found. This GUI requires an X display.\n"
                         "Use 'ssh -X' or a virtual framebuffer (e.g., xvfb-run python3 elite.py).\n")
        sys.exit(1)

class EliteGUI:
    def __init__(self, master):
        self.master = master
        master.title("Vanguard Elite")
        master.geometry("600x650")
        master.configure(bg="#2d2d2d")

        self.status_var = tk.StringVar()
        self.status_var.set("Welcome to Vanguard Elite")

        self.status_label = ttk.Label(master, textvariable=self.status_var,
                                      foreground="white", background="#2d2d2d", font=("Arial", 12))
        self.status_label.pack(pady=10)

        self.text_area = tk.Text(master, height=26, width=70, bg="#1e1e1e", fg="white")
        self.text_area.pack(pady=10)

        self.menu_frame = ttk.Frame(master)
        self.menu_frame.pack(pady=10)

        # Row 0
        self.button_firewall = ttk.Button(self.menu_frame, text="Reload Firewall", command=self.reload_firewall)
        self.button_firewall.grid(row=0, column=0, padx=5, pady=5)
        self.button_fail2ban = ttk.Button(self.menu_frame, text="Restart Fail2Ban", command=self.restart_fail2ban)
        self.button_fail2ban.grid(row=0, column=1, padx=5, pady=5)
        # Row 1
        self.button_apparmor = ttk.Button(self.menu_frame, text="Reload AppArmor", command=self.reload_apparmor)
        self.button_apparmor.grid(row=1, column=0, padx=5, pady=5)
        self.button_audit = ttk.Button(self.menu_frame, text="Run Lynis Audit", command=self.run_audit)
        self.button_audit.grid(row=1, column=1, padx=5, pady=5)
        # Row 2
        self.button_grub = ttk.Button(self.menu_frame, text="Configure GRUB", command=self.configure_grub)
        self.button_grub.grid(row=2, column=0, padx=5, pady=5)
        self.button_advanced = ttk.Button(self.menu_frame, text="Advanced Hardening", command=self.apply_advanced_hardening)
        self.button_advanced.grid(row=2, column=1, padx=5, pady=5)
        # Row 3
        self.button_ssh = ttk.Button(self.menu_frame, text="SSH Hardening", command=self.apply_ssh_hardening)
        self.button_ssh.grid(row=3, column=0, padx=5, pady=5)
        # Row 4
        self.button_exit = ttk.Button(self.menu_frame, text="Exit", command=master.quit)
        self.button_exit.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def update_status(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"{timestamp} - {message}\n"
        self.text_area.insert(tk.END, full_message)
        self.text_area.see(tk.END)
        self.status_var.set(message)
        logging.info(message)

    def run_command(self, command):
        self.update_status(f"Executing: {' '.join(command)}")
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
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
        profiles = glob.glob("/etc/apparmor.d/*")
        if not profiles:
            self.update_status("No AppArmor profiles found.")
            return
        for profile in profiles:
            self.run_command(["apparmor_parser", "-r", profile])
        messagebox.showinfo("AppArmor", "AppArmor profiles reloaded.")

    def run_audit(self):
        self.update_status("Running Lynis system audit...")
        threading.Thread(target=self._run_audit, daemon=True).start()

    def _run_audit(self):
        self.run_command(["lynis", "audit", "system", "--quick"])
        messagebox.showinfo("Lynis Audit", "Lynis audit completed.")

    def configure_grub(self):
        self.update_status("Configuring GRUB secure settings...")
        password = simpledialog.askstring("GRUB Password", "Enter a secure GRUB password:", show="*")
        if not password:
            self.update_status("GRUB configuration aborted (no password provided).")
            return
        confirm = simpledialog.askstring("GRUB Confirmation", "Confirm GRUB password:", show="*")
        if password != confirm:
            self.update_status("Passwords do not match. Aborting GRUB configuration.")
            messagebox.showerror("GRUB", "Passwords do not match.")
            return
        try:
            import pexpect
        except ImportError:
            self.update_status("pexpect module not found. Cannot configure GRUB securely.")
            logging.error("pexpect module required.")
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
            messagebox.showinfo("GRUB", "GRUB secured with a password.")
        except Exception as e:
            self.update_status(f"Error configuring GRUB: {e}")
            logging.error(e)

    def apply_advanced_hardening(self):
        self.update_status("Applying advanced hardening settings...")
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
            self.run_command(["sysctl", "--system"])
            self.update_status("Advanced hardening settings applied successfully!")
            messagebox.showinfo("Advanced Hardening", "Advanced hardening settings have been applied.")
        except Exception as e:
            self.update_status(f"Error applying advanced hardening: {e}")
            logging.error(e)

    def apply_ssh_hardening(self):
        self.update_status("Applying SSH hardening settings...")
        proceed = messagebox.askyesno("SSH Hardening", 
            "This will modify /etc/ssh/sshd_config to disable root login, disable password authentication, "
            "and adjust additional parameters. Do you want to proceed?")
        if not proceed:
            self.update_status("SSH hardening aborted.")
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
            self.run_command(["systemctl", "restart", "ssh"])
            self.update_status("SSH hardening applied. Backup saved as /etc/ssh/sshd_config.bak")
            messagebox.showinfo("SSH Hardening", "SSH hardening applied successfully.")
        except Exception as e:
            self.update_status(f"Error applying SSH hardening: {e}")
            logging.error(e)

def main():
    check_display()
    root = tk.Tk()
    app = EliteGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
