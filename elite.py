#!/usr/bin/env python3
"""
Vanguard Elite Interactive Tool
This script provides an interactive GUI to apply runtime hardening measures,
reload security services, and run system audits on a Debian‑based server.
Features include:
  • Reloading UFW firewall rules
  • Restarting Fail2Ban service
  • Reloading AppArmor profiles
  • Running a Lynis system audit
  • Optionally configuring GRUB secure settings
Author: Vanguard Elite (Improved by AI)
"""

import os
import sys
import subprocess
import threading
import logging
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def ensure_root():
    if os.geteuid() != 0:
        messagebox.showerror("Permission Error", "This script must be run as root!")
        sys.exit(1)

ensure_root()

class EliteGUI:
    def __init__(self, master):
        self.master = master
        master.title("Vanguard Elite")
        master.geometry("600x500")
        master.configure(bg="#2d2d2d")
        
        self.status_var = tk.StringVar()
        self.status_var.set("Welcome to Vanguard Elite")
        
        self.status_label = ttk.Label(master, textvariable=self.status_var,
                                      foreground="white", background="#2d2d2d", font=("Arial", 12))
        self.status_label.pack(pady=10)
        
        self.text_area = tk.Text(master, height=20, width=70, bg="#1e1e1e", fg="white")
        self.text_area.pack(pady=10)
        
        self.menu_frame = ttk.Frame(master)
        self.menu_frame.pack(pady=10)
        
        # Buttons for various security tasks
        self.button_firewall = ttk.Button(self.menu_frame, text="Reload Firewall", command=self.reload_firewall)
        self.button_firewall.grid(row=0, column=0, padx=5, pady=5)
        
        self.button_fail2ban = ttk.Button(self.menu_frame, text="Restart Fail2Ban", command=self.restart_fail2ban)
        self.button_fail2ban.grid(row=0, column=1, padx=5, pady=5)
        
        self.button_apparmor = ttk.Button(self.menu_frame, text="Reload AppArmor", command=self.reload_apparmor)
        self.button_apparmor.grid(row=1, column=0, padx=5, pady=5)
        
        self.button_audit = ttk.Button(self.menu_frame, text="Run Lynis Audit", command=self.run_audit)
        self.button_audit.grid(row=1, column=1, padx=5, pady=5)
        
        self.button_grub = ttk.Button(self.menu_frame, text="Configure GRUB", command=self.configure_grub)
        self.button_grub.grid(row=2, column=0, padx=5, pady=5)
        
        self.button_exit = ttk.Button(self.menu_frame, text="Exit", command=master.quit)
        self.button_exit.grid(row=2, column=1, padx=5, pady=5)
    
    def update_status(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"{timestamp} - {message}\n"
        self.text_area.insert(tk.END, full_message)
        self.text_area.see(tk.END)
        self.status_var.set(message)
        logging.info(message)
    
    def run_command(self, command):
        self.update_status(f"Executing: {command}")
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            self.update_status("Command executed successfully.")
            self.update_status(output)
        except subprocess.CalledProcessError as e:
            self.update_status(f"Error: {e.output}")
            logging.error(e.output)
    
    def reload_firewall(self):
        self.update_status("Reloading UFW firewall...")
        self.run_command("ufw reload")
        messagebox.showinfo("Firewall", "UFW firewall has been reloaded.")
    
    def restart_fail2ban(self):
        self.update_status("Restarting Fail2Ban service...")
        self.run_command("systemctl restart fail2ban")
        messagebox.showinfo("Fail2Ban", "Fail2Ban has been restarted.")
    
    def reload_apparmor(self):
        self.update_status("Reloading AppArmor profiles...")
        self.run_command("apparmor_parser -r /etc/apparmor.d/*")
        messagebox.showinfo("AppArmor", "AppArmor profiles have been reloaded.")
    
    def run_audit(self):
        self.update_status("Running Lynis system audit...")
        threading.Thread(target=self._run_audit, daemon=True).start()
    
    def _run_audit(self):
        self.run_command("lynis audit system --quick")
        messagebox.showinfo("Lynis Audit", "Lynis audit completed. Check /var/log/lynis_cron.log for details.")
    
    def configure_grub(self):
        self.update_status("Configuring GRUB secure settings...")
        # For demonstration, a placeholder password is used.
        # In production, replace this with a secure prompt or vault integration.
        grub_password = "SuperSecurePassword123!"  # Replace with secure input method
        import pexpect
        child = pexpect.spawn("grub-mkpasswd-pbkdf2")
        child.expect("Enter password:")
        child.sendline(grub_password)
        child.expect("Reenter password:")
        child.sendline(grub_password)
        child.expect(pexpect.EOF)
        output = child.before.decode()
        hashed_password = ""
        for line in output.splitlines():
            if "PBKDF2 hash of your password is" in line:
                hashed_password = line.split("is ")[1].strip()
                break
        if not hashed_password:
            self.update_status("Failed to generate GRUB hash.")
            return
        grub_config = f'set superusers="admin"\npassword_pbkdf2 admin {hashed_password}\n'
        try:
            with open("/etc/grub.d/00_password", "w") as f:
                f.write(grub_config)
            self.run_command("update-grub")
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
