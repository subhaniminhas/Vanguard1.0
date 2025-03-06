Vanguard Elite is a robust, self-contained security hardening suite designed exclusively for Debian‑based systems, improved by the AI. Inspired by the highest security standards typically found in elite proxy environments, Vanguard Elite automates the installation and configuration of essential security tools and best practices to ensure your server remains resilient against modern threats.

![image](https://github.com/user-attachments/assets/fd48677b-b460-4ea9-867b-3de4d2be2eb2)

Key Features
Automated Dependency Management:
Installs all necessary system packages and Python libraries (e.g., UFW, Fail2Ban, AppArmor, Lynis, rkhunter, and more) on Debian‑based systems.

Defense-in-Depth Hardening:
Applies multiple layers of protection including firewall configuration with UFW (default deny incoming, allow SSH), secure cron jobs for regular system audits and updates, and additional measures such as disabling USB storage.

Interactive GUI/CLI Management:
A user‑friendly Tkinter‑based/CLI interface provides real‑time status updates and enables easy management of security services. Reload firewall rules, restart Fail2Ban, reload AppArmor profiles, run system audits and more with just a few clicks or keypresses.

Robust Error Handling & Logging:
Built with stringent error checking and detailed logging, ensuring reliable operation and easier troubleshooting.

Secure GRUB Configuration:
Optionally secure your bootloader with password protection to guard against boot-time tampering.

Getting Started
Run the Setup Script:
Execute sudo ./setup.sh to install dependencies and apply baseline hardening measures.
Launch the Interactive Tool:
Run python3 elite.py to access the GUI for ongoing security management, or python3 elite_cli.py to access the CLI version.
Embrace elite-grade security hardening with Vanguard Elite and fortify your Debian-based server with a trusted, automated solution.
