# WG-Doctor: Your WireGuard Troubleshooting Assistant

WG-Doctor is a user-friendly, cross-platform command-line tool designed to help you diagnose and fix common WireGuard connectivity issues. Whether you're facing the dreaded "no handshake" problem or have a connection with no internet access, WG-Doctor will guide you through a step-by-step diagnostic process to get you back online.

It combines automated checks with an interactive quiz to pinpoint issues ranging from simple configuration errors to complex network problems like firewalls and Double NAT.

## Features

- **Automated Sanity Checks:**
  - Verifies that required tools (`wg`, `ping`) are installed and provides beginner-friendly installation instructions if they are not.
  - Parses your `.conf` file and validates its structure.
  - Derives your client public key from your private key to check for potential key mismatches.
  - Pings your server's endpoint to check for basic reachability.

- **Handshake and Connectivity Analysis:**
  - Checks the status of your WireGuard interface to see if a recent, successful handshake has occurred.
  - If a handshake is present but you have no internet, it runs further checks for common causes.

- **Interactive Diagnostic Quizzes:**
  - **No Handshake?** If no handshake is detected, WG-Doctor launches an interactive guide to help you find the root cause, with specific advice for:
    - **Cloud Servers:** Checklist for security groups and server-side firewalls (e.g., `ufw`, `firewalld`).
    - **Home/Office Servers:** Detailed instructions on how to configure **Port Forwarding** on your router.
    - **Double NAT Detection:** A specific check to identify and solve tricky Double NAT scenarios.
  - **No Internet?** If you have a handshake but no internet, the tool provides guidance on:
    - **DNS Resolution Issues:** Detects if DNS is the problem and tells you how to fix it in your config.
    - **Server-Side Forwarding:** Provides instructions for enabling IP forwarding and setting up firewall NAT rules (`iptables`) on your server.

- **Configuration Linter:**
  - Proactively analyzes your `.conf` file for best practices.
  - Warns about potential **DNS leaks** when tunneling all traffic.
  - Recommends adding `PersistentKeepalive` for a more stable connection.

- **MTU Discovery Guidance:**
  - Educates you on MTU (Maximum Transmission Unit) issues, which can cause some websites to not load.
  - Provides platform-specific commands to help you find the optimal MTU for your connection.

## Installation

WG-Doctor is a Python script and requires Python 3.

1.  **Install WireGuard:** You must have the WireGuard application and its command-line tools installed for your operating system.
    - **Linux:** Open your terminal and use your distribution's package manager.
      - *Debian/Ubuntu:* `sudo apt-get update && sudo apt-get install wireguard-tools`
      - *Fedora/CentOS/RHEL:* `sudo dnf install wireguard-tools`
      - *Arch Linux:* `sudo pacman -S wireguard-tools`
    - **macOS:**
      - *App Store (Recommended):* Install the official "WireGuard" application from the Mac App Store.
      - *Homebrew:* `brew install wireguard-tools`
    - **Windows:**
      - Download and run the official installer from **https://www.wireguard.com/install/**.

2.  **Install Python Dependencies:**
    The only dependency is the `rich` library for beautiful command-line output.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script from your terminal and provide the path to your WireGuard `.conf` file as an argument.

```bash
python3 wg_doctor.py /path/to/your/wg0.conf
```

On Linux and macOS, the script may require root privileges to inspect the WireGuard interface. It will attempt to re-run itself with `sudo` if needed.