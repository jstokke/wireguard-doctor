import argparse
import os
import sys
import textwrap
import subprocess
import platform

import config_parser
import diagnostics
import ui

def run_no_handshake_quiz():
    """Guides the user through diagnosing no-handshake issues."""
    ui.console.print("\n[bold yellow]--- Interactive No-Handshake Guide ---[/bold yellow]")
    ui.print_info("A handshake failure is usually caused by a networking or firewall issue.")

    server_env = ui.ask_question(
        "First, where is your WireGuard server hosted?",
        choices=["cloud", "home/office"],
        default="cloud"
    )

    if server_env == "cloud":
        ui.console.print(textwrap.dedent("""
            [bold cyan]Troubleshooting for Cloud Servers (AWS, GCP, Azure, etc.):[/bold cyan]

            1.  [bold]Security Group / Cloud Firewall:[/bold] Log in to your cloud provider's console. Ensure you have an inbound rule that allows UDP traffic on your WireGuard port (e.g., 51820) from any source IP (0.0.0.0/0). This is the most common cause.
            2.  [bold]Server's Local Firewall:[/bold] SSH into your server and check its local firewall (like `ufw` or `firewalld`).
                - For `ufw`, run `sudo ufw status` and ensure your port is allowed (`sudo ufw allow 51820/udp`).
                - For `firewalld`, run `sudo firewall-cmd --list-all` and ensure your port is in the correct zone.
            3.  [bold]WireGuard Service Status:[/bold] On the server, run `sudo wg show`. Does the interface exist? Is it running? Check the service status with `sudo systemctl status wg-quick@<interface_name>`.
        """))
    else:  # home/office
        ui.console.print(textwrap.dedent(f"""
            [bold cyan]Troubleshooting for Home/Office Servers:[/bold cyan]

            1.  [bold]Port Forwarding:[/bold] You **must** set up port forwarding on your internet router.
                - Log in to your router's admin page.
                - Find the 'Port Forwarding' or 'Virtual Server' section.
                - Create a new rule:
                    - **External Port:** Your WireGuard port (e.g., 51820)
                    - **Internal Port:** The same port (e.g., 51820)
                    - **Protocol:** UDP
                    - **Device IP / Internal IP:** The local IP address of your WireGuard server (e.g., 192.168.1.100).
        """))

        is_double_nat = ui.ask_confirm(
            "Are you using a second router inside your network (e.g., a mesh system like Eero/Google Wifi connected to your ISP's modem)?",
            default=False
        )
        if is_double_nat:
            ui.console.print(textwrap.dedent("""
                [bold magenta]Double NAT Detected![/bold magenta] This requires special configuration.

                You have a 'chain' of routers: [Internet] -> [ISP Modem/Router] -> [Your Second Router] -> [WG Server]

                You must set up 'Chained Port Forwarding':
                1.  **On your SECOND router:** Port forward UDP 51820 to your WireGuard server's IP.
                2.  **On your MAIN ISP router:** Port forward UDP 51820 to your *second router's* IP address.
            """))

def run_post_handshake_checks(config):
    """Guides the user through diagnosing post-handshake internet issues."""
    ui.console.print("\n[bold yellow]--- Interactive Post-Handshake Guide ---[/bold yellow]")
    if not diagnostics.check_dns():
        ui.console.print(textwrap.dedent(f"""
            [bold red]DNS Resolution Failed![/bold red]

            This is a common issue. Your device is connected to the VPN but can't look up websites.

            [bold cyan]Solution:[/bold cyan]
            - Open your WireGuard configuration file (`.conf`).
            - In the `[Interface]` section, ensure you have a `DNS` entry.
            - A good public DNS server is `1.1.1.1` (Cloudflare) or `8.8.8.8` (Google).

            Example:
            [Interface]
            PrivateKey = ...
            Address = {config.get('Address', '10.0.0.2/32')}
            DNS = 1.1.1.1
        """))
    else:
        ui.console.print(textwrap.dedent("""
            [bold green]DNS is working.[/bold green] Your internet issue is likely on the server side.
            The server isn't correctly 'forwarding' your traffic to the internet.

            [bold cyan]Solution: Check Server-Side Forwarding and NAT[/bold cyan]
            SSH into your server and check the following:

            1.  [bold]Enable IP Forwarding:[/bold]
                - Run `sudo sysctl net.ipv4.ip_forward`. The result should be `1`.
                - If it's `0`, edit `/etc/sysctl.conf` (or a file in `/etc/sysctl.d/`), add `net.ipv4.ip_forward=1`, and run `sudo sysctl -p`.

            2.  [bold]Firewall NAT Rule:[/bold]
                - You need an `iptables` rule to masquerade (NAT) traffic from your VPN clients.
                - A common rule is:
                  `sudo iptables -t nat -A POSTROUTING -o <Your_Server_Public_Interface> -j MASQUERADE`
                - Replace `<Your_Server_Public_Interface>` with your server's main network interface (e.g., `eth0`).
                - This rule needs to be saved so it persists after a reboot. The `iptables-persistent` package can help.
        """))

        # Finally, check for MTU issues
        diagnostics.check_mtu()

def main():
    parser = argparse.ArgumentParser(
        description="WG-Doctor: A command-line tool to diagnose WireGuard connectivity issues.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("config_file", help="Path to your WireGuard .conf file.")
    args = parser.parse_args()

    ui.print_welcome()

    # --- Automated Checks ---
    if not diagnostics.check_tools():
        sys.exit(1)

    config = config_parser.parse_config(args.config_file)
    if not config:
        sys.exit(1)

    # Run the configuration linter for best practices
    diagnostics.lint_config(config)

    derived_pubkey = diagnostics.derive_public_key(config['client_private_key'])
    if not derived_pubkey:
        sys.exit(1)

    # Simple sanity check
    if derived_pubkey == config['server_public_key']:
        ui.print_error("Configuration Error: Your client PrivateKey and the peer's PublicKey are a matching pair. The peer's PublicKey should be the *server's* public key.")

    diagnostics.check_endpoint_connectivity(config['endpoint_ip'])

    # --- Core Logic: Handshake or No Handshake? ---
    interface_name = os.path.splitext(os.path.basename(args.config_file))[0]
    has_handshake, message = diagnostics.check_handshake(interface_name)

    if not has_handshake:
        ui.print_error("No recent handshake detected. This is the primary issue to solve.")
        ui.print_info(f"Details: {message}")
        run_no_handshake_quiz()
    else:
        ui.print_info("A recent handshake was detected! The tunnel itself is likely working.")
        run_post_handshake_checks(config)

    ui.console.print("\n[bold green]Diagnosis complete.[/bold green]")

if __name__ == "__main__":
    try:
        # On non-Windows systems, check for root and re-run with sudo if needed.
        if platform.system() != "Windows":
            if os.geteuid() != 0 and 'SUDO_UID' not in os.environ:
                ui.print_info("WG-Doctor needs root privileges. Re-running with sudo...")
                # Use sys.executable to ensure we use the same python interpreter
                args = ['sudo', sys.executable] + sys.argv
                subprocess.check_call(args)
                sys.exit()  # Exit the non-privileged process
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit(0)
    except Exception as e:
        ui.print_error(f"An unexpected error occurred: {e}")
        sys.exit(1)
