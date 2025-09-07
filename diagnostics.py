import subprocess
import shutil
import platform
import socket
import time
from typing import Tuple
import textwrap

import ui

def check_tools() -> bool:
    """Checks if required command-line tools (wg, ping) are installed."""
    ui.print_info("Checking for required tools (`wg` and `ping`)...")

    status = ui.start_task("Verifying tool availability")

    wg_path = shutil.which("wg")
    ping_path = shutil.which("ping")

    if wg_path and ping_path:
        ui.end_task(status, success=True, message="Required tools are available.")
        return True

    # If tools are missing, stop the spinner and provide detailed help
    status.stop()
    if not wg_path:
        ui.print_error("`wg` command not found. WireGuard tools are not installed or not in your system's PATH.")

        os_type = platform.system()
        if os_type == "Linux":
            ui.console.print(textwrap.dedent("""
                [bold cyan]How to Install on Linux:[/bold cyan]
                Open your terminal and use your distribution's package manager.
                - For Debian/Ubuntu: `sudo apt-get update && sudo apt-get install wireguard-tools`
                - For Fedora/CentOS/RHEL: `sudo dnf install wireguard-tools`
                - For Arch Linux: `sudo pacman -S wireguard-tools`
            """))
        elif os_type == "Darwin": # macOS
            ui.console.print(textwrap.dedent("""
                [bold cyan]How to Install on macOS:[/bold cyan]
                You have two main options:
                1.  [bold]App Store (Recommended):[/bold] Install the official "WireGuard" application from the Mac App Store.
                2.  [bold]Homebrew (for command-line users):[/bold] Run `brew install wireguard-tools` in your terminal.
            """))
        elif os_type == "Windows":
            ui.console.print(textwrap.dedent("""
                [bold cyan]How to Install on Windows:[/bold cyan]
                The `wg` tool is included with the official WireGuard installer.
                - Download and run the installer from [bold blue]https://www.wireguard.com/install/[/bold blue]
                - After installation, the `wg` command will be available in the Command Prompt or PowerShell.
            """))
        else:
            ui.print_warning(f"Unsupported OS '{os_type}' detected. Please consult your OS documentation for how to install WireGuard.")
        return False

    if not ping_path:
        ui.print_error("`ping` command not found. This is highly unusual and suggests a broken system PATH.")
        return False

    return True # Should be unreachable, but for safety

def derive_public_key(private_key: str) -> str | None:
    """
    Derives the public key from a private key using the `wg pubkey` command.

    Args:
        private_key: The client's private key.

    Returns:
        The derived public key, or None if the command fails.
    """
    status = ui.start_task("Deriving public key from private key...")
    try:
        process = subprocess.run(
            ['wg', 'pubkey'],
            input=private_key,
            capture_output=True,
            check=True,
            text=True
        )
        derived_key = process.stdout.strip()
        ui.end_task(status, success=True, message="Public key derived successfully.")
        return derived_key
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        ui.end_task(status, success=False, message=f"Failed to derive public key. Error: {e}")
        return None

def check_endpoint_connectivity(endpoint_ip: str) -> bool:
    """
    Pings the server endpoint to check for basic network connectivity.

    Args:
        endpoint_ip: The IP address of the WireGuard server.

    Returns:
        True if the ping is successful, False otherwise.
    """
    status = ui.start_task(f"Pinging server endpoint: {endpoint_ip}...")

    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', endpoint_ip]

    try:
        subprocess.run(command, check=True, capture_output=True, timeout=10)
        ui.end_task(status, success=True, message=f"Endpoint {endpoint_ip} is reachable.")
        return True
    except subprocess.TimeoutExpired:
        ui.end_task(status, success=False, message=f"Ping timed out. The server at {endpoint_ip} is unresponsive.")
        return False
    except subprocess.CalledProcessError:
        ui.end_task(status, success=False, message=f"Endpoint {endpoint_ip} is not reachable via ping.")
        ui.print_info("Note: Some servers disable ping (ICMP). This may not be a fatal error.")
        return False
    except FileNotFoundError:
        # This should have been caught by check_tools, but as a fallback.
        ui.end_task(status, success=False, message="`ping` command not found.")
        return False

def find_interface_for_peer(server_public_key: str) -> str | None:
    """
    Finds the correct interface name by looking for the server's public key in the dump.

    Args:
        server_public_key: The public key of the server peer.

    Returns:
        The name of the interface, or None if not found.
    """
    status = ui.start_task("Scanning for active WireGuard interfaces...")
    try:
        # 'wg show all dump' provides a stable, machine-readable format
        result = subprocess.run(
            ['wg', 'show', 'all', 'dump'],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        for line in result.stdout.strip().split('\n'):
            fields = line.split('\t')
            # A peer line has more than 4 fields. The public key is the second field.
            if len(fields) > 4 and fields[1] == server_public_key:
                interface_name = fields[0]
                ui.end_task(status, success=True, message=f"Found matching peer on interface '{interface_name}'.")
                return interface_name

        ui.end_task(status, success=False, message="Could not find an active interface for the given peer public key.")
        return None
    except subprocess.TimeoutExpired:
        ui.end_task(status, success=False, message="`wg show` command timed out. The interface may be in a bad state.")
        return None
    except (subprocess.CalledProcessError, FileNotFoundError):
        ui.end_task(status, success=False, message="Failed to execute `wg show all dump`. WireGuard may not be active.")
        return None

def check_handshake(interface: str) -> Tuple[bool, str]:
    """
    Checks the WireGuard interface for a recent handshake.

    Args:
        interface: The name of the WireGuard interface (e.g., 'wg0').

    Returns:
        A tuple containing:
        - bool: True if a recent handshake was found, False otherwise.
        - str: A message describing the handshake status.
    """
    status = ui.start_task(f"Checking for a handshake on interface '{interface}'...")
    try:
        result = subprocess.run(
            ['wg', 'show', interface, 'latest-handshakes'],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )

        # The output is of the form: <public_key>\t<timestamp_unix>
        # If there's no handshake, the output is empty or the command might fail.
        handshake_data = result.stdout.strip()
        if not handshake_data:
            message = "No handshake found for any peer on this interface."
            ui.end_task(status, success=False, message=message)
            return False, message

        # Check the timestamp. A handshake is "recent" if it's within the last ~3 minutes.
        _, handshake_timestamp_str = handshake_data.split('\t')
        handshake_timestamp = int(handshake_timestamp_str)
        current_time = int(time.time())

        if current_time - handshake_timestamp < 180: # 3 minutes
            seconds_ago = current_time - handshake_timestamp
            message = f"Recent handshake found! ({seconds_ago} seconds ago)"
            ui.end_task(status, success=True, message=message)
            return True, message
        else:
            minutes_ago = (current_time - handshake_timestamp) // 60
            message = f"Stale handshake found. (Last handshake was {minutes_ago} minutes ago)"
            ui.end_task(status, success=False, message=message)
            return False, message

    except subprocess.TimeoutExpired:
        message = f"`wg show` command timed out while checking for handshake. The interface '{interface}' may be in a bad state."
        ui.end_task(status, success=False, message=message)
        return False, message
    except subprocess.CalledProcessError:
        message = f"Could not get handshake status. Is interface '{interface}' up?"
        ui.end_task(status, success=False, message=message)
        return False, message
    except (FileNotFoundError, ValueError):
        message = "Failed to parse handshake data."
        ui.end_task(status, success=False, message=message)
        return False, message

def check_dns() -> bool:
    """
    Checks if DNS resolution is working by resolving a common domain.

    Returns:
        True if DNS resolution is successful, False otherwise.
    """
    status = ui.start_task("Checking DNS resolution...")
    try:
        socket.gethostbyname('one.one.one.one') # Cloudflare's DNS, good for testing
        socket.gethostbyname('google.com')
        ui.end_task(status, success=True, message="DNS resolution is working correctly.")
        return True
    except socket.gaierror:
        ui.end_task(status, success=False, message="DNS resolution failed. This is likely the cause of the 'no internet' issue.")
        return False

def lint_config(config: dict):
    """
    Analyzes the configuration for common best-practice issues and prints warnings.
    """
    ui.print_info("Linting configuration for best practices...")

    # Check for DNS leak potential
    if '0.0.0.0/0' in config.get('AllowedIPs', '') and not config.get('DNS'):
        ui.print_warning("Your 'AllowedIPs' is set to route all traffic through the VPN, but you have not set a 'DNS' server in your config. This can lead to DNS leaks.")
        ui.print_info("Suggestion: Add 'DNS = 1.1.1.1' (or another trusted DNS) to your [Interface] section.")

    # Check for missing PersistentKeepalive
    if not config.get('PersistentKeepalive'):
        ui.print_warning("Your configuration is missing 'PersistentKeepalive' in the [Peer] section.")
        ui.print_info("Suggestion: Add 'PersistentKeepalive = 25' to maintain a stable connection, especially through NAT and firewalls.")

def check_mtu():
    """
    Provides information and commands for the user to check for MTU issues.
    """
    ui.print_info("Checking for potential MTU issues...")
    ui.console.print(textwrap.dedent("""
        [bold cyan]What is MTU?[/bold cyan]
        MTU (Maximum Transmission Unit) defines the largest packet size that can be sent over a network. If some websites load but others (especially ones with rich content) fail, it might be an MTU issue. Your packets are too big and get dropped.

        [bold cyan]How to Test Manually:[/bold cyan]
        WG-Doctor can't run this test automatically, but you can do it easily. You need to find the largest packet size that doesn't fragment.

        [bold]On Linux or macOS:[/bold]
        Run this command, starting with a size of 1472 and decreasing it until the ping works:
        `ping -M do -s 1472 <SERVER_IP>`
        (Replace <SERVER_IP> with your WG server's IP address)

        - If you see "Frag needed and DF set" or similar, the size is too big. Lower it by 10-20 and try again.
        - Once the ping succeeds, take that size and add 28 (for the IP/ICMP headers). The result is your optimal MTU. For example, if `ping -s 1440` works, your MTU is 1468.

        [bold]On Windows:[/bold]
        Run this command, starting with a size of 1472 and decreasing it:
        `ping -f -l 1472 <SERVER_IP>`

        [bold cyan]The Fix:[/bold cyan]
        Once you find the right MTU value (e.g., 1468), add it to your `.conf` file under the `[Interface]` section:
        `MTU = 1468`
    """))
