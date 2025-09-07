import subprocess
import shutil
import platform
import socket
import time
from typing import Tuple

import ui

def check_tools() -> bool:
    """Checks if required command-line tools (wg, ping) are installed."""
    ui.print_info("Checking for required tools (`wg` and `ping`)...")

    status = ui.start_task("Verifying tool availability")

    wg_path = shutil.which("wg")
    ping_path = shutil.which("ping")

    if not wg_path:
        ui.end_task(status, success=False, message="`wg` command not found. Is WireGuard installed and in your PATH?")
        return False

    if not ping_path:
        ui.end_task(status, success=False, message="`ping` command not found. This is highly unusual.")
        return False

    ui.end_task(status, success=True, message="Required tools are available.")
    return True

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
        subprocess.run(command, check=True, capture_output=True)
        ui.end_task(status, success=True, message=f"Endpoint {endpoint_ip} is reachable.")
        return True
    except subprocess.CalledProcessError:
        ui.end_task(status, success=False, message=f"Endpoint {endpoint_ip} is not reachable via ping.")
        ui.print_info("Note: Some servers disable ping (ICMP). This may not be a fatal error.")
        return False
    except FileNotFoundError:
        # This should have been caught by check_tools, but as a fallback.
        ui.end_task(status, success=False, message="`ping` command not found.")
        return False

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
            check=True
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
