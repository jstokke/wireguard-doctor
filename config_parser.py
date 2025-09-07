import configparser
import os
import ui

def parse_config(config_path: str) -> dict | None:
    """
    Parses a WireGuard configuration file.

    Args:
        config_path: The path to the WireGuard .conf file.

    Returns:
        A dictionary containing the parsed configuration details if successful,
        otherwise None.
    """
    if not os.path.exists(config_path):
        ui.print_error(f"Configuration file not found at '{config_path}'")
        return None

    config = configparser.ConfigParser()
    try:
        config.read(config_path)

        # --- [Interface] Section ---
        client_private_key = config.get('Interface', 'PrivateKey')
        client_address = config.get('Interface', 'Address', fallback=None)
        client_dns = config.get('Interface', 'DNS', fallback=None)

        # --- [Peer] Section ---
        server_public_key = config.get('Peer', 'PublicKey')
        endpoint = config.get('Peer', 'Endpoint')
        allowed_ips = config.get('Peer', 'AllowedIPs', fallback='0.0.0.0/0') # Default to all traffic for logic
        persistent_keepalive = config.get('Peer', 'PersistentKeepalive', fallback=None)

        # Extract IP and port from endpoint
        endpoint_ip, endpoint_port = endpoint.rsplit(':', 1)

        parsed_data = {
            'client_private_key': client_private_key,
            'server_public_key': server_public_key,
            'endpoint_ip': endpoint_ip,
            'endpoint_port': int(endpoint_port),
            'Address': client_address,
            'DNS': client_dns,
            'AllowedIPs': allowed_ips,
            'PersistentKeepalive': persistent_keepalive
        }

        return parsed_data

    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        ui.print_error(f"Invalid or incomplete configuration file. Missing section or key. Details: {e}")
        return None
    except ValueError:
        ui.print_error(f"Invalid endpoint format in config file: '{endpoint}'. It should be 'ip:port'.")
        return None
    except Exception as e:
        ui.print_error(f"An unexpected error occurred while parsing the config file: {e}")
        return None
