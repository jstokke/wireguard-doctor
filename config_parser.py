import configparser
import os
import ui # Import the ui module

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

        # Basic details
        client_private_key = config.get('Interface', 'PrivateKey')
        server_public_key = config.get('Peer', 'PublicKey')
        endpoint = config.get('Peer', 'Endpoint')

        # Also get Address for later use in post-handshake checks
        client_address = config.get('Interface', 'Address', fallback=None)

        # Extract IP and port from endpoint
        endpoint_ip, endpoint_port = endpoint.rsplit(':', 1)

        parsed_data = {
            'client_private_key': client_private_key,
            'server_public_key': server_public_key,
            'endpoint_ip': endpoint_ip,
            'endpoint_port': int(endpoint_port)
        }

        if client_address:
            parsed_data['Address'] = client_address

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
