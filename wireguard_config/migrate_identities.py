#!/usr/bin/env python3
''' Migrates from the prior method of handling wireguard client identities using single files for each piece of data '''
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
from typing import Union

# set up logging configuration - only to stdout/stderr for now
class ErrorLogFilter(logging.Filter):
    ''' prevents error logs from making it into stdout '''
    def __init__(self, name: str = 'ErrorLogFilter') -> None:
        super().__init__(name)

    def filter(self, record):
        return record.levelno < logging.WARNING

logger = logging.getLogger('build')
log_formatter = logging.Formatter(
    '[%(asctime)s] (%(name)s:%(levelname)s) %(message)s',
    '%Y-%m-%dT%H:%M:%S%z'
)

log_stdout_handler = logging.StreamHandler(sys.stdout)
log_stdout_handler.addFilter(ErrorLogFilter())
log_stdout_handler.setFormatter(log_formatter)

log_stderr_handler = logging.StreamHandler(sys.stderr)
log_stderr_handler.setFormatter(log_formatter)
log_stderr_handler.setLevel(logging.WARNING)

logger.addHandler(log_stdout_handler)
logger.addHandler(log_stderr_handler)

logger.setLevel(logging.INFO)

WG_BIN = os.environ.get('WG_BIN', '/usr/bin/wg')

def call_wg(wg_args: str, stdin: Union[str, None] = None):
    ''' make a call to wg binary via a subprocess invoke '''

    call = f'{WG_BIN} {wg_args}'
    logger.debug(f'running wg call: {call}')

    try:
        if stdin:
            output = subprocess.check_output(
                call.split(' '),
                input=stdin,
                text=True
            )
        else:
            output = subprocess.check_output(
                call.split(' '),
                text=True
            )

        logger.debug('wg call ran without errors')

        return output.strip()
    except subprocess.CalledProcessError as ex:
        logger.error(f'wg call failed with status code {ex.returncode}')
        raise ex

def port_range(arg):
    ''' Port range validation helper for argparse. '''

    try:
        port = int(arg)
    except ValueError as ex:
        raise argparse.ArgumentTypeError('must be an integer') from ex

    if port < 0 or port > 65535:
        raise argparse.ArgumentTypeError('must be a valid port number (0-65535)')

    return port

@dataclass
class ClientIdentity:
    ''' Represents the client "identity" for details required by the client when building the Wireguard server configuration. '''

    vpn_ip: ipaddress.IPv4Address = ipaddress.IPv4Address('127.0.0.1')
    public_key: str = ''
    preshared_key: str = ''

    @staticmethod
    def from_legacy_files(legacy_files_path: Path) -> ClientIdentity:
        ''' Load client identities from legacy files storage method. '''

        identity = {
            'vpn_ip': ipaddress.IPv4Address((legacy_files_path / 'ip').read_text('utf-8').rstrip('\n')),
            'public_key': (legacy_files_path / 'public').read_text('utf-8').rstrip('\n'),
            'preshared_key': (legacy_files_path / 'psk').read_text('utf-8').rstrip('\n')
        }

        return ClientIdentity(**identity)

    def to_identity_file(self) -> str:
        ''' Create a client identity fragment to assist in building the server identity file. '''

        identity = {
            'vpn_ip': str(self.vpn_ip),
            'public_key': self.public_key,
            'preshared_key': self.preshared_key
        }

        return json.dumps(identity, indent=2)

@dataclass
class ServerMigrateConfig:
    ''' Handles the server configuration generation for the Wireguard server. '''

    vpn_endpoint: str
    vpn_port: int

    vpn_network: ipaddress.IPv4Network
    vpn_server_ip: ipaddress.IPv4Address = ipaddress.IPv4Address('127.0.0.1')
    dns_ip: Union[ipaddress.IPv4Address, None] = None

    private_key: str = ''
    public_key: str = ''

    def extract_public_key(self):
        ''' Extracts the public key from the private key. '''

        self.public_key = call_wg('pubkey', self.private_key)

    def create_server_config(self) -> str:
        ''' Build a partial server Wireguard configuration file, given an appropriate server config. '''

        config = {
            'vpn_endpoint': self.vpn_endpoint,
            'vpn_port': self.vpn_port,

            'vpn_network': self.vpn_network.with_prefixlen,
            'dns_ip': str(self.dns_ip) if self.dns_ip else None,
            'vpn_server_ip': str(self.vpn_server_ip),

            'private_key': self.private_key,
            'public_key': self.public_key
        }

        return json.dumps(config, indent=2)

    def create_server_identity(self) -> str:
        ''' Create a server identity fragment to assist in building client configurations. '''

        identity = {
            'vpn_endpoint': self.vpn_endpoint,
            'vpn_port': self.vpn_port,

            'vpn_network': self.vpn_network.with_prefixlen,
            'vpn_public_key': self.public_key,

            'dns_ip': str(self.dns_ip) if self.dns_ip else None
        }

        return json.dumps(identity, indent=2)

def main(
        endpoint: str,
        port: int,
        vpn_network_cidr: ipaddress.IPv4Network,
        vpn_server_ip: ipaddress.IPv4Address,
        vpn_dns_ip: ipaddress.IPv4Address,
        private_key_path: Path,
        server_config_path: Path,
        server_identity_path: Path,
        client_legacy_files_path: Path
    ): # pylint: disable=too-many-arguments
    ''' main method '''

    config = ServerMigrateConfig(
        vpn_endpoint=endpoint,
        vpn_port=port,
        vpn_network=vpn_network_cidr,
        vpn_server_ip=vpn_server_ip,
        dns_ip=vpn_dns_ip
    )

    config.private_key = private_key_path.read_text('utf-8').rstrip('\n')
    config.extract_public_key()

    server_identity_path.write_text(config.create_server_identity(), 'utf-8')

    server_config_path.write_text(config.create_server_config(), 'utf-8')
    server_config_path.chmod(0o600) # chmod 600
    if os.geteuid() == 0:
        os.chown(server_config_path, uid=0, gid=0) # chown root:root

    for entry in client_legacy_files_path.iterdir():
        if entry.is_dir():
            client = ClientIdentity.from_legacy_files(entry)
            client_identity_file = client_legacy_files_path / (entry.name + '.json')
            client_identity_file.write_text(client.to_identity_file(), 'utf-8')
            client_identity_file.chmod(0o600) # chmod 600
            if os.geteuid() == 0:
                os.chown(client_identity_file, uid=0, gid=0) # chown root:root

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bootstrap a Wireguard server setup.')
    parser.add_argument(
        'endpoint',
        type=str,
        help='The VPN endpoint (DNS recommended).'
    )
    parser.add_argument(
        '--port',
        type=port_range,
        help='The port number that Wireguard will listen on.'
    )
    parser.add_argument(
        '--vpn-network-cidr',
        type=ipaddress.IPv4Network,
        help='The IPv4 network address space that the VPN will use in CIDR format (e.g. 10.0.0.0/24).'
    )
    parser.add_argument(
        '--vpn-server-ip',
        type=ipaddress.IPv4Address,
        required=True,
        help='The IPV4 address for the VPN server.'
    )
    parser.add_argument(
        '--vpn-dns-ip',
        type=ipaddress.IPv4Address,
        required=False,
        help='The IP address of the DNS server to use for clients, if one is to be used (e.g. 10.0.0.1).'
    )
    parser.add_argument(
        '--private-key-path',
        type=Path,
        required=True,
        help='The location of the VPN server private key.'
    )
    parser.add_argument(
        '--server-config-path',
        type=Path,
        required=True,
        help='The path to where the server configuration file will be written'
    )
    parser.add_argument(
        '--server-identity-path',
        type=Path,
        required=True,
        help='The path to where the client identity file will be written to upon server configuration initialization.'
    )
    parser.add_argument(
        '--client-legacy-files-path',
        type=Path,
        required=True,
        help='The path to the legacy client configuration files.'
    )

    args = parser.parse_args()
    main(**args.__dict__)
