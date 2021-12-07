import socket
import re
from ipaddress import (
    IPv4Address,
    IPv4Network,
    AddressValueError
)

import click


class Protocol:
    TCP = 'tcp'
    UDP = 'udp'


PROTOCOL_SOCKETS = {
    'tcp': socket.SOCK_STREAM,
    'udp': socket.SOCK_DGRAM,
}
SOCKET_TIMEOUT = 0.5


def validate_port(ctx, param, port: str) -> str:
    if not port:
        return None
    if port.isdigit():
        port = int(port)
        if in_valid_range(port):
            return [port]
    regex = r'\d+:\d+'
    match = re.match(regex, port)
    ports = None
    if match:
        ports = port.split(':')
        if all(map(str.isdigit, ports)):
            ports = range(*map(int, ports))
    elif ',' in port:
        ports = port.split(',')
        if all(map(str.isdigit, ports)):
            ports = [int(port) for port in ports]
    if ports:
        for number in ports:
            if not in_valid_range(number):
                raise click.BadParameter('Port must be int or int:int or int,int,int')
        return ports
    raise click.BadParameter('Port must be int or int:int or int,int,int')


def in_valid_range(port: int) -> bool:
    return port in range(1, 65535)


def validate_target(ctx, param, target) -> IPv4Address or list[IPv4Address] or str:
    try:
        target = IPv4Address(target)
        return [str(target)]
    except AddressValueError:
        pass
    try:
        net = IPv4Network(target)
        return [str(host) for host in net.hosts()]
    except ValueError:
        pass
    try:
        target = socket.getaddrinfo(target, 0)[0][4][0]
        return [target]
    except socket.gaierror:
        pass
    raise click.BadParameter('Not correct target')


def scan_port(target: str, protocol: str, port_number: int, verbose: bool) -> None:
    try:
        sock = socket.socket(socket.AF_INET, PROTOCOL_SOCKETS[protocol])
        sock.settimeout(SOCKET_TIMEOUT)

        # behaviour depends on protocol
        if protocol == Protocol.TCP:
            sock.connect((target, port_number))
            click.echo(
                click.style(
                    f'[+] Port {port_number} is open',
                    fg='green'
                )
            )
        elif protocol == Protocol.UDP:
            sock.sendto(b'Hello', (target, port_number))
            if verbose:
                click.echo(f'[?] Sending UDP data to {port_number}')
        sock.close()

    except Exception as e:
        if verbose:
            click.echo(e, err=True)
            print(f'[-] Port {port_number} is closed')


@click.command()
@click.option(
    '--target',
    type=click.UNPROCESSED,
    callback=validate_target,
    help='ip address/network or domain name',
    required=True,
)
@click.option(
    '--proto',
    type=click.Choice(['tcp', 'udp'], case_sensitive=False),
    multiple=True,
    show_choices=True,
    default=['tcp'],
    help='tcp or udp',
    required=True,
)
@click.option(
    '--port',
    type=click.UNPROCESSED,
    callback=validate_port,
    help='80 or 80,443,22 or 40000:50000',
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Show more output',
    default=False,
)
def run(target, proto, port, verbose):
    # handle ports
    ports = port

    for host in target:
        click.echo(f'[+] Scanning {host}')
        for protocol in proto:
            if protocol in [Protocol.TCP, Protocol.UDP] and not ports:
                raise click.BadArgumentUsage('Specify --port if proto is tcp or udp')
            for port_number in ports:
                scan_port(host, protocol, port_number, verbose)


if __name__ == '__main__':
    run()
