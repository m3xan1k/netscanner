import socket
import re
from ipaddress import IPv4Address, AddressValueError

from IPy import IP
import click


class Protocol:
    TCP = 'tcp'
    UDP = 'udp'


PROTOCOL_SOCKETS = {
    'tcp': socket.SOCK_STREAM,
    'udp': socket.SOCK_DGRAM,
}
SOCKET_TIMEOUT = 2


def validate_port(ctx, param, port: str) -> str:
    if port.isnumeric():
        if in_valid_range(port):
            return [int(port)]
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


def validate_target(ctx, param, target) -> str:
    try:
        IPv4Address(target)
        return target
    except AddressValueError:
        try:
            target = socket.getaddrinfo(target, 0)[0][4][0]
            return target
        except:
            pass
        raise click.BadParameter('Not correct target')


def resolve_domain_to_ipv4_address(domain: str) -> str:
    pass


def scan_port(target: str, protocol: str, port_number: int) -> None:
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
            click.echo(f'[?] Sending UDP data to {port_number}')
        sock.close()

    except Exception as e:
        click.echo(e, err=True)
        print(f'[-] Port {port_number} is closed')


@click.command()
@click.option(
    '--target',
    prompt=True,
    type=click.UNPROCESSED,
    callback=validate_target,
    help='ip address or domain name',
)
@click.option(
    '--proto',
    type=click.Choice(['tcp', 'udp'], case_sensitive=False),
    multiple=True,
    show_choices=True,
    default=['tcp'],
    help='tcp or udp',
)
@click.option(
    '--port',
    type=click.UNPROCESSED,
    callback=validate_port,
    prompt=True,
    help='80 or 80,443,22 or 40000:50000',
)
def run(target, proto, port):
    # handle ports
    ports = port

    for protocol in proto:
        for port_number in ports:
            scan_port(target, protocol, port_number)


if __name__ == '__main__':
    run()
