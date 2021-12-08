import socket
import re
from ipaddress import (
    IPv4Address,
    IPv4Network,
    AddressValueError
)
from binascii import hexlify
from textwrap import wrap

import click
import dpkt


class Protocol:
    TCP = 'tcp'
    UDP = 'udp'
    ARP = 'arp'


class ArpOperations:
    REQUEST = 0x0001
    REPLY = 0x0002


ARP_PROTOCOL_CODE = 0x0806
HTYPE_ETHERNET = 0x0001
ETHERTYPE_IPV4 = 0x0800
HLEN_ETHERNET = 0x06
PLEN_IPV4 = 0x04

PROTOCOL_SOCKETS = {
    'tcp': {
        'address_family': socket.AF_INET,
        'transport': socket.SOCK_STREAM,
    },
    'udp': {
        'address_family': socket.AF_INET,
        'transport': socket.SOCK_DGRAM,
    },
    'arp': {
        'address_family': socket.AF_PACKET,
        'transport': socket.SOCK_RAW,
    },
}

SOCKET_TIMEOUT = 3


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
        sock = socket.socket(
            PROTOCOL_SOCKETS[protocol]['address_family'],
            PROTOCOL_SOCKETS[protocol]['transport']
        )
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
            prompt = sock.recv(1024)
            click.echo(click.style(prompt.decode(errors='ignore').strip(), fg='blue'))
        elif protocol == Protocol.UDP:
            sock.sendto(b'Hello', (target, port_number))
            if verbose:
                click.echo(f'[?] Sending UDP data to {port_number}')
        sock.close()

    except Exception as e:
        if verbose:
            click.echo(e, err=True)
            print(f'[-] Port {port_number} is closed')


def make_arp_request(host: str, protocol: str, verbose: bool, interface: str) -> None:
    sock = socket.socket(
        PROTOCOL_SOCKETS[protocol]['address_family'],
        PROTOCOL_SOCKETS[protocol]['transport'],
        socket.htons(0x0806),
    )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(2)
    sock.bind((interface, 0))

    s_mac = sock.getsockname()[4]
    d_mac = b'\xff\xff\xff\xff\xff\xff'

    s_ip = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close())
            for s
            in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    s_ip = socket.inet_aton(s_ip)
    d_ip = socket.inet_aton(host)

    operation = ArpOperations.REQUEST

    frame = [
        d_mac,
        s_mac,
        ARP_PROTOCOL_CODE.to_bytes(2, 'big'),
        HTYPE_ETHERNET.to_bytes(2, 'big'),
        ETHERTYPE_IPV4.to_bytes(2, 'big'),
        HLEN_ETHERNET.to_bytes(1, 'big'),
        PLEN_IPV4.to_bytes(1, 'big'),
        operation.to_bytes(2, 'big'),
        s_mac,
        s_ip,
        d_mac,
        d_ip,
    ]

    sock.send(b''.join(frame))
    try:
        data = sock.recv(72)
        reply = dpkt.ethernet.Ethernet(data)
        if reply.arp.op == ArpOperations.REPLY:
            target_mac = ':'.join(wrap(hexlify(reply.src).decode(), 2))
            click.echo(click.style(f'[+] {host} {target_mac}', fg='green'))
        sock.close()
    except socket.timeout:
        pass


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
    type=click.Choice(['tcp', 'arp'], case_sensitive=False),
    multiple=True,
    show_choices=True,
    default=['tcp'],
    help='tcp,arp',
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
@click.option(
    '--interface',
    help='Interface name required with --proto=arp',
)
def run(target, proto, port, verbose, interface):
    # handle ports
    ports = port

    for host in target:
        click.echo(f'[*] Scanning {host}')
        for protocol in proto:
            if protocol in [Protocol.TCP, Protocol.UDP]:
                if not ports:
                    raise click.BadArgumentUsage('Specify --port if proto is tcp')
                for port_number in ports:
                    scan_port(host, protocol, port_number, verbose)
            if protocol == Protocol.ARP:
                if not interface:
                    raise click.BadParameter('--interface required with --proto=arp')
                make_arp_request(host, protocol, verbose, interface)


if __name__ == '__main__':
    run()
