import socket
import re
from ipaddress import IPv4Address, AddressValueError

from IPy import IP
import click


def validate_port(ctx, param, port: str) -> str:
    if port.isnumeric():
        if in_valid_range(port):
            return port
    regex = r'\d+:\d+'
    match = re.match(regex, port)
    if match:
        for number in port.split(':'):
            if not in_valid_range(number):
                raise click.BadParameter('Port must be numeric or int:int')
        return port
    raise click.BadParameter('Port must be numeric or int:int')


def in_valid_range(port: str) -> bool:
    return int(port) in range(1, 65535)


def validate_target(ctx, param, target) -> str:
    try:
        IPv4Address(target)
        return target
    except AddressValueError:
        raise click.BadParameter('Not correct target')


@click.command()
@click.option(
    '--target',
    prompt=True,
    type=click.UNPROCESSED,
    callback=validate_target,
)
@click.option(
    '--proto',
    type=click.Choice(['tcp', 'udp'], case_sensitive=False),
    multiple=True,
    show_choices=True,
    default=['tcp'],
)
@click.option(
    '--port',
    type=click.UNPROCESSED,
    callback=validate_port,
    prompt=True,
)
def run(target, proto, port):
    # handle ports
    if not port.isnumeric():
        start, stop = map(int, port.split(':'))
        ports = range(start, stop + 1)
    else:
        ports = [port]
    
    # handle protocol
    PROTOCOLS = {
        'tcp': socket.SOCK_STREAM,
        'udp': socket.SOCK_DGRAM,
    }


    for protocol in proto:
        for port_number in ports:
            try:
                sock = socket.socket(socket.AF_INET, PROTOCOLS[protocol])
                sock.settimeout(5)
                if protocol == 'tcp':
                    sock.connect((target, port_number))
                    click.echo(
                        click.style(
                            f'[+] Port {port_number} is open',
                            fg='green'
                        )
                    )
                elif protocol == 'udp':
                    sock.sendto(b'Hello', (target, port_number))
                    click.echo(f'[+] Sending UDP data to {port_number}')
                sock.close()
            except Exception as e:
                click.echo(e, err=True)
                print(f'[+] Port {port_number} is closed')


if __name__ == '__main__':
    run()
