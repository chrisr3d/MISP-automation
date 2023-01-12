import argparse
import subprocess
from pathlib import Path
from pymisp import MISPEvent, MISPAttribute, MISPObject, PyMISP

default_path = Path(__file__).resolve().parent / 'data'

# Non exhaustive list of protocols to populate `network-connection` object attributes
layer3_protocols = (
    'arp', 'icmp', 'icmpv6', 'ip', 'ipv6'
)
layer4_protocols = (
    'tcp', 'udp'
)
layer7_protocols = (
    'dhcp', 'dns', 'ftp', 'http', 'ntp', 'smtp', 'snmp', 'ssdp', 'tftp'
)

# Tshark filters
standard_filters = (
    'frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport', 'frame.protocols'
)

# MISP object relations lists and mappings
CONNECTION_OBJECT_RELATIONS = ('ip-src', 'ip-dst', 'src-port', 'dst-port')


def define_command(input_file: Path, filters: tuple) -> str:
    param = '-o tcp.relative_sequence_numbers:FALSE -E separator="|"'
    filters_cmd = ' -e '.join(filters)
    tshark = f'tshark -T fields {param} -e {filters_cmd} -Y "!(arp || dhcp)"'
    return f'{tshark} -r {input_file}'


def handle_protocols(frame_protocols: str) -> list:
    protocols = set(frame_protocols.split(':'))
    protocol_key = []
    for layer in (3, 4, 7):
        for protocol in globals()[f'layer{layer}_protocols']:
            if protocol in protocols:
                protocol_key.append(protocol)
                break
    return protocol_key


def parse_pcaps(args):
    
    connections = {}
    misp_event = MISPEvent()
    misp_event.info = f'PCAP parsing of the file {args.input}'

    # We call the tshark command
    cmd = define_command(args.input, standard_filters)
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # We read the results of the tshark command on the stdout channel
    for line in proc.stdout.readlines():
        timestamp, ip_src, ip_dst, ts_port, td_port, us_port, ud_port, protocols = line.decode().strip('\n').split('|')

        # We store the connection information
        key = (
            ip_src, ip_dst,
            ts_port if ts_port else us_port,
            td_port if td_port else ud_port,
            *handle_protocols(protocols)
        )
        if key not in connections:
            connections[key] = {
                'first_seen': float('inf'),
                'counter': 0
            }
        timestamp = float(timestamp)
        if timestamp < connections[key]['first_seen']:
            connections[key]['first_seen'] = timestamp
        connections[key]['counter'] += 1

    # Once we've processed the packets and grouped what had to be grouped,
    # we can now build the MISP `network-connection` objects
    for connection, values in connections.items():
        misp_object = misp_event.add_object(name='network-connection')
        for value, relation in zip(connection[:4], CONNECTION_OBJECT_RELATIONS):
            if value:
                misp_object.add_attribute(relation, value)
        for protocol in connection[4:]:
            layer = 3 if protocol in layer3_protocols else 4 if protocol in layer4_protocols else 7
            misp_object.add_attribute(f'layer{layer}-protocol', protocol.upper())
        misp_object.add_attribute('first-packet-seen', values['first_seen'])
        misp_object.add_attribute('count', values['counter'])
    output_filename = f"{'.'.join(args.input.name.split('.')[:-1])}.v1.misp.json"
    with open(args.outputpath / output_filename, 'wt', encoding='utf-8') as f:
        f.write(misp_event.to_json(indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert network data from PCAP files to MISP')
    
    parser.add_argument('-i', '--input', required=True, help='PCAP input files to parse')
    parser.add_argument('-o', '--outputpath', default=default_path, help='Output path to store the MISP JSON format results')

    args = parser.parse_args()
    args.input = Path(args.input).resolve()
    if not isinstance(args.outputpath, Path):
        args.outputpath = Path(args.outputpath).resolve()
    parse_pcaps(args)
