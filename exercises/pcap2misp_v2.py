import argparse
import re
import subprocess
from pathlib import Path
from pymisp import MISPEvent, MISPAttribute, MISPObject, PyMISP
from pymisp.tools import FileObject

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

CONNECTION_OBJECT_RELATIONS = ('ip-src', 'ip-dst', 'src-port', 'dst-port')
PCAP_METADATA_OBJECT_MAPPING = {
    'Capture length': 'capture-length',
    'File encapsulation': 'protocol',
    'First packet time': 'first-packet-seen',
    'Last packet time': 'last-packet-seen'
}


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


def parse_pcap_info_line(line: str) -> tuple:
    if ' = ' in line:
        return line.split(' = ')
    return re.split(r': +', line)
    

def parse_pcaps(args):
    
    # Filters that might change with potential additions to the script
    filters = (
        'frame.time_epoch',
        'ip.src',
        'ip.dst',
        'tcp.srcport',
        'tcp.dstport',
        'frame.protocols'
    )

    connections = {}
    misp_event = MISPEvent()
    misp_event.info = f'PCAP parsing of the file {args.input}'

    # We can start by extracting the information about the PCAP file itself
    file_object = FileObject(filepath=args.input, standalone=False)
    misp_event.add_object(file_object)
    # Then we can extract the PCAP file metadata
    pcap_object = MISPObject('pcap-metadata')
    proc = subprocess.Popen(
        f'capinfos {args.input}', shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    for line in proc.stdout.readlines():
        decoded = line.decode().strip().strip('\n')
        try:
            key, value = parse_pcap_info_line(decoded)
        except ValueError:
            continue
        if key not in PCAP_METADATA_OBJECT_MAPPING:
            continue
        relation = PCAP_METADATA_OBJECT_MAPPING[key]
        pcap_object.add_attribute(
            relation,
            value.upper() if relation == 'protocol' else value
        )
    pcap_object.add_reference(file_object.uuid, 'describes')
    misp_event.add_object(pcap_object)

    cmd = define_command(args.input, filters)
    # We call the terminal command
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # We read the results of the terminal command on the stdout channel
    for line in proc.stdout.readlines():
        timestamp, ip_src, ip_dst, src_port, dst_port, frame_protocols = line.decode().strip('\n').split('|')
        key = (ip_src, ip_dst, src_port, dst_port, *handle_protocols(frame_protocols))
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
        misp_object = MISPObject('network-connection')
        for value, relation in zip(connection[:4], CONNECTION_OBJECT_RELATIONS):
            if value:
                misp_object.add_attribute(relation, value)
        for protocol in connection[4:]:
            layer = 3 if protocol in layer3_protocols else 4 if protocol in layer4_protocols else 7
            misp_object.add_attribute(f'layer{layer}-protocol', protocol.upper())
        misp_object.add_attribute(
            **{
                'type': 'datetime',
                'object_relation': 'first-packet-seen',
                'value': values['first_seen']
            }
        )
        misp_object.add_attribute(
            **{
                'type': 'counter',
                'object_relation': 'count',
                'value': values['counter']
            }
        )
        misp_object.add_reference(file_object.uuid, 'included-in')
        misp_event.add_object(misp_object)
    output_filename = f"{'.'.join(args.input.name.split('.')[:-1])}.misp.json"
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