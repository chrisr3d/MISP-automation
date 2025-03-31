import argparse
import binascii
import json
import re
import subprocess
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from pymisp import MISPEvent, PyMISP
from pymisp.tools import FileObject, make_binary_objects

default_path = Path(__file__).resolve().parent / 'data'

# Non exhaustive list of protocols to populate `network-connection` object attributes
layer3_protocols = {'ip': 'IP', 'ipv6': 'IP'}
layer4_protocols = {'tcp': 'TCP', 'udp': 'UDP'}
layer7_protocols = {
    'dhcp': 'DHCP', 'dns': 'DNS', 'ftp': 'FTP', 'http': 'HTTP',
    'ntp': 'NTP', 'smtp': 'SMTP', 'snmp': 'SNMP', 'ssdp': 'SSDP',
    'ssl': 'HTTPS', 'tftp': 'TFTP', 'tls': 'HTTPS'
}

# Tshark filters
connection_fields = (
    'frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport', 'frame.protocols'
)
dns_fields = (
    'dns', 'dns.qry.name', 'dns.a', 'dns.aaaa', 'dns.cname',
    'dns.mx.mail_exchange', 'dns.ns', 'dns.ptr.domain_name',
    'dns.soa.rname', 'dns.spf', 'dns.srv.name'
)
http_fields = (
    'http', 'http.request.method', 'http.host', 'http.content_type',
    'http.cookie', 'http.referer', 'http.request.full_uri', 'http.request.uri',
    'http.user_agent'
)

# MISP object relations lists and mappings
CONNECTION_OBJECT_RELATIONS = ('ip-src', 'ip-dst', 'src-port', 'dst-port')
DNS_RECORDS_OBJECT_RELATIONS = (
    'queried-domain', 'a-record', 'aaaa-record', 'cname-record', 'mx-record',
    'ns-record', 'ptr-record', 'soa-record', 'spf-record', 'srv-record'
)
HTTP_REQUEST_OBJECT_RELATIONS = (
    'method', 'host', 'content-type', 'cookie', 'referer', 'url', 'uri',
    'user-agent'
)
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
    protocol_keys = []
    for protocol in frame_protocols.split(':'):
        if protocol in layer3_protocols:
            protocol_keys.append(layer3_protocols[protocol])
            continue
        if protocol in layer4_protocols:
            protocol_keys.append(layer4_protocols[protocol])
            continue
        if protocol in layer7_protocols:
            protocol_keys.append(layer7_protocols[protocol])
    return protocol_keys


def parse_pcap_info_line(line: str) -> tuple:
    if ' = ' in line:
        return line.split(' = ')
    return re.split(r': +', line)


def set_payload_name(uri: str, frame_number: str) -> str:
    filename = uri.split('/')[-2 if uri.endswith('/') else -1]
    if filename:
        return filename
    return f'payload_from_packet_{frame_number}'


def parse_pcaps(args):
    
    connections = {}
    http_requests = defaultdict(list)
    misp_event = MISPEvent()
    misp_event.info = f'PCAP parsing of the file {args.input.name}'
    misp_event.distribution = args.distribution

    # We can start by extracting the information about the PCAP file itself
    file_object = FileObject(filepath=args.input, standalone=False)
    misp_event.add_object(file_object)
    # Then we can extract the PCAP file metadata
    pcap_object = misp_event.add_object(name='pcap-metadata')
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

    # We call the tshark command
    cmd = define_command(
        args.input,
        connection_fields + dns_fields + http_fields
    )
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # We read the results of the tshark command on the stdout channel
    for line in proc.stdout.readlines():
        timestamp, ip_src, ip_dst, ts_port, td_port, us_port, ud_port, protocols, *fields = line.decode().strip('\n').split('|')

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
                'last_seen': 0.0
            }
        timestamp = float(timestamp)
        if timestamp < connections[key]['first_seen']:
            connections[key]['first_seen'] = timestamp
        if timestamp > connections[key]['last_seen']:
            connections[key]['last_seen'] = timestamp

        # We parse the dns record data
        if 'dns' in protocols and 'response' in fields[0]:
            dns_record = misp_event.add_object(name='dns-record')
            for relation, values in zip(DNS_RECORDS_OBJECT_RELATIONS, fields[1:11]):
                if values:
                    if ',' in values:
                        for value in values.split(','):
                            dns_record.add_attribute(relation, value)
                    else:
                        dns_record.add_attribute(relation, values)
            dns_record.add_reference(file_object.uuid, 'included-in')

        # We parse the http requests and store the reference to the created
        # MISP object so we can generate a reference between the `network-connection``
        # object related to the IP addresses and the `http-request` object
        if fields[11] == 'http':
            http_request = misp_event.add_object(name='http-request')
            http_request.add_attribute('ip-src', ip_src)
            http_request.add_attribute('ip-dst', ip_dst)
            for relation, value in zip(HTTP_REQUEST_OBJECT_RELATIONS, fields[12:]):
                if value:
                    http_request.add_attribute(relation, value)
            http_request.add_reference(file_object.uuid, 'included-in')
            http_requests[(ip_src, ip_dst)].append(http_request.uuid)

    # Once we've processed the packets and grouped what had to be grouped,
    # we can now build the MISP `network-connection` objects
    for connection, values in connections.items():
        misp_object = misp_event.add_object(name='network-connection')
        for value, relation in zip(connection[:4], CONNECTION_OBJECT_RELATIONS):
            if value:
                misp_object.add_attribute(relation, value)
        for protocol in connection[4:]:
            layer = 3 if protocol in layer3_protocols else 4 if protocol in layer4_protocols else 7
            misp_object.add_attribute(f'layer{layer}-protocol', protocol)
        misp_object.add_attribute('first-packet-seen', values['first_seen'])
        misp_object.add_attribute('last-packet-seen', values['last_seen'])
        misp_object.add_reference(file_object.uuid, 'included-in')
        # We check if this is an HTTP connection and there is an existing
        # reference to an `http-request` MISP object
        if 'http' in connection and (connection[0], connection[1]) in http_requests:
            for referenced_uuid in http_requests[(connection[0], connection[1])]:
                misp_object.add_reference(referenced_uuid, 'contains')
    output_filename = f"{'.'.join(args.input.name.split('.')[:-1])}.v4.misp.json"
    with open(args.outputpath / output_filename, 'wt', encoding='utf-8') as f:
        f.write(misp_event.to_json(indent=4))
    print(f'{args.input} successfully parsed - MISP format results extracted in {args.outputpath / output_filename}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert network data from PCAP files to MISP')
    
    parser.add_argument('-i', '--input', type=Path, required=True, help='PCAP input files to parse')
    parser.add_argument('-o', '--outputpath', default=default_path, help='Output path to store the MISP JSON format results')
    parser.add_argument(
        '-d', '--distribution', type=int, default=0, choices=[0, 1, 2, 3],
        help='''
            Distribution level for the imported MISP content (default is 0)
              - 0: Your organisation only
              - 1: This community only
              - 2: Connected communities
              - 3: All communities
            (For simplification purposes, we skip the "Sharing group" distribution level)
            '''
    )

    args = parser.parse_args()
    args.input = Path(args.input).resolve()
    if not isinstance(args.outputpath, Path):
        args.outputpath = Path(args.outputpath).resolve()
    parse_pcaps(args)
