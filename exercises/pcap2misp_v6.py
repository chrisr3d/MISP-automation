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
    'udp.srcport', 'udp.dstport', 'frame.protocols', 'communityid'
)
dns_fields = (
    'dns', 'dns.qry.name', 'dns.a', 'dns.aaaa', 'dns.cname',
    'dns.mx.mail_exchange', 'dns.ns', 'dns.ptr.domain_name',
    'dns.soa.rname', 'dns.spf', 'dns.srv.name'
)
http_fields = (
    'http', 'http.request.method', 'http.host', 'http.content_type',
    'http.cookie', 'http.referer', 'http.request.full_uri', 'http.request.uri',
    'http.user_agent', 'http.file_data', 'frame.number'
)

# MISP object relations lists and mappings
CONNECTION_OBJECT_RELATIONS = (
    'community-id', 'ip-src', 'ip-dst', 'src-port', 'dst-port',
    'first-packet-seen', 'last-packet-seen', 'dst-packets-count',
    'src-packets-count', 'layer3-protocol', 'layer4-protocol'
)
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


def handle_protocols(
        frame_protocols: str, connection: dict = None) -> dict | None:
    if connection is None:
        connection = {'layer7-protocol': set()}
        for protocol in frame_protocols.split(':'):
            if layer3_protocols.get(protocol) is not None:
                connection['layer3-protocol'] = layer3_protocols[protocol]
                continue
            if layer4_protocols.get(protocol) is not None:
                connection['layer4-protocol'] = layer4_protocols[protocol]
        return connection
    # If we already have a connection, we see if we have a new layer 7 protocol
    for protocol in frame_protocols.split(':'):
        if layer7_protocols.get(protocol) is not None:
            connection['layer7-protocol'].add(layer7_protocols[protocol])


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
        (timestamp, ip_src, ip_dst, ts_port, td_port, us_port, ud_port,
         protocols, community_id, *fields) = line.decode().strip('\n').split('|')

        # We use the community ID as key and we store the other field values
        if community_id not in connections:
            # we directly store object relations as keys of the dictionary
            connections[community_id] = {
                'community-id': community_id,
                'ip-src': ip_src, 'ip-dst': ip_dst,
                'src-port': ts_port if ts_port else us_port,
                'dst-port': td_port if td_port else ud_port,
                'first-packet-seen': float('inf'), 'last-packet-seen': 0.0,
                'src-packets-count': 0, 'dst-packets-count': 0,
                **handle_protocols(protocols)
            }

        # The we update the connection information - timestamps & counters
        connection = connections[community_id]
        timestamp = float(timestamp)
        if timestamp < connection['first-packet-seen']:
            connection['first-packet-seen'] = timestamp
        if timestamp > connection['last-packet-seen']:
            connection['last-packet-seen'] = timestamp
        if ip_src == connection['ip-src'] and ip_dst == connection['ip-dst']:
            connection['dst-packets-count'] += 1
        else:
            connection['src-packets-count'] += 1
        # We handle the layer 7 protocols separately
        handle_protocols(protocols, connection)

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
        http, *_, response_uri, _, file_data, frame_number = fields[11:]
        if http == 'http':
            http_request = misp_event.add_object(name='http-request')
            http_request.add_attribute('ip-src', ip_src)
            http_request.add_attribute('ip-dst', ip_dst)
            for relation, value in zip(HTTP_REQUEST_OBJECT_RELATIONS, fields[12:-2]):
                if value:
                    http_request.add_attribute(relation, value)
            http_request.add_reference(file_object.uuid, 'included-in')
            http_requests[(ip_src, ip_dst)].append(http_request.uuid)

            # We extract the file data from the http layer and generate MISP objects
            if file_data:
                payload, executable, sections = make_binary_objects(
                    pseudofile=BytesIO(binascii.unhexlify(file_data)),
                    filename=set_payload_name(response_uri, frame_number),
                    standalone=False
                )
                misp_event.add_object(payload)
                http_request.add_reference(payload.uuid, 'drops')
                if executable is not None:
                    misp_event.add_object(executable)
                    if sections:
                        for section in sections:
                            misp_event.add_object(section)

    # Once we've processed the packets and grouped what had to be grouped,
    # we can now build the MISP `network-connection` objects
    for connection in connections.values():
        misp_object = misp_event.add_object(name='network-connection')
        # as we stored the object relations, we can directly use them to add attributes
        for relation in CONNECTION_OBJECT_RELATIONS:
            misp_object.add_attribute(relation, connection[relation])
        for protocol in connection['layer7-protocol']:
            misp_object.add_attribute('layer7-protocol', protocol)
        misp_object.add_reference(file_object.uuid, 'included-in')
        # We check if this is an HTTP connection and there is an existing
        # reference to an `http-request` MISP object
        if 'http' in connection and (connection[0], connection[1]) in http_requests:
            for referenced_uuid in http_requests[(connection[0], connection[1])]:
                misp_object.add_reference(referenced_uuid, 'contains')
    output_filename = f"{'.'.join(args.input.name.split('.')[:-1])}.v6.misp.json"
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
