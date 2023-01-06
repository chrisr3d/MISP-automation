import argparse
import subprocess
from pathlib import Path
from pymisp import MISPEvent, MISPAttribute, MISPObject, PyMISP

default_path = Path(__file__).resolve().parent / 'data'


def parse_pcaps(args):
    # MAGIC HERE
    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert network data from PCAP files to MISP')
    
    parser.add_argument('-i', '--input', required=True, nargs='+', help='PCAP input files to parse')
    parser.add_argument('-o', '--outputpath', default=default_path, help='Output path to store the MISP JSON format results')
    
    args = parser.parse_args()
    if not isinstance(args.outputpath, Path):
        args.outputpath = Path(args.outputpath).resolve()
    parse_pcaps(args)
