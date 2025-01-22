import requests
from pathlib import Path
from zipfile import ZipFile

current_path = Path(__file__).resolve().parent

filenames = (
    '2025-01-09-CVE-2017-0199-XLS-to-DBatLoader-or-GuLoader-for-AgentTesla-variant.pcap',
    '2025-01-13-KongTuke-leads-to-infection-abusing-BOINC.pcap'
)

base_url = 'https://www.malware-traffic-analysis.net'
for filename in filenames:
    yyyy, mm, dd = filename.split('-')[:3]
    zipped = current_path / 'data' / f'{filename}.zip'
    if zipped.exists():
        print(f'data/{filename}.zip already downloaded')
    else:
        url = f'{base_url}/{yyyy}/{mm}/{dd}/{filename}.zip'
        response = requests.get(url)
        if response.status_code == 200:
            with open(zipped, 'wb') as f:
                f.write(response.content)
            print(f'data/{filename}.zip - Successfully downloaded')
        else:
            print(f'Error while downloading from {url}:\n{response.status_code} - {response.reason}')
            continue
    unzipped = current_path / 'data' / filename
    if unzipped.exists():
        print(f'data/{filename} already unzipped')
        continue
    try:
        with ZipFile(current_path / 'data' / f'{filename}.zip', 'r') as zf:
            zf.extractall(
                current_path / 'data',
                pwd=bytes(f'infected_{yyyy}{mm}{dd}', 'utf-8')
            )
        print(f'    - Successfully unzipped')
    except Exception as e:
        print(f'An exception appeared during the unzipping process: {e}')
