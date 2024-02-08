import requests
from pathlib import Path
from zipfile import ZipFile

current_path = Path(__file__).resolve().parent

filenames = (
    '2024-01-19-GootLoader-infection-traffic.pcap',
    '2024-01-23-UltraVNC-infection-traffic.pcap',
    '2024-01-30-DarkGate-infection-traffic.pcap'
)

name = 'traffic-analysis'
for filename in filenames:
    yyyy, mm, dd = filename.split('-')[:3]
    zipped = current_path / 'data' / f'{filename}.zip'
    if zipped.exists():
        print(f'data/{filename}.zip already downloaded')
    else:
        url = f'https://www.malware-{name}.net/{yyyy}/{mm}/{dd}/{filename}'
        response = requests.get(url)
        if response.status_code == 200:
            with open(current_path / 'data' / filename, 'wb') as f:
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
