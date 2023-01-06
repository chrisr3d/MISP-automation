import requests
from pathlib import Path
from zipfile import ZipFile

current_path = Path(__file__).resolve().parent

name = 'traffic-analysis'
for date_value in ('2021-08-19', '2021-09-10', '2022-01-07', '2022-02-23', '2022-03-21'):
    yyyy, mm, dd = date_value.split('-')
    filename = f'{date_value}-{name}-exercise.pcap'
    if (current_path / 'data' / filename).exists():
        print(f'data/{filename} already downloaded and unzipped!')
        continue
    url = f'https://www.malware-{name}.net/{yyyy}/{mm}/{dd}/{filename}.zip'
    response = requests.get(url)
    if response.status_code == 200:
        with open(current_path / 'data' / f'{filename}.zip', 'wb') as f:
            f.write(response.content)
        print(f'data/{filename}.zip - Successfully downloaded')
    else:
        print(f'Error while downloading from {url}:\n{response.status_code} - {response.reason}')
        continue
    try:
        with ZipFile(current_path / 'data' / f'{filename}.zip', 'r') as zf:
            zf.extractall(current_path / 'data', pwd=bytes('infected', 'utf-8'))
        print(f'    - Successfully unzipped')
    except Exception as e:
        print(f'An exception appeared during the unzipping process: {e}')
