# Analysing Network Capture

Doing network analysis, you usually have more than one way to do it. The challenge when doing network analysis is to find the interesting packets in the haystack. There are various tools to analyse network captures.

## Network Evidences

Network evidences like packet captures are at the root of a good analysis. If your evidences are partial or incorrect, you’ll produce incorrect or partial analysis. The coll ection of network evidences is often underestimated and seen as a simple process.

Factors to check while performing a network capture:

- Time reference (Is your system time synchronized? or What to do with network packet capture using an incorrect time-stamp?)
- Is a passive network collection always passive? (e.g. Are you doing name resolution? Do you have internet access from your network collection system? Can my network collec tion system be exploited?)
- Do you loose packets during the capture (or before?)? (e.g. Using netbeacon? Do you have any statistics from your network packet capture device?)
- Do you capture the correct size? (e.g. jumbo frame?)
- How large will be my packet capture? Should I have small file or large network capture files? Is my disk large enough to store the network capture? Is my disk fast enough to write capture files?
- Which format should I use to store my network capture? (pcap, pcap-ng?)



## Analysis Tools

- capinfos (Wireshark)
- mergecap (Wireshark)
- editcap (Wireshar)
- tcpdump
- [ipsumdump](http://www.read.seas.harvard.edu/~kohler/ipsumdump/)
- tshark
- tcpflow (1) and tcpflow (2)
- ngrep
- [yaf](https://tools.netsa.cert.org/yaf/)

## Data-set

```bash
python download_samples.py
```

## Examples

### tcpdump

```bash
ls -1 data/enforce-capture/*.cap | parallel 'tcpdump -s0 -A -r {1} -n port 53413' | grep http
```

### tshark

#### Type of packets

```bash
ls -1 data/*.pcap | parallel 'tshark -T fields -e _ws.col.Protocol -r {}' | sort | uniq -c | sort -rn
```

#### Extracting ISN

```bash
tshark -n -T fields -e frame.time_epoch -e tcp.seq -Y 'tcp' -r data/2021-08-19-traffic-analysis-exercise.pcap
```

#### Displaying the results

```bash
tshark -n -T fields -e frame.time_epoch -e tcp.seq -Y 'tcp' -r data/2021-08-19-traffic-analysis-exercise.pcap -o tcp.relative_sequence_numbers:FALSE | awk '{print $1"\t"$2}' | gnuplot -p -e 'set title "ISN"; plot "/dev/stdin" using :2 with points pointtype 0'

ls -1 data/*.pcap | parallel 'tshark -n -T fields -e frame.time_epoch -e tcp.seq -Y "tcp" -r {} -o tcp.relative_sequence_numbers:FALSE' | awk '{print $1"\t"$2}' | gnuplot -p -e 'set title "ISN"; plot "/dev/stdin" using :2 with points pointtype 0'
```

#### Extract the query name of all DNS requests

```bash
ls -1 data/*.pcap | parallel 'tshark -Tfields -e dns.qry.name -Y "dns" -r {}' | sort | uniq -c | sort -rn
```

#### Extract user-agent headers from IP pakets

```bash
ls -1 data/*.pcap| parallel 'tshark -E header=yes -E separator=, -Tfields -e http.user_agent -r {}' | grep -v "^$"
```

### Non exhaustive list of fields that might be interesting

- `frame.time`: the timestamp of the frame
- `ip.src`: the source IP address
- `ip.dst`: the destination IP address
- `tcp.srcport`: the source TCP port
- `tcp.dstport`: the destination TCP port
- `http.request.method`: the HTTP request method (e.g., GET, POST)
- `http.response.code`: the HTTP response code (e.g., 200, 404)
