# Automate the collection of data from network captures

`Wireshark` and `thsark` alternative in Python is `pyshark`.  
We could definitely play with it and avoid being bothered with subprocesses, but...  
`pyshark` is way too slow.

The preferred solution for today is then going to be:
- Calling bash subprocesses with the `subprocess` library
- Which allows us to use `tshark` (or any other preferred network capture parsing tool)
- We can even use `parallel` to make it quicker

### Non exhaustive list of useful libraries to make our life easier

#### argparse

`argparse` is a powerful and easy-to-use command-line argument parser library for Python. It allows you to write code that can accept a variety of input options and arguments when the code is run from the command line.

#### PyMISP (obviously)

The main point here is to use PyMISP to automatically encode the data into MISP Events, Attributes & Objects  
And it is also more convenient that writing dictionaries by hand.

### Hints for the PCAP parsing

#### Focus on a specific type of data

One strategy could be to focus on a specific type of data first, like the DNS requests, the HTTP connections, etc.  
We can then add additional features.

#### Choose an output format

`tshark` is able to display the packets of a netwrk capture in different formats.  
There is for instance:
    - `fields` -> content is displayed in a 'CSV like' format with each packet being a line of values separated by a certain separator (that we can specify in our `tshark` command)
    - `json` -> each packet is displayed in a JSON blob
    
The next question after we chose our favorite output format is: Do we filter the fields to display (recommanded for the `fields` display) or keep everything available (OK if we use the `json` display)

#### Example of tshark command

```bash
tshark -T fields -E header=yes -E separator='|' -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e _ws.col.Protocol -e frame.time -o tcp.relative_sequence_numbers:FALSE -r data/2024-01-30-DarkGate-infection-traffic.pcap
```

In order to use the `tshark` command, we can use:
```python
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
lines = proc.stdout.readlines()
```

And the loop over the returned lines.

Each line can then be parsed as a CSV entry:
```python
ip_src, ip_dst, src_port, dst_port, protocol, frame_time = line.split('|')
```

### Usage

```bash
python pcap2misp.py -i data/2024-01-30-DarkGate-infection-traffic.pcap
```

