## Exercise steps

#### 1- Standard version

With the first version implemented in `pcap2misp_v1.py`, we simply extract `network-connection` objects.

The process is pretty straight forward:
- Process the network capture file with `tshark`in a `subprocess` command
- Loop through the packets displayed in the standard output and identify connections
- The connections information is stored in a dictionary:
  - The key is the tuple `(ip.src, ip.dst, tcp.srcport, tcp.dstport, *frame.protocols)`
  - We store the timestamp of the first packet seen and the number of similar connections
- We loop through dictionary and create a `network-connection` MISP object for each connection
- We write the resulting MISP Event in an output file

#### 2- Add the information of the input file in the MISP Event

Starting from the standard script described right above, add in the resulting MISP Event:
- the information of the network capture file
  - -> a `file` MISP object
  - it is recommanded to use the `FileObject` class from PyMISP
- additional information of the metadata
  - the `pcap-metadata` object template seems fine for this kind of data
  - you can use the `capinfos` command-line tool to get the information

#### 3- Parse dns records from the packets

Add either an option or as a default feature, the ability to parse the information of the DNS packets:
- use the `dns-record` MISP object to describe the DNS information
- to help you map the packets data with the object template, here is the list of fields to consider in a packet:
  - dns
  - dns.a
  - dns.aaaa
  - dns.cname
  - dns.mx.mail_exchange
  - dns.ns
  - dns.ptr.domain_name
  - dns.qry.name
  - dns.soa.rname
  - dns.spf
  - dns.srv.name
  
#### 4- Extract HTTP requests

Another kind of information we could find in our network captures is the HTTP requests.  
- use the `http-request` MISP object to describe the HTTP requests
- to help you map the packets data with the object template, here is a list of fields to consider in a packet:
  - http
  - http.content_type
  - http.cookie
  - http.host
  - http.referer
  - http.request.method
  - http.request.uri
  - http.user_agent

#### 5- Extract payloads

It is also possible to extract the payloads from the HTTP packets:
- the field you are looking for is `http.file_data`
- you can use the PyMISP helpers such as `make_binary_object` to generate MISP objects for you
  - `make_binary_object` can take the payload's file name or the payload itself as bytes
  - in order to pass the payload directly, encode it in a `BytesIO` object

#### 6- (Bonus) Share the parsed and converted MISP data in the MISP instance of your choice

Using the config file `MISP_config.json`, connect to your favourite MISP server and push the MISP Event you just created and populated with the parsed network capture data.

While there is mostly only one way to connect to the server using the `PyMISP` constructor, you can choose between 2 strategies to push your MISP data:
- the straight forward and easier way: keep the event and objects declaration as they are and add the event at the end.
- the trickier version: use from the beginning the `add_X` methods to let `pymisp` declare the event & objects and give you a pointer to the created structures.  
  In this situation you need to make sure the data is directly synchronised with your instance or you have to update it at the end
