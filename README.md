# rawsocket_sniffer
sniffing ICMP, DNS, HTTP packet with raw socket

## options
```
usage: sniffer.py [-h] [-s] [-sp SORCEPORT] [-dp DESTPORT]
                  [-np NECESSARY_PROTO] [-ep EXCEPT_PROTO] [-dl DISPLAY_LAYER]

optional arguments:
  -h, --help            show this help message and exit
  -s, --summary         summary mode
  -sp SORCEPORT, --sorceport SORCEPORT
                        sorce port
  -dp DESTPORT, --destport DESTPORT
                        destination port
  -np NECESSARY_PROTO, --necessary_proto NECESSARY_PROTO
                        necessary protocol: [Ethernet, IP, ICMP, TCP, UDP]
  -ep EXCEPT_PROTO, --except_proto EXCEPT_PROTO
                        except protocol: [Ethernet, IP, ICMP, TCP, UDP]
  -dl DISPLAY_LAYER, --display_layer DISPLAY_LAYER
                        display layer: [datalink, network, transport,
                        application]
```
