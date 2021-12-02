# rawsocket_sniffer
sniffing ICMP, DNS, HTTP packet with raw socket


# CLI
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

# GUI
## filters example
```
example: ip.src==10.8.230.50 and ip.dst  !=   10.8.5.50 and eth.dst == 00:12:34:54:AC:BA  and eth.dst==  00:12:34:54:AC:BA and tcp.port == 80 and tcp and icmp and http and dns and !dns and  ip   andudp and udp.port==443

<protocol>.<option> == <target>
  <protocol>
    example: eht, ip, tcp, udp
  <option>
    example: src, dst, arrs, srcport, dstport, port
  <target>
    example: mac address, ip address

<protocol>
  <protocol>
    example: eht, ip, tcp, udp, icmp, http, dns

```