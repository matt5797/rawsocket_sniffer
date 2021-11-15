# rawsocket_sniffer
sniffing ICMP, DNS, HTTP packet with raw socket

## options
### usage: 
>sniffer.py [-h] [-s] [-sp SORCEPORT] [-dp DESTPORT]
                  [-np NECESSARY_PROTO] [-ep EXCEPT_PROTO] [-dl DISPLAY_LAYER]
                  
### optional arguments:
help
    -h, --help            
    show this help message and exit

summary
    -s, --summary         
    summary mode

sorce port
    -sp SORCEPORT, --sorceport SORCEPORT         
    sorce port

destination port
    -dp DESTPORT, --destport DESTPORT         
    destination port

necessary_proto
    -np NECESSARY_PROTO, --necessary_proto NECESSARY_PROTO         
    necessary protocol: [Ethernet, IP, ICMP, TCP, UDP]

except protocol
    -ep EXCEPT_PROTO, --except_proto EXCEPT_PROTO         
    except protocol: [Ethernet, IP, ICMP, TCP, UDP]

display layer
   -dl DISPLAY_LAYER, --display_layer DISPLAY_LAYER         
    display layer: [datalink, network, transport, application]