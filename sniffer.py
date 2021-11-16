from socket import *
from struct import unpack
import binascii
from argparse import ArgumentParser


def print_section_header(src, level=0):
    if level==2:
        print("{:#^78}".format(" " + src + " "))
    elif level==1:
        print("{:=^78}".format(" " + src + " "))
    else:
        print("{:-^78}".format(" " + src + " "))


def print_section_footer(level=0):
    if level==2:
        print("{:#^78}".format(""))
    elif level==1:
        print("{:=^78}".format(""))
    else:
        print("{:-^78}".format(""))


class DataLinkHeader():
    def __init__(self, data):
        pass

    def dump(self):
        print_section_header("DataLink HEADER", 1)
        print_section_footer(1)


class EthernetHeader(DataLinkHeader):
    def __init__(self, data):
        self.type = "Ethernet"
        dest, src, eth_type = unpack('! 6s 6s H', data[:14])
        self.dest_mac = self.get_mac_addr(dest)
        self.src_mac = self.get_mac_addr(src)
        self.eth_type = eth_type
        self.eth_type_str = self.get_eth_type(self.eth_type)
        self.data = data[14:]

    def dump(self):
        print_section_header("Ethernet HEADER", 1)
        print("Source MAC : {}".format(self.src_mac))
        print("Destination MAC : {}".format(self.dest_mac))
        print("Ethernet Type : {} ({})".format(hex(self.eth_type), self.eth_type_str))
        print_section_footer(1)

    def get_mac_addr(self, src):
        byte_str = ["{:02x}".format(src[i]) for i in range(0, len(src))]
        return ":".join(byte_str)

    def get_eth_type(self, src):
        EtherTypes = {0x0800 : "IPv4", 0x0806 : "ARP", 0x8035 : "RARP", 0x814c : "SNMP", 0x86dd : "IPv6"}
        if src not in EtherTypes.keys():
            return "Unknown"
        return EtherTypes[src]


class NetworkHeader():
    def __init__(self, data):
        return

    def dump(self):
        print_section_header("Network HEADER", 1)
        print_section_footer(1)


class IPv4Header(NetworkHeader):
    def __init__(self, data):
        self.type = "IP"
        hdr_unpacked = unpack("!BBHHHBBH4s4s", data[:20])

        self.ver = hdr_unpacked[0] >> 4
        self.ver_str = self.get_ip_version(self.ver)
        self.hdr_size = (hdr_unpacked[0] & 0b1111) * 4
        self.dscp = hdr_unpacked[1] >> 6
        self.ecn = hdr_unpacked[1] & 0b11
        self.tlen = hdr_unpacked[2]
        self.id = hdr_unpacked[3]
        self.flags = self.get_ip_flag(hdr_unpacked[4] >> 3)
        self.fragoff = hdr_unpacked[4] & 0b1111111111111
        self.ttl = hdr_unpacked[5]
        self.proto = hdr_unpacked[6]
        self.proto_str = self.get_trans_proto(self.proto)
        self.check_sum = hdr_unpacked[7]
        self.src_ip = inet_ntoa(hdr_unpacked[8])
        self.dst_ip = inet_ntoa(hdr_unpacked[9])
        self.data = data[self.hdr_size:]

    def dump(self):
        print_section_header("IP HEADER", 1)

        print("Version : {} ({})".format(self.ver, self.ver_str))
        print("IP Header Length : {} bytes".format(self.hdr_size))
        print("Diff Services : {}".format(self.dscp))
        print("Expl Congestion Notification : {}".format(self.ecn))
        print("Total Length : {} bytes".format(self.tlen))
        print("Identification : 0x{:04x}".format(self.id))
        print("Flags : {}".format(self.flags))
        print("Fragment Offset : {}".format(self.fragoff))
        print("TTL : {}".format(self.ttl))
        print("Protocol : {} ({})".format(self.proto, self.proto_str))
        print("Checksum : 0x{:04x}".format(self.check_sum))
        print("Source IP : {}".format(self.src_ip))
        print("Destination IP : {}".format(self.dst_ip))

        print_section_footer(1)

    def get_ip_version(self, src):
        IPVersions = {4:"IPv4", 6: "IPv6"}
        if src not in IPVersions.keys():
            return "Unknown"
        return IPVersions[src]

    def get_trans_proto(self, src):
        TransportProtocols = {1:"ICMP",
                              2: "IGMP",
                              6: "TCP",
                              9: "IGRP",
                              17: "UDP",
                              47: "GRE",
                              50: "ESP",
                              51: "AH",
                              57: "SKIP",
                              66: "RVD",
                              88: "EIGRP",
                              89: "OSPF",
                              115: "L2TP"}
        if src not in TransportProtocols.keys():
            return "Unknown"
        return TransportProtocols[src]

    def get_ip_flag(self, flag_bits):
        result = []
        if flag_bits & 0b11 >> 1:
            result.append("DF")
        if flag_bits & 0b1:
            result.append("MF")

        if result:
            return ",".join(result)
        else:
            return "--"


class TransportHeader():
    def __init__(self, data):
        print(data)
        return

    def dump(self):
        print_section_header("Network HEADER", 1)
        print_section_footer(1)


class ICMPHeader(TransportHeader):
    def __init__(self, data):
        self.type = "ICMP"
        hdr_unpacked = unpack("!BBHL", data[:8])

        self.icmp_type = hdr_unpacked[0]
        self.icmp_code = hdr_unpacked[1]
        self.check_sum = hdr_unpacked[2]
        self.message = hdr_unpacked[3]
        if len(data[8:]) > 0:
            self.message2 = data[8:]
        else:
            self.message2 = None
        self.hdr_size = len(data)
        self.data = data[self.hdr_size:]
        self.src_port = 0
        self.dst_port = 0

    def dump(self):
        print_section_header("IP HEADER", 1)

        print("ICMP Type : {} ({})".format(self.icmp_type, self.get_icmp_type()))
        print("ICMP Code : {} ({})".format(self.icmp_code, self.get_icmp_code()))
        print("Checksum : {}".format(self.check_sum))
        print("Message : {}".format(self.message))

        print_section_footer(1)

    def get_icmp_type(self):
        ICMPType = {0: "Echo Reply", 
                    3: "Destination Unreachable", 
                    4: "Source quench",
                    5: "Redirect",
                    8: "Echo request", 
                    9: "Router advertisement",
                    10: "Router selection",
                    11: "Time Exceeded",
                    12: "Parameter problem",
                    13: "Timestamp",
                    14: "Timestamp reply",
                    15: "Information request",
                    16: "Information reply",
                    17: "Address mask request",
                    18: "Address mask reply",
                    30: "Traceroute",
                   }
        if self.icmp_type not in ICMPType.keys():
            return "Unknown"
        return ICMPType[self.icmp_type]

    def get_icmp_code(self):
        ICMPCode = {3: {
                        0: "Net is unreachable",
                        1: "Host is unreachable",
                        2: "Protocol is unreachable",
                        3: "Port is unreachable",
                        4: "Fragmentation is needed and Don't Fragment was set",
                        5: "Source route failed",
                        6: "Destination network is unknown",
                        7: "Destination host is unknown",
                        8: "Source host is isolated",
                        9: "Communication with destination network is administratively prohibited",
                        10: "Communication with destination host is administratively prohibited",
                        11: "Destination network is unreachable for type of service",
                        12: "Destination host is unreachable for type of service",
                        13: "Communication is administratively prohibited",
                        14: "Host precedence violation",
                        15: "Precedence cutoff is in effect",
                    },
                    5: {
                        0: "Redirect datagram for the network (or subnet)",
                        1: "Redirect datagram for the host",
                        2: "Redirect datagram for the type of service and network",
                        3: "Redirect datagram for the type of service and host",
                    },
                    11: {
                        0: "Time to Live exceeded in transit",
                        1: "Fragment reassembly time exceeded",
                    },
                    12: {
                        0: "Pointer indicates the error",
                        1: "Missing a required option",
                        2: "Bad length",
                    }
                     }
        if self.icmp_type not in ICMPCode.keys():
            return ""
        if self.icmp_code not in ICMPCode[self.icmp_type].keys():
            return "Unknown"
        return ICMPCode[self.icmp_type][self.icmp_code]


class UDPHeader(TransportHeader):
    def __init__(self, data):
        self.type = "UDP"
        hdr_unpacked = unpack("!HHHH", data[:8])

        self.src_port = hdr_unpacked[0]
        self.dst_port = hdr_unpacked[1]
        self.length = hdr_unpacked[2]
        self.check_sum = hdr_unpacked[3]
        self.hdr_size = 8
        self.data = data[self.hdr_size:]

    def dump(self):
        print_section_header("UDP HEADER", 1)

        print("Source Port : {}".format(self.src_port))
        print("Destination Port : {}".format(self.dst_port))
        print("UDP Length : {} bytes".format(self.length))
        print("Checksum : {}".format(self.check_sum))

        print_section_footer(1)


class TCPHeader(TransportHeader):
    def __init__(self, data):
        self.type = "TCP"
        hdr_unpacked = unpack("!HHLLHHHH", data[:20])

        self.src_port = hdr_unpacked[0]
        self.dst_port = hdr_unpacked[1]
        self.seq_num = hdr_unpacked[2]
        self.ack_num = hdr_unpacked[3]
        self.hdr_size = (hdr_unpacked[4] >> 12) * 4
        self.flags = self.get_tcp_flag(hdr_unpacked[4] & 0b111111111)
        self.win_size = hdr_unpacked[5]
        self.check_sum = hdr_unpacked[6]
        self.urg_ptr = hdr_unpacked[7]
        self.data = data[self.hdr_size:]

    def dump(self):
        print_section_header("TCP HEADER", 1)

        print("Source Port : {}".format(self.src_port))
        print("Destination Port : {}".format(self.dst_port))
        print("Sequence Number : {}".format(self.seq_num))
        print("Acknowledgement number : {}".format(self.ack_num))
        print("TCP Header Length : {} bytes".format(self.hdr_size))
        print("TCP Flags : {}".format(self.flags))
        print("Window size : {}".format(self.win_size))
        print("Checksum : {}".format(self.check_sum))
        print("Urgent Pointer : {}".format(self.urg_ptr))

        print_section_footer(1)

    def get_tcp_flag(self, flag_bits):
        result = []
        if flag_bits & 0b100000000:
            result.append("NS")
        if flag_bits & 0b010000000:
            result.append("CWR")
        if flag_bits & 0b001000000:
            result.append("ECE")
        if flag_bits & 0b000100000:
            result.append("URG")
        if flag_bits & 0b000010000:
            result.append("ACK")
        if flag_bits & 0b000001000:
            result.append("PSH")
        if flag_bits & 0b000000100:
            result.append("RST")
        if flag_bits & 0b000000010:
            result.append("SYN")
        if flag_bits & 0b000000001:
            result.append("FIN")

        if result:
            return ",".join(result)
        else:
            return "--"


class ApplicationData():
    def __init__(self, payload):
        self.payload_raw = payload
        self.payload = payload
        self.protocol = "Unknown"

    def dump(self):
        print_section_header("Application HEADER", 1)
        print_section_footer(1)


class HTTPData(ApplicationData):
    def __init__(self, payload):
        self.type = "HTTP"
        self.payload_raw = payload
        self.payload = payload.decode('ascii')

        headers, body = self.payload.split('\r\n\r\n')
        headers = headers.split('\r\n')
        start_line = headers.pop(0).split(' ')

        self.result = {}
        if start_line[0] in ['POST', 'GET', 'HEAD', 'PUT', 'DELETE']:    # 요청일때
            self.result['request'], self.result['headers'] = {}, {}
            self.result['request']['method'], self.result['request']['url'], self.result['request']['version'] = start_line
            for line in headers:
                line = line.split(': ')
                self.result['headers'][line[0]] = line[1]
            self.result['body'] = body
            self.protocol = self.result['request']['version']
        elif start_line[0] in ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']:    # 응답일때
            self.result['response'], self.result['headers'] = {}, {}
            self.result['response']['protocol'], self.result['response']['state_code'], self.result['response']['state_line'] = start_line
            for line in headers:
                line = line.split(': ')
                self.result['headers'][line[0]] = line[1]
            self.result['body'] = body
            self.protocol = self.result['response']['protocol']
        else:
            self.protocol = "Unknown HTTP"

    def dump(self):
        if 'request' in self.result.keys():
            print_section_header("HTTP REQUEST", 1)
            for key, value in self.result['request'].items():
                print("{}: {}".format(key, value))

            print_section_header("headers", 0)
            for key, value in self.result['headers'].items():
                print("{}: {}".format(key, value))

            print_section_header("body", 0)
            print("{}: {}".format('body', self.result['body']))
        else:
            print_section_header("HTTP RESPONSE", 1)
            for key, value in self.result['response'].items():
                print("{}: {}".format(key, value))

            print_section_header("headers", 0)
            for key, value in self.result['headers'].items():
                print("{}: {}".format(key, value))

            print_section_header("body", 0)
            print("{}: {}".format('body', self.result['body']))

        print_section_footer(1)


class Packet():
    def __init__(self, raw_data):
        try:
            self.raw_data = raw_data
            self.datalink_header, data = self.get_datalink_header(raw_data)
            self.network_header, data = self.get_network_header(data)
            self.transport_header, data = self.get_transport_header(data)
            self.application_data = self.get_application_data(data)
        except Exception as ex:
            print(ex)
            print("error packet: ", self.raw_data)
            self.dump()

    def is_filtered(self, opts):
        types = [x.type for x in [self.datalink_header, self.network_header, self.transport_header, self.application_data] if x]

        if opts[0] and len(set(types).intersection(set(opts[0])))==0:
            return False
        if opts[1] and len(set(types).intersection(set(opts[1])))>0:
            return False
        if opts[2] and self.transport_header and (self.transport_header.src_port not in opts[2] and self.transport_header.dst_port not in opts[3]):
            return False
        else:
            return True

    def dump(self, num=0, opts=['datalink', 'network', 'transport', 'application']):
        print_section_header("PACKET {}".format(num), 2)

        if self.datalink_header and 'datalink' in opts:
            self.datalink_header.dump()
        if self.network_header and 'network' in opts:
            self.network_header.dump()
        if self.transport_header and 'transport' in opts:
            self.transport_header.dump()
        if self.application_data and 'application' in opts:
            self.application_data.dump()

        print_section_footer(2)
        print('\n')

    def dump_summary(self, num=0):
        if self.network_header and self.transport_header:
            print("PACKET #{} / {}:{} -> {}:{} / ({})".format(num, self.network_header.src_ip, self.transport_header.src_port,  self.network_header.dst_ip, self.transport_header.dst_port, self.network_header.proto_str))

    def get_datalink_header(self, data):
        if True:
            eth = EthernetHeader(data)
            return eth, eth.data
        return None, None

    def get_network_header(self, data):
        if len(data)==0:
            return None, None
        if True:
            ip = IPv4Header(data)
            return ip, ip.data
        return None, None

    def get_transport_header(self, data):
        if self.network_header:
            if len(self.raw_data)==0:
                return None, None
            elif self.network_header.proto_str=="ICMP":
                icmp = ICMPHeader(data)
                return icmp, icmp.data
            elif self.network_header.proto_str=="TCP":
                tcp =  TCPHeader(data)
                return tcp, tcp.data
            elif self.network_header.proto_str=="UDP":
                udp =  UDPHeader(data)
                return udp, udp.data
        return None, None

    def get_application_data(self, data):
        if self.transport_header:
            if len(data)==0:
                return None
            elif (self.transport_header.src_port in [80,8080] or self.transport_header.dst_port in [80,8080]):
                return HTTPData(data)
        return None


class Sniffer():
    def __init__(self):
        self.hostname = gethostname()
        self.host = gethostbyname(self.hostname)
        self.sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))

    def sniffing(self, cnt, opts, summary=False):
        for i in range(cnt):
            raw_data, addr = self.sniffer.recvfrom(65565)
            packet = Packet(raw_data)
            if packet.is_filtered(opts) and not summary:
                if opts[-1]:
                    packet.dump(i, opts[-1])
                else:
                    packet.dump(i)
            elif packet.is_filtered(opts) and summary:
                packet.dump_summary(i)

    def main(self, args):
        print(self.hostname)
        print('start sniffing {0}'.format(self.host))
        print('options: ', args)
        self.sniffing(1000, (args.necessary_proto, args.except_proto, args.sorceport, args.destport, args.display_layer), args.summary)


def argparser():
    parser = ArgumentParser()
    parser.add_argument('-s', '--summary', action='store_true', help='summary mode')
    parser.add_argument('-sp', '--sorceport', action='append', type=int, help='sorce port')
    parser.add_argument('-dp', '--destport', action='append', type=int, help='destination port')

    parser.add_argument('-np', '--necessary_proto', action='append', type=str, help='necessary protocol: [Ethernet, IP, ICMP, TCP, UDP]')
    parser.add_argument('-ep', '--except_proto', action='append', type=str, help='except protocol: [Ethernet, IP, ICMP, TCP, UDP]')

    parser.add_argument('-dl', '--display_layer', action='append', type=str, help='display layer: [datalink, network, transport, application]')

    return parser.parse_args()


if __name__ == "__main__":
    args = argparser()
    Sniffer().main(args)

