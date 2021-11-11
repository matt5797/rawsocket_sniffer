from socket import *
from struct import unpack
import binascii
    
        
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
    def __init__(self, hdr_str):
        pass
        
    def dump(self):
        print_section_header("DataLink HEADER", 1)
        print_section_footer(1)
        
class EthernetHeader(DataLinkHeader):
    def __init__(self, hdr_str):
        self.type = "Ethernet"
        dest, src, eth_type = unpack('! 6s 6s H', hdr_str)
        self.dest_mac = self.get_mac_addr(dest)
        self.src_mac = self.get_mac_addr(src)
        self.eth_type = eth_type
        self.eth_type_str = self.get_eth_type(self.eth_type)

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
    def __init__(self, hdr_str):
        return
    
    def dump(self):
        print_section_header("Network HEADER", 1)
        print_section_footer(1)


class IPHeader(NetworkHeader):
    def __init__(self, hdr_str):
        self.type = "IP"
        hdr_unpacked = unpack("!BBHHHBBH4s4s", hdr_str)

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
        TransportProtocols = {1:"ICMP", 6: "TCP", 17: "UDP"}
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
    def __init__(self, hdr_str):
        print(hdr_str)
        return

    def dump(self):
        print_section_header("Network HEADER", 1)
        print_section_footer(1)


class ICMPHeader(TransportHeader):
    def __init__(self, hdr_str):
        self.type = "ICMP"
        hdr_unpacked = unpack("!BBHL", hdr_str[:8])
        
        self.icmp_type = hdr_unpacked[0]
        self.code = hdr_unpacked[1]
        self.check_sum = hdr_unpacked[2]
        self.message = hdr_unpacked[3]
        if len(hdr_str[8:]) > 0:
            self.message2 = hdr_str[8:]
        else:
            self.message2 = None
        self.hdr_size = len(hdr_str)

    def dump(self):
        print_section_header("IP HEADER", 1)

        print("ICMP Type : {} ({})".format(self.icmp_type, self.get_icmp_type(self.icmp_type)))
        print("ICMP CODE : {}".format(self.code))
        print("Checksum : {}".format(self.check_sum))
        print("Message : {}".format(self.message))

        print_section_footer(1)

    def get_icmp_type(self, src):
        IPVersions = {8:"Echo request", 0: "Echo reply"}
        if src not in IPVersions.keys():
            return "Unknown"
        return IPVersions[src]


class UDPHeader(TransportHeader):
    def __init__(self, hdr_str):
        self.type = "UDP"
        hdr_unpacked = unpack("!HHHH", hdr_str)

        self.src_port = hdr_unpacked[0]
        self.dst_port = hdr_unpacked[1]
        self.length = hdr_unpacked[2]
        self.check_sum = hdr_unpacked[3]
        self.hdr_size = 8

    def dump(self):
        print_section_header("UDP HEADER", 1)

        print("Source Port : {}".format(self.src_port))
        print("Destination Port : {}".format(self.dst_port))
        print("UDP Length : {} bytes".format(self.length))
        print("Checksum : {}".format(self.check_sum))

        print_section_footer(1)

        
class TCPHeader(TransportHeader):
    def __init__(self, hdr_str):
        self.type = "TCP"
        hdr_unpacked = unpack("!HHLLHHHH", hdr_str)

        self.src_port = hdr_unpacked[0]
        self.dst_port = hdr_unpacked[1]
        self.seq_num = hdr_unpacked[2]
        self.ack_num = hdr_unpacked[3]
        self.hdr_size = (hdr_unpacked[4] >> 12) * 4
        self.flags = self.get_tcp_flag(hdr_unpacked[4] & 0b111111111)
        self.win_size = hdr_unpacked[5]
        self.check_sum = hdr_unpacked[6]
        self.urg_ptr = hdr_unpacked[7]

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
            self.datalink_header = self.get_datalink_header()
            self.network_header = self.get_network_header()
            self.transport_header = self.get_transport_header()
            self.application_data = self.get_application_data()
        except Exception as ex:
            print(ex)
            print("error packet: ", self.raw_data)
            
    def is_filtered(self, opts):
        types = [x.type for x in [self.datalink_header, self.network_header, self.transport_header, self.application_data] if x]
        
        if len(opts[0])>0 and len(set(types).intersection(set(opts[0])))==0:
            return False
        if len(opts[1])>0 and len(set(types).intersection(set(opts[1])))>0:
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
        
    def get_datalink_header(self):
        data = self.raw_data[:14]
        if True:
            return EthernetHeader(data)
        return None
    
    def get_network_header(self):
        offset = 14
        if len(self.raw_data)<=offset:
            return None
        if True:
            data = self.raw_data[offset:offset+20]
            return IPHeader(data)
        return None
    
    def get_transport_header(self):
        if self.network_header:
            offset = 14 + self.network_header.hdr_size
            if len(self.raw_data)<=offset:
                return None
            elif self.network_header.proto_str=="ICMP":
                data = self.raw_data[offset:]
                return ICMPHeader(data)
            elif self.network_header.proto_str=="TCP":
                data = self.raw_data[offset:offset + 20]
                return TCPHeader(data)
            elif self.network_header.proto_str=="UDP":
                data = self.raw_data[offset:offset + 8]
                return UDPHeader(data)
        return None
        
    def get_application_data(self):
        if self.transport_header:
            offset = 14 + self.network_header.hdr_size + self.transport_header.hdr_size
            data = self.raw_data[offset:]
            if len(self.raw_data)<=offset:
                return None
            elif (self.transport_header.src_port in [80,8080] or self.transport_header.dst_port in [80,8080]):
                return HTTPData(data)
        return None


def sniffing(host, opts):
    sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
    
    for i in range(1000):
        raw_data, addr = sniffer.recvfrom(65565)
        packet = Packet(raw_data)
        if packet.is_filtered(opts):
            packet.dump(i, opts[2])
        #if len(opts[0])==0 or packet.network_header.proto_str in opts[0]:    #옵션 만들어야됨
        #    if len(opts[1])==0 or (packet.transport_header.dst_port in opts[1] or packet.transport_header.src_port in opts[1]):
        #        packet.dump(i, opts[2])

def main():
    print(gethostname())
    host = gethostbyname(gethostname())
    print('start sniffing {0}'.format(host))
    # 필터 형식: ([필수 프로토콜], [제외 프로토콜], [출력 단위])
    #sniffing('127.0.0.1', (['ICMP', 'Ethernet', 'TCP'], [], ['datalink', 'network', 'transport', 'application']))
    #sniffing('127.0.0.1', (['IP'], [], ['datalink', 'network', 'transport', 'application']))
    sniffing('127.0.0.1', (['ICMP'], [], ['datalink', 'network', 'transport', 'application']))


if __name__ == "__main__":
    main()

