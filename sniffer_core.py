from socket import *
from struct import unpack
import binascii
from io import BytesIO


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


def get_hex_data(data):
    h = binascii.hexlify(data).decode()
    return " ".join([h[i:i+4] for i in range(0, len(h), 4)])


def get_IPv6_addr(data):
    groups = [i.lstrip("0") for i in get_hex_data(data).split(" ")]
    empties, start = [], -1
    for i, v in enumerate(groups):
        if not v:
            if start == -1:
                start = i
        elif start != -1:  # end of empty sequence
            empties.append((start, i-start))
            start = -1
    if empties:  # reduce: delete longest zero sequence
        longest, ii = (-1, -1), -1
        for i, v in enumerate(empties):
            if v[1] > longest[1]:
                longest, ii = v, i
        del empties[ii]
        for i in empties:
            for j in range(i[1]):
                groups[i[0]+j] = "0"
        for i in range(longest[1]-1):
            del groups[longest[0]]
        if longest[0] == 0:  # if :: is at the beginning
            groups[longest[0]] = ":"
    return ":".join(groups)


class DataLinkHeader():
    def __init__(self, data):
        pass

    def dump(self):
        print_section_header("DataLink HEADER", 1)
        print_section_footer(1)

    def get_json(self):
        return {}

    def get_info(self):
        return ""


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

    def get_json(self):
        return {'type': self.type, 'dest_mac': self.dest_mac, 'src_mac': self.src_mac, 'eth_type': self.eth_type_str}

    def get_info(self):
        return "{} -> {} ({})".format(self.src_mac, self.dest_mac, self.eth_type_str)

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

    def get_json(self):
        return {}

    def get_info(self):
        return ""


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

    def get_json(self):
        return {'type': self.type, 'ver': self.ver_str, 'hdr_size': self.hdr_size, 'dscp': self.dscp,
                'ecn': self.ecn, 'tlen': self.tlen, 'id': self.id, 'flags': self.flags, 'fragoff': self.fragoff,
                'ttl': self.ttl, 'proto': self.proto_str, 'check_sum': self.check_sum, 'src_ip': self.src_ip, 'dst_ip': self.dst_ip}

    def get_info(self):
        return "{} / {} -> {} ({})".format(self.ver_str, self.src_ip, self.dst_ip, self.proto_str)

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

    def get_json(self):
        return {}

    def get_info(self):
        return ""


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

    def get_json(self):
        return {'type': self.type, 'icmp_type': self.icmp_type, 'icmp_code': self.icmp_code, 'check_sum': self.check_sum,
                'message': self.message, 'message2': self.message2, 'hdr_size': self.hdr_size}

    def get_info(self):
        return "{} ({})".format(self.icmp_type, self.icmp_code)

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

    def get_json(self):
        return {'type': self.type, 'src_port': self.src_port, 'dst_port': self.dst_port, 'length': self.length,
                'check_sum': self.check_sum, 'hdr_size': self.hdr_size}

    def get_info(self):
        return "{} -> {} Len={}".format(self.src_port, self.dst_port, self.length)


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

    def get_json(self):
        return {'type': self.type, 'src_port': self.src_port, 'dst_port': self.dst_port, 'seq_num': self.seq_num,
                'ack_num': self.ack_num, 'hdr_size': self.hdr_size, 'flags': self.flags, 'win_size': self.win_size,
                'check_sum': self.check_sum, 'urg_ptr': self.urg_ptr}

    def get_info(self):
        return "{} -> {} [{}] Seq={} Ack={} Win={} Len={}".format(self.src_port, self.dst_port, self.flags, self.seq_num, self.ack_num, self.win_size, len(self.data))

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

    def get_json(self):
        return {}

    def get_info(self):
        return ""


class DNS():
    def get_query_type(self, src):
        QueryTypes = {0x0001: "A",
                      0x0002: "NS",
                      0x0005: "CNAME",
                      0x0006: "SOA",
                      0x000c: "PTR",
                      0x000f: "MX",
                      0x001c: "AAAA"}
        if src not in QueryTypes.keys():
            return "Unknown"
        return QueryTypes[src]
    
    def get_query_class(self, src):
        QueryClass = {0x0001: "IN",
                     0x0003: "CH",
                     0x0004: "HS"}
        if src not in QueryClass.keys():
            return "Unknown"
        return QueryClass[src]
    
    def readDNSstr(self, data):
        parts = []
        realparts = []
        pl = ord(data.read(1))
        while pl:
            if pl >= 0b11000000:
                data.seek(data.tell()-1)
                pointer = data.read(2)
                realparts.append(binascii.hexlify(pointer).decode())
                offset = unpack("!H", pointer)[0] & 0x3fff
                fp = data.tell()
                data.seek(offset)
                parts.append(self.readDNSstr(data)[0])  # recursive
                data.seek(fp)
                break
            else:
                s = data.read(pl)
                realparts += [binascii.hexlify(chr(pl).encode()).decode(), binascii.hexlify(s).decode()]
                parts.append(s.decode())
            pl = ord(data.read(1))
        if not pl:
            realparts.append('00')
        return ".".join(parts), realparts
    
    def alterIdna(self, s):
        s2 = s.encode().decode('idna')
        return s if s == s2 else " / ".join([s, s2])
    

class DNSMessage(DNS):
    def __init__(self, data):
        self.name, self.namep = self.readDNSstr(data)
        self.type, self.qclass, self.ttl, self.rdlength = unpack('!HHLH', data.read(10))
        self.type_str = self.get_query_type(self.type)
        self.rdatap = data.tell()
        self.rdata = data.read(self.rdlength)
        data.seek(self.rdatap)

        if self.type_str == "A":
            self.rdata2 = unpack('!4s', data.read(4))[0]
        elif self.type_str == "PTR":
            self.PTRDName = self.readDNSstr(data)[0]
        elif self.type_str == "SOA":
            self.MName = self.readDNSstr(data)[0]
            self.RName = self.readDNSstr(data)[0]
            self.Serial, self.Refresh, self.Retry, self.Expire, self.Minimum = unpack('!LLLLL', data.read(20))
        elif self.type_str == "CNAME":
            self.CName = self.readDNSstr(data)[0]
        elif self.type_str == "NS":
            self.NSDName = self.readDNSstr(data)[0]
        elif self.type_str == "MX":
            self.Preference = unpack('!H', data.read(2))[0]
            self.Exchange = self.readDNSstr(data)[0]
        elif self.type_str == "AAAA":
            self.rdata2 = unpack('!16s', data.read(16))[0]
        else:
            data.read(self.rdlength)

    def dump(self):
        print_section_header("Message", 0)
        print("NAME : %s" % (self.alterIdna(self.name)))
        print("TYPE : 0x%04x" % self.type, "(%s)" % self.type_str)
        print("CLASS : 0x%04x" % self.qclass, "(%s)" % self.get_query_class(self.qclass))
        print("TTL : {0:d} sec".format(self.ttl))
        print("RDLENGTH : {0:d} byte(s)".format(self.rdlength))
        print("RDATA : ", get_hex_data(self.rdata), end=' ')

        if self.type_str == "A":
            print("(IP %s)" % ".".join([str(b) for b in self.rdata2]))
        elif self.type_str == "PTR":
            print("(PTRDName=%s)" % self.PTRDName)
        elif self.type_str == "SOA":
            print("(MName=%s, RName=%s, Serial=0x%08x, Refresh=%ds, Retry=%ds, "
                  "Expire=%ds, Minimum=%ds)" % (self.MName, self.RName.replace(".", "@", 1),
                                                self.Serial, self.Refresh, self.Retry, self.Expire,
                                                self.Minimum))
        elif self.type_str == "CNAME":
            print("(CName=%s)" % self.CName)
        elif self.type_str == "NS":
            print("(NSDName=%s)" % self.NSDName)
        elif self.type_str == "MX":
            print("(Preference=%d, Exchange=%s)" % (self.Preference, self.Exchange))
        elif self.type_str == "AAAA":
            print("(IPv6 %s)" % get_IPv6_addr(self.rdata2))
        else:
            print('')

    def get_json(self):
        values = {'name': self.name, 'type': self.type_str, 'qclass': self.qclass, 'ttl': self.ttl}

        if self.type_str == "A":
            values['rdata2'] = self.rdata2
        elif self.type_str == "PTR":
            values['PTRDName'] = self.PTRDName
        elif self.type_str == "SOA":
            values['MName'] = self.MName
            values['RName'] = self.RName
            values['Serial'] = self.Serial
            values['Refresh'] = self.Refresh
            values['Retry'] = self.Retry
            values['Expire'] = self.Expire
            values['Minimum'] = self.Minimum
        elif self.type_str == "CNAME":
            values['CName'] = self.CName
        elif self.type_str == "NS":
            values['NSDName'] = self.NSDName
        elif self.type_str == "MX":
            values['Preference'] = self.Preference
            values['Exchange'] = self.Exchange
        elif self.type_str == "AAAA":
            values['rdata2'] = self.rdata2
        
        return values

    def get_info(self):
        return " {} {}".format(self.type_str, self.name)


class DNSData(ApplicationData, DNS):
    def __init__(self, payload):
        self.type = "DNS"
        data = BytesIO(payload)
        
        hdr_unpacked = unpack("!HHHHHH", data.read(12))
        
        self.identifier = hdr_unpacked[0]
        self.flag = hdr_unpacked[1]
        self.quest_num = hdr_unpacked[2]
        self.answer_num = hdr_unpacked[3]
        self.author_num = hdr_unpacked[4]
        self.addition_num = hdr_unpacked[5]
        
        self.QR, self.OPCODE, self.AA, self.TC, self.RD, self.RA, self.Z, self.RCODE = self.parseHeaderFlagField(self.flag)
        
        self.query_name, self.qnamep = self.readDNSstr(data)
        self.query_type, self.query_class = unpack('!HH', data.read(4))
        
        self.answer_list = []
        for _ in range(self.answer_num + self.author_num + self.addition_num):
            self.answer_list.append(DNSMessage(data))

    def dump(self):
        print_section_header("DNS HEADER", 1)

        print("Identifier : 0x{0:04x}".format(self.identifier))
        print("Flags: 0x%04x" % self.flag, "(QR="+self.QR, "OPCODE="+self.OPCODE, "AA="+self.AA, "TC="+self.TC, "RD="+self.RD, "RA="+self.RA, "Z="+self.Z, "RCODE="+self.RCODE+")")
        print("Number of Question Records : {}".format(self.quest_num))
        print("Number of Answer Records : {}".format(self.answer_num))
        print("Number of Authoritative Records : {}".format(self.author_num))
        print("Number of Additional Records : {}".format(self.addition_num))
        print("Query Name : {}".format(self.query_name))
        print("Query Type : 0x{0:04x} ({1})".format(self.query_type, self.get_query_type(self.query_type)))
        print("Query Class : 0x{0:04x} ({1})".format(self.query_class, self.get_query_class(self.query_class)))
        
        for i in range(len(self.answer_list)):
            self.answer_list[i].dump()
        
        print_section_footer(1)

    def get_json(self):
        answer_json_list = []
        for answer in self.answer_list:
            answer_json_list.append(answer.get_json())
        return {'type': self.type, 'identifier': self.identifier, 'flag': self.flag, 'quest_num': self.quest_num,
                'answer_num': self.answer_num, 'author_num': self.author_num, 'addition_num': self.addition_num, 'QR': self.QR,
                'OPCODE': self.OPCODE, 'AA': self.AA, 'TC': self.TC, 'RD': self.RD,
                'RA': self.RA, 'Z': self.Z, 'RCODE': self.RCODE, 'query_name': self.query_name,
                'query_type': self.query_type, 'query_class': self.query_class, 'answers': answer_json_list}

    def get_info(self):
        res = "0x{0:04x}".format(self.identifier)
        for answer in self.answer_list:
            res = res + answer.get_info()
        return res
    
    def parseHeaderFlagField(self, flags):
        QR = str(flags >> 15)
        OPCODE = str(flags >> 11 & 0b1111).rjust(4, '0')
        AA = str(flags >> 10 & 1)
        TC = str(flags >> 9 & 1)
        RD = str(flags >> 8 & 1)
        RA = str(flags >> 7 & 1)
        Z = str(flags >> 4 & 0b111).rjust(3, '0')
        RCODE = str(flags & 0b1111).rjust(4, '0')
        return QR, OPCODE, AA, TC, RD, RA, Z, RCODE


class HTTPData(ApplicationData):
    def __init__(self, payload):
        self.type = "HTTP"
        self.payload_raw = payload
        self.payload = payload.decode('ascii')

        headers, body = self.payload.split('\r\n\r\n')
        headers = headers.split('\r\n')
        start_line = headers.pop(0).split(' ')

        self.result = {'type': self.type}
        if start_line[0] in ['POST', 'GET', 'HEAD', 'PUT', 'DELETE']:
            self.result['request'], self.result['headers'] = {}, {}
            self.result['request']['method'], self.result['request']['url'], self.result['request']['version'] = start_line
            for line in headers:
                line = line.split(': ')
                self.result['headers'][line[0]] = line[1]
            self.result['body'] = body
            self.protocol = self.result['request']['version']
        elif start_line[0] in ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']:
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

    def get_json(self):
        return self.result

    def get_info(self):
        if 'request' in self.result.keys():
            return "{} {} {}".format(self.result['request']['method'], self.result['request']['url'], self.result['request']['version'])
        elif 'response' in self.result.keys():
            return "{} {} {}".format(self.result['response']['protocol'], self.result['response']['state_code'], self.result['response']['state_line'])


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

    def get_json(self):
        res = {"raw_data": self.raw_data, "length": len(self.raw_data), "protocol": "None"}
        if self.datalink_header:
            res['datalink_header'] = self.datalink_header.get_json()
            res['protocol'] = res['datalink_header']['type']
        if self.network_header:
            res['network_header'] = self.network_header.get_json()
            res['protocol'] = res['network_header']['type']
        if self.transport_header:
            res['transport_header'] = self.transport_header.get_json()
            res['protocol'] = res['transport_header']['type']
        if self.application_data:
            res['application_data'] = self.application_data.get_json()
            res['protocol'] = res['application_data']['type']
        return res

    def get_info(self):
        res = ""
        if self.datalink_header:
            res = self.datalink_header.get_info()
        if self.network_header:
            res = self.network_header.get_info()
        if self.transport_header:
            res = self.transport_header.get_info()
        if self.application_data:
            res = self.application_data.get_info()
        return res

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
            elif (self.transport_header.src_port in [53] or self.transport_header.dst_port in [53]):
                return DNSData(data)
        return None

