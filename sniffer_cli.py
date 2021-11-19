from sniffer_core import *
from argparse import ArgumentParser


class Sniffer():
    def __init__(self):
        self.hostname = gethostname()
        self.host = gethostbyname(self.hostname)
        self.sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
        self.packets = []

    def sniffing(self, opts, cnt, summary=False, silence=False):
        i = 0
        while i<cnt:
            raw_data, addr = self.sniffer.recvfrom(65565)
            packet = Packet(raw_data)
            if packet.is_filtered(opts):
                self.packets.append(packet)
                if not summary and not silence:
                    if opts[-1]:
                        packet.dump(i, opts[-1])
                    else:
                        packet.dump(i)
                elif summary and not silence:
                    packet.dump_summary(i)
                i = i + 1

    def main(self, args):
        print(self.hostname)
        print('start sniffing {0}'.format(self.host))
        print('options: ', args)
        self.sniffing((args.necessary_proto, args.except_proto, args.sorceport, args.destport, args.display_layer), args.number, args.summary, args.silence)


def argparser():
    parser = ArgumentParser()
    parser.add_argument('-s', '--summary', action='store_true', help='summary mode')
    parser.add_argument('-sl', '--silence', action='store_true', help='silence mode')

    parser.add_argument('-n', '--number', type=int, help='packet number', default=1000)
    parser.add_argument('-sp', '--sorceport', action='append', type=int, help='sorce port')
    parser.add_argument('-dp', '--destport', action='append', type=int, help='destination port')

    parser.add_argument('-np', '--necessary_proto', action='append', type=str, help='necessary protocol: [Ethernet, IP, ICMP, TCP, UDP]')
    parser.add_argument('-ep', '--except_proto', action='append', type=str, help='except protocol: [Ethernet, IP, ICMP, TCP, UDP]')

    parser.add_argument('-dl', '--display_layer', action='append', type=str, help='display layer: [datalink, network, transport, application]')

    return parser.parse_args()


if __name__ == "__main__":
    args = argparser()
    Sniffer().main(args)

