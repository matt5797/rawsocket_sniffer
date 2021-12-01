import sys
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from sniffer_core import *
import time
from argparse import ArgumentParser
import json
import re
import os


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


def get_hex_dump(buffer, start_offset=0):
    offset = 0
    res = ""
    while offset < len(buffer):
        # Offset
        row1 = ' %04X : ' % (offset + start_offset)
        if ((len(buffer) - offset) < 0x10) is True:
            data = buffer[offset:]
        else:
            data = buffer[offset:offset + 0x10]
 
        # Hex Dump
        row2 = ""
        for hex_dump in data:
            row2 = row2 + "%02X" % hex_dump + ' '
        if ((len(buffer) - offset) < 0x10) is True:
            row2 = row2 + ' ' * (3 * (0x10 - len(data)))
 
        # Ascii
        row3 = ""
        for ascii_dump in data:
            if ((ascii_dump >= 0x20) is True) and ((ascii_dump <= 0x7E) is True):
                row3 = row3 + chr(ascii_dump)
            else:
                row3 = row3 + '.'
        offset = offset + len(data)

        res = res + "{:<10} {:<70} {}\n".format(row1, row2, row3)
    return res


class QCustomTableWidgetItem(QTableWidgetItem):
    def __init__ (self, value):
        super(QCustomTableWidgetItem, self).__init__(('%s' % value))

    def __lt__ (self, other):
        if (isinstance(other, QCustomTableWidgetItem)):
            selfDataValue  = float(self.data(Qt.EditRole))
            otherDataValue = float(other.data(Qt.EditRole))
            return selfDataValue < otherDataValue
        else:
            return QTableWidgetItem.__lt__(self, other)


class Sniffer(QThread):
    def __init__(self, table):
        super(Sniffer, self).__init__()
        self.running = True
        self.table = table
        self.host = gethostbyname(gethostname())
        if os.name == 'nt':
            addr_family = AF_INET
            socket_protocol = IPPROTO_IP
        else:
            addr_family = AF_PACKET
            socket_protocol = ntohs(0x0003)
        self.sniffer = socket(addr_family, SOCK_RAW, socket_protocol)
        if os.name == 'nt':
            self.sniffer.bind((self.host, 0))
            self.sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            self.sniffer.ioctl(SIO_RCVALL, RCVALL_ON)
        self.packet_num = 0
        self.time_start = time.time()
        self.filter = {
            "eth": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "ip": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "tcp": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "udp": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "protocol": {"necessary": [], "except": []},
        }

    def run(self):
        while self.running:
            raw_data, addr = self.sniffer.recvfrom(65565)
            packet = Packet(raw_data)
            #if packet.is_filtered(self.opts):
            if self.is_filtered(packet.get_json()):
                self.table.add_packet({"no": self.packet_num, "time": time.time(), "time_since": (time.time() - self.time_start), "packet": packet.get_json()})
                self.packet_num = self.packet_num + 1

    def resume(self):
        self.running = True

    def pause(self):
        self.running = False

    def reset(self):
        self.pause()
        self.table.clear()
        self.packet_num = 0
        self.filter = {
            "eth": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "ip": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "tcp": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "udp": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "protocol": {"necessary": [], "except": []},
        }

    def filter_change(self, filter_str):
        self.reset()
        
        regex = """(?P<pre>and|or)*\s*((?P<opts>((?P<pro_name>eth|ip|tcp|udp).(?P<pro_tar>\w+))\s*(?P<opr>==|!=)\s*(?P<target>(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|(?:[a-zA-Z0-9]{2}[:-]){5}[a-zA-Z0-9]{2}|\d+))|((?P<except>!*)(?P<protocol>eth|ip|udp|tcp|icmp|dns|http)))"""

        match_list = re.finditer(regex, filter_str)

        res_list = {}
        for index, match in enumerate(match_list):
            res = match.groupdict()
            res_list[index] = res

            if res['pro_name']:
                if res['pro_name']=='eth':
                    if res['pro_tar'] == 'addr':
                        if res['opr'] == '==':
                            self.filter['eth']['all']['necessary'].append(res['target'])
                        elif res['opr'] == '!=':
                            self.filter['eth']['all']['except'].append(res['target'])
                    elif res['pro_tar'] == 'src':
                        if res['opr'] == '==':
                            self.filter['eth']['src']['necessary'].append(res['target'])
                        elif res['opr'] == '!=':
                            self.filter['eth']['src']['except'].append(res['target'])
                    elif res['pro_tar'] == 'dst':
                        if res['opr'] == '==':
                            self.filter['eth']['dst']['necessary'].append(res['target'])
                        elif res['opr'] == '!=':
                            self.filter['eth']['dst']['except'].append(res['target'])
                    self.filter['protocol']['necessary'].append('eth')
                elif res['pro_name']=='ip':
                    if res['pro_tar'] == 'addr':
                        if res['opr'] == '==':
                            self.filter['ip']['all']['necessary'].append(res['target'])
                        elif res['opr'] == '!=':
                            self.filter['ip']['all']['except'].append(res['target'])
                    elif res['pro_tar'] == 'src':
                        if res['opr'] == '==':
                            self.filter['ip']['src']['necessary'].append(res['target'])
                        elif res['opr'] == '!=':
                            self.filter['ip']['src']['except'].append(res['target'])
                    elif res['pro_tar'] == 'dst':
                        if res['opr'] == '==':
                            self.filter['ip']['dst']['necessary'].append(res['target'])
                        elif res['opr'] == '!=':
                            self.filter['ip']['dst']['except'].append(res['target'])
                    self.filter['protocol']['necessary'].append('ip')
                elif res['pro_name']=='tcp':
                    if res['pro_tar'] == 'port':
                        if res['opr'] == '==':
                            self.filter['tcp']['all']['necessary'].append(int(res['target']))
                        elif res['opr'] == '!=':
                            self.filter['tcp']['all']['except'].append(int(res['target']))
                    elif res['pro_tar'] == 'srcport':
                        if res['opr'] == '==':
                            self.filter['tcp']['src']['necessary'].append(int(res['target']))
                        elif res['opr'] == '!=':
                            self.filter['tcp']['src']['except'].append(int(res['target']))
                    elif res['pro_tar'] == 'dstport':
                        if res['opr'] == '==':
                            self.filter['tcp']['dst']['necessary'].append(int(res['target']))
                        elif res['opr'] == '!=':
                            self.filter['tcp']['dst']['except'].append(int(res['target']))
                    self.filter['protocol']['necessary'].append('tcp')
                elif res['pro_name']=='udp':
                    if res['pro_tar'] == 'port':
                        if res['opr'] == '==':
                            self.filter['udp']['all']['necessary'].append(int(res['target']))
                        elif res['opr'] == '!=':
                            self.filter['udp']['all']['except'].append(int(res['target']))
                    elif res['pro_tar'] == 'srcport':
                        if res['opr'] == '==':
                            self.filter['udp']['src']['necessary'].append(int(res['target']))
                        elif res['opr'] == '!=':
                            self.filter['udp']['src']['except'].append(int(res['target']))
                    elif res['pro_tar'] == 'dstport':
                        if res['opr'] == '==':
                            self.filter['udp']['dst']['necessary'].append(int(res['target']))
                        elif res['opr'] == '!=':
                            self.filter['udp']['dst']['except'].append(int(res['target']))
                    self.filter['protocol']['necessary'].append('udp')
            elif res['protocol']:
                if res['protocol']=='eth':
                    if res['except']:
                        self.filter['protocol']['except'].append('eth')
                    else:
                        self.filter['protocol']['necessary'].append('eth')
                elif res['protocol']=='ip':
                    if res['except']:
                        self.filter['protocol']['except'].append('ip')
                    else:
                        self.filter['protocol']['necessary'].append('ip')
                elif res['protocol']=='tcp':
                    if res['except']:
                        self.filter['protocol']['except'].append('tcp')
                    else:
                        self.filter['protocol']['necessary'].append('tcp')
                elif res['protocol']=='udp':
                    if res['except']:
                        self.filter['protocol']['except'].append('udp')
                    else:
                        self.filter['protocol']['necessary'].append('udp')
        self.resume()

    def is_filtered(self, packet):
        if 'datalink_header' in packet.keys() and packet['datalink_header']['type'] == 'Ethernet':
            if 'eth' in self.filter['protocol']['except']:
                return False
            if packet['datalink_header']['src_mac'] in self.filter['eth']['src']['except']:
                return False
            if (len(self.filter['eth']['src']['necessary'])>0) and packet['datalink_header']['src_mac'] not in self.filter['eth']['src']['necessary']:
                return False
            if packet['datalink_header']['dst_mac'] in self.filter['eth']['dst']['except']:
                return False
            if (len(self.filter['eth']['dst']['necessary'])>0) and packet['datalink_header']['dst_mac'] not in self.filter['eth']['dst']['necessary']:
                return False
            if (packet['datalink_header']['src_mac'] in self.filter['eth']['all']['except']) or (packet['datalink_header']['dst_mac'] in self.filter['eth']['all']['except']):
                return False
            if (len(self.filter['eth']['all']['necessary'])>0) and ((packet['datalink_header']['src_mac'] not in self.filter['eth']['all']['necessary']) and (packet['datalink_header']['dst_mac'] not in self.filter['eth']['all']['necessary'])):
                return False
        elif 'eth' in self.filter['protocol']['necessary']:
            return False
        if 'network_header' in packet.keys() and packet['network_header']['type'] == 'IPv4':
            if 'ip' in self.filter['protocol']['except']:
                return False
            if packet['network_header']['src_ip'] in self.filter['ip']['src']['except']:
                return False
            if (len(self.filter['ip']['src']['necessary'])>0) and packet['network_header']['src_ip'] not in self.filter['ip']['src']['necessary']:
                return False
            if packet['network_header']['dst_ip'] in self.filter['ip']['dst']['except']:
                return False
            if (len(self.filter['ip']['dst']['necessary'])>0) and packet['network_header']['dst_ip'] not in self.filter['ip']['dst']['necessary']:
                return False
            if (packet['network_header']['src_ip'] in self.filter['ip']['all']['except']) or (packet['network_header']['dst_ip'] in self.filter['ip']['all']['except']):
                return False
            if (len(self.filter['ip']['all']['necessary'])>0) and ((packet['network_header']['src_ip'] not in self.filter['ip']['all']['necessary']) and (packet['network_header']['dst_ip'] not in self.filter['ip']['all']['necessary'])):
                return False
        elif 'ip' in self.filter['protocol']['necessary']:
            return False
        if 'transport_header' in packet.keys() and packet['transport_header']['type'] == 'TCP':
            if 'tcp' in self.filter['protocol']['except']:
                return False
            if packet['transport_header']['src_port'] in self.filter['tcp']['src']['except']:
                return False
            if (len(self.filter['tcp']['src']['necessary'])>0) and packet['transport_header']['src_port'] not in self.filter['tcp']['src']['necessary']:
                return False
            if packet['transport_header']['dst_port'] in self.filter['tcp']['dst']['except']:
                return False
            if (len(self.filter['tcp']['dst']['necessary'])>0) and packet['transport_header']['dst_port'] not in self.filter['tcp']['dst']['necessary']:
                return False
            if (packet['transport_header']['src_port'] in self.filter['tcp']['all']['except']) or (packet['transport_header']['dst_port'] in self.filter['tcp']['all']['except']):
                return False
            if (len(self.filter['tcp']['all']['necessary'])>0) and ((packet['transport_header']['src_port'] not in self.filter['tcp']['all']['necessary']) and (packet['transport_header']['dst_port'] not in self.filter['tcp']['all']['necessary'])):
                return False
        elif 'tcp' in self.filter['protocol']['necessary']:
            return False
        if 'transport_header' in packet.keys() and packet['transport_header']['type'] == 'UDP':
            if 'udp' in self.filter['protocol']['except']:
                return False
            if packet['transport_header']['src_port'] in self.filter['udp']['src']['except']:
                return False
            if (len(self.filter['udp']['src']['necessary'])>0) and packet['transport_header']['src_port'] not in self.filter['udp']['src']['necessary']:
                return False
            if packet['transport_header']['dst_port'] in self.filter['udp']['dst']['except']:
                return False
            if (len(self.filter['udp']['dst']['necessary'])>0) and packet['transport_header']['dst_port'] not in self.filter['udp']['dst']['necessary']:
                return False
            if (packet['transport_header']['src_port'] in self.filter['udp']['all']['except']) or (packet['transport_header']['dst_port'] in self.filter['udp']['all']['except']):
                return False
            if (len(self.filter['udp']['all']['necessary'])>0) and ((packet['transport_header']['src_port'] not in self.filter['udp']['all']['necessary']) and (packet['transport_header']['dst_port'] not in self.filter['udp']['all']['necessary'])):
                return False
        elif 'udp' in self.filter['protocol']['necessary']:
            return False
        return True


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.sniffer = Sniffer(self.packet_list)

    def initUI(self):
        self.setWindowTitle('Sniffing program')

        #actions
        startAction = QAction(QIcon('res/start.png'), 'Start', self)
        startAction.setShortcut('Ctrl+E')
        startAction.setStatusTip('Start sniffing')
        startAction.triggered.connect(self.sniffing_start)

        exitAction = QAction(QIcon('res/quit.png'), 'Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(qApp.quit)

        saveAction = QAction(QIcon('res/save.png'), 'Save', self)
        saveAction.setShortcut('Ctrl+S')
        saveAction.setStatusTip('save log')
        saveAction.triggered.connect(self.packet_save)

        loadAction = QAction(QIcon('res/load.jfif'), 'Load', self)
        loadAction.setShortcut('Ctrl+L')
        loadAction.setStatusTip('load log')
        loadAction.triggered.connect(self.packet_load)

        stopAction = QAction(QIcon('res/stop.png'), 'Stop', self)
        stopAction.setShortcut('Ctrl+P')
        stopAction.setStatusTip('Stop sniffing')
        stopAction.triggered.connect(self.sniffing_stop)

        self.statusBar()

        #menu bar
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)
        filemenu = menubar.addMenu('&File')
        filemenu.addAction(saveAction)
        filemenu.addAction(loadAction)
        filemenu.addAction(exitAction)

        capturemenu = menubar.addMenu('&Capture')
        capturemenu.addAction(startAction)
        capturemenu.addAction(stopAction)

        #tool bar
        self.toolbar = self.addToolBar('Exit')
        self.toolbar.addAction(startAction)
        self.toolbar.addAction(stopAction)
        self.toolbar.addAction(saveAction)
        self.toolbar.addAction(loadAction)
        self.toolbar.addAction(exitAction)

        #filter line
        self.filter_str = QLineEdit()
        self.filter_btn = QPushButton(self)
        self.filter_btn.setText('apply')
        self.filter_btn.clicked.connect(self.filter_btn_clicked)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(self.filter_str)
        filter_layout.addWidget(self.filter_btn)

        filter_widget = QWidget()
        filter_widget.setLayout(filter_layout)

        self.packet_list = PacketList(self)
        self.packet_browser = PacketBrowser(self)
        self.packet_bytes = PacketBytes(self)

        layout = QVBoxLayout()
        layout.addWidget(filter_widget)
        layout.addWidget(self.packet_list)
        layout.addWidget(self.packet_browser)
        layout.addWidget(self.packet_bytes)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        self.setGeometry(500, 500, 1000, 800)
        self.show()

    def sniffing_start(self):
        if self.sniffer.running:
            self.sniffer.start()
        elif not self.sniffer.running:
            self.sniffer.packet_num = len(self.packet_list.packet_list)
            self.sniffer.resume()
            self.sniffer.start()

    def sniffing_stop(self):
        if self.sniffer.running:
            self.sniffer.pause()

    def packet_save(self):
        with open("logs/log.json", "w") as json_file:
            json.dump(self.packet_list.packet_list, json_file)
            
    def packet_load(self):
        self.sniffer.reset()
        with open("logs/log.json", "r") as json_file:
            packet_list = json.load(json_file)
        for packet in packet_list:
            self.packet_list.add_packet(packet)
    
    def filter_btn_clicked(self):
        self.sniffer.filter_change(self.filter_str.text())


class PacketList(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.initUI()
        self.packet_list = []
        self.main_window = main_window
        self.order = [0, True]

    def initUI(self):
        self.tableWidget = QTableWidget(0, 7,
            selectionBehavior=QAbstractItemView.SelectRows,
            selectionMode=QAbstractItemView.SingleSelection,
        )
        self.tableWidget.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tableWidget.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tableWidget.verticalHeader().hide()

        self.tableWidget.cellClicked.connect(self.cell_clicked)
        self.tableWidget.horizontalHeader().sectionClicked.connect(self.onHeaderClicked)

        layout = QVBoxLayout()
        layout.addWidget(self.tableWidget)
        self.setLayout(layout)

    @pyqtSlot(int, int)
    def cell_clicked(self, row, col):
        num = int(self.tableWidget.item(row, 0).text())
        self.main_window.packet_browser.print_packet(self.packet_list[num])
        self.main_window.packet_bytes.print_packet(self.packet_list[num])
    
    def onHeaderClicked(self, col):
        if self.order[0]==col:
            self.order[1] = not self.order[1]
            self.tableWidget.sortItems(col, self.order[1])
        else:
            self.order[0]=col
            self.order[1]=True
            self.tableWidget.sortItems(col, self.order[1])
    
    def add_packet(self, data):
        self.packet_list.append(data)
        packet_json = data['packet']
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        self.tableWidget.setItem(row, 0, QCustomTableWidgetItem(int(data['no'])))
        self.tableWidget.setItem(row, 1, QCustomTableWidgetItem(float(("%.5f" % data['time_since']))))
        self.tableWidget.setItem(row, 2, QTableWidgetItem(str(packet_json['network_header']['src_ip'])))
        self.tableWidget.setItem(row, 3, QTableWidgetItem(str(packet_json['network_header']['dst_ip'])))
        self.tableWidget.setItem(row, 4, QTableWidgetItem(str(packet_json['protocol'])))
        self.tableWidget.setItem(row, 5, QCustomTableWidgetItem((int(packet_json['length']))))
        self.tableWidget.setItem(row, 6, QTableWidgetItem(packet_json['info']))
        self.tableWidget.resizeColumnsToContents()

    def resize(self):
        header = self.tableWidget.horizontalHeader()
        twidth = header.width()
        rows = []
        width = []
        for column in range(header.count()):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
            width.append(header.sectionSize(column))

        wfactor = twidth / sum(width)
        for column in rows:
            header.setSectionResizeMode(column, QHeaderView.Interactive)
            header.resizeSection(column, width[column]*wfactor)
    
    def clear(self):
        self.packet_list = []
        self.tableWidget.setRowCount(0)


class PacketBrowser(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.initUI()
        self.main_window = main_window

    def initUI(self):
        self.browser = QTextBrowser()
        self.browser.setAcceptRichText(True)

        vbox = QVBoxLayout()
        vbox.addWidget(self.browser, 1)
        self.setLayout(vbox)
    
    def print_packet(self, packet):
        packet_json = packet['packet']
        self.browser.clear()
        if 'datalink_header' in packet_json.keys():
            res = "<b> {} / {} </b>".format(packet_json['datalink_header']['type'], packet_json['datalink_header']['info'])
            self.browser.append(res)
            res = self.print_json(packet_json['datalink_header'])
            self.browser.append(res)
        if 'network_header' in packet_json.keys():
            self.browser.append("{:=^78}".format(""))
            res = "<b> {} / {} </b>".format(packet_json['network_header']['type'], packet_json['network_header']['info'])
            self.browser.append(res)
            res = self.print_json(packet_json['network_header'])
            self.browser.append(res)
        if 'transport_header' in packet_json.keys():
            self.browser.append("{:=^78}".format(""))
            res = "<b> {} / {} </b>".format(packet_json['transport_header']['type'], packet_json['transport_header']['info'])
            self.browser.append(res)
            res = self.print_json(packet_json['transport_header'])
            self.browser.append(res)
        if 'application_data' in packet_json.keys():
            self.browser.append("{:=^78}".format(""))
            res = "<b> {} / {} </b>".format(packet_json['application_data']['type'], packet_json['application_data']['info'])
            self.browser.append(res)
            res = self.print_json(packet_json['application_data'])
            self.browser.append(res)

    def print_json(self, ori):
        res = ""
        for i in ori:
            res = res + "{}: {}\n".format(str(i), str(ori[i]))
        return res


class PacketBytes(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.initUI()
        self.main_window = main_window

    def initUI(self):
        self.browser = QTextBrowser()
        self.browser.setAcceptRichText(True)

        vbox = QVBoxLayout()
        vbox.addWidget(self.browser, 1)
        self.setLayout(vbox)
    
    def print_packet(self, packet):
        raw_data = bytes.fromhex(packet['packet']['raw_data'])
        self.browser.clear()
        res = get_hex_dump(raw_data)
        self.browser.append(res)


if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MainWindow()
   sys.exit(app.exec_())
