import sys
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from sniffer_core import *
import time
from argparse import ArgumentParser
import json
import re


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


class Sniffer(QThread):
    def __init__(self, table, args):
        super(Sniffer, self).__init__()
        self.running = True
        self.table = table
        self.cnt = args.number
        self.opts = (args.necessary_proto, args.except_proto, args.sorceport, args.destport, args.display_layer)
        self.sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
        self.packet_num = 0
        self.time_start = time.time()
        self.filter = {
            "eth": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "ip": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "tcp": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "protocol": [],
        }

    def run(self):
        while self.running:# and self.packet_num<self.cnt:
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
    
    def filter_change(self, filter_str):
        self.pause()
        self.table.clear()
        self.packet_num = 0
        self.filter = {
            "eth": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "ip": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "tcp": {"src": {"necessary": [], "except": []}, "dst": {"necessary": [], "except": []}, "all": {"necessary": [], "except": []}},
            "protocol": [],
        }
        
        regex = """(?P<pre>and|or)*\s*(((?P<protocol>ip|eth|tcp).(?P<pro_tar>\w+))\s*(?P<opr>==|!=)\s*(?P<target>(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|(?:[a-zA-Z0-9]{2}[:-]){5}[a-zA-Z0-9]{2}|\d+))"""

        match_list = re.finditer(regex, filter_str)

        res_list = {}
        for index, match in enumerate(match_list):
            res = match.groupdict()
            res_list[index] = res
            print(match)

            if res['protocol']=='eth':
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
                self.filter['protocol'].append('eth')
            elif res['protocol']=='ip':
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
                self.filter['protocol'].append('ip')
            elif res['protocol']=='tcp':
                if res['pro_tar'] == 'port':
                    if res['opr'] == '==':
                        self.filter['tcp']['all']['necessary'].append(res['target'])
                    elif res['opr'] == '!=':
                        self.filter['tcp']['all']['except'].append(res['target'])
                elif res['pro_tar'] == 'srcport':
                    if res['opr'] == '==':
                        self.filter['tcp']['src']['necessary'].append(res['target'])
                    elif res['opr'] == '!=':
                        self.filter['tcp']['src']['except'].append(res['target'])
                elif res['pro_tar'] == 'dstport':
                    if res['opr'] == '==':
                        self.filter['tcp']['dst']['necessary'].append(res['target'])
                    elif res['opr'] == '!=':
                        self.filter['tcp']['dst']['except'].append(res['target'])
                self.filter['protocol'].append('tcp')
        print(self.filter)
        self.resume()

    def is_filtered(self, packet):
        if 'datalink_header' in packet.keys() and packet['datalink_header']['type'] == 'Ethernet':
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
            if (len(self.filter['eth']['all']['necessary'])>0) and ((packet['datalink_header']['src_mac'] not in self.filter['eth']['all']['necessary']) or (packet['datalink_header']['dst_mac'] not in self.filter['eth']['all']['necessary'])):
                return False
        elif 'eth' in self.filter['protocol']:
            return False
        if 'network_header' in packet.keys() and packet['network_header']['type'] == 'IPv4':
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
            if (len(self.filter['ip']['all']['necessary'])>0) and ((packet['network_header']['src_ip'] not in self.filter['ip']['all']['necessary']) or (packet['network_header']['dst_ip'] not in self.filter['ip']['all']['necessary'])):
                return False
        elif 'ip' in self.filter['protocol']:
            return False
        if 'transport_header' in packet.keys() and packet['transport_header']['type'] == 'TCP':
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
            if (len(self.filter['tcp']['all']['necessary'])>0) and ((packet['transport_header']['src_port'] not in self.filter['tcp']['all']['necessary']) or (packet['transport_header']['dst_port'] not in self.filter['tcp']['all']['necessary'])):
                return False
        elif 'tcp' in self.filter['protocol']:
            return False
        return True


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.args = argparser()
        self.sniffer = Sniffer(self.packet_list, self.args)

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
        filemenu.addAction(exitAction)

        capturemenu = menubar.addMenu('&Capture')
        capturemenu.addAction(startAction)
        capturemenu.addAction(stopAction)

        #tool bar
        self.toolbar = self.addToolBar('Exit')
        self.toolbar.addAction(startAction)
        self.toolbar.addAction(stopAction)
        self.toolbar.addAction(saveAction)
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
            self.sniffer.resume()
            self.sniffer.start()

    def sniffing_stop(self):
        if self.sniffer.running:
            self.sniffer.pause()

    def packet_save(self):
        pass
        #with open("logs/log.json", "w") as json_file:
        #    json.dump(self.packet_list.packet_list, json_file)
    
    def filter_btn_clicked(self):
        self.sniffer.filter_change(self.filter_str.text())


class PacketList(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.initUI()
        self.packet_list = []
        self.main_window = main_window

    def initUI(self):
        self.tableWidget = QTableWidget(0, 7,
            selectionBehavior=QAbstractItemView.SelectRows,
            selectionMode=QAbstractItemView.SingleSelection,
        )
        self.tableWidget.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tableWidget.verticalHeader().hide()

        self.tableWidget.cellClicked.connect(self.cell_clicked)

        layout = QVBoxLayout()
        layout.addWidget(self.tableWidget)
        self.setLayout(layout)

    @pyqtSlot(int, int)
    def cell_clicked(self, row, col):
        self.main_window.packet_browser.print_packet(self.packet_list[row])
        self.main_window.packet_bytes.print_packet(self.packet_list[row])
    
    def add_packet(self, data):
        self.packet_list.append(data)
        packet_json = data['packet']
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        self.tableWidget.setItem(row, 0, QTableWidgetItem(str(data['no'])))
        self.tableWidget.setItem(row, 1, QTableWidgetItem(("%.5f" % data['time_since'])))
        self.tableWidget.setItem(row, 2, QTableWidgetItem(str(packet_json['network_header']['src_ip'])))
        self.tableWidget.setItem(row, 3, QTableWidgetItem(str(packet_json['network_header']['dst_ip'])))
        self.tableWidget.setItem(row, 4, QTableWidgetItem(str(packet_json['protocol'])))
        self.tableWidget.setItem(row, 5, QTableWidgetItem(str(packet_json['length'])))
        self.tableWidget.setItem(row, 6, QTableWidgetItem(packet_json['info']))
    
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

        #res = "<html><details> {} {} </details></html>".format("<summary>more details</summary>", "<p>here is detail texts</p>")
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
        raw_data = packet['packet']['raw_data']
        self.browser.clear()
        res = get_hex_dump(raw_data)
        self.browser.append(res)


if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MainWindow()
   sys.exit(app.exec_())
