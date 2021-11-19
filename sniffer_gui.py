import sys
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from sniffer_core import *
import time
from argparse import ArgumentParser


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

    def run(self):
        while self.running:# and self.packet_num<self.cnt:
            raw_data, addr = self.sniffer.recvfrom(65565)
            packet = Packet(raw_data)
            if packet.is_filtered(self.opts):
                self.table.add_packet({"no": self.packet_num, "time": time.time(), "time_since": (time.time() - self.time_start), "packet": packet})
                self.packet_num = self.packet_num + 1

    def resume(self):
        self.running = True

    def pause(self):
        self.running = False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.args = argparser()
        self.sniffer = Sniffer(self.packet_list, self.args)

    def initUI(self):
        self.setWindowTitle('My First Application')

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
        self.filter_line = QLineEdit()

        layout = QVBoxLayout()

        self.packet_list = PacketList(self)
        self.packet_browser = PacketBrowser(self)
        layout.addWidget(self.filter_line)
        layout.addWidget(self.packet_list)
        layout.addWidget(self.packet_browser)

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
    
    def add_packet(self, data):
        self.packet_list.append(data)
        packet = data['packet']
        packet_json = packet.get_json()
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        self.tableWidget.setItem(row, 0, QTableWidgetItem(str(data['no'])))
        self.tableWidget.setItem(row, 1, QTableWidgetItem(("%.5f" % data['time_since'])))
        self.tableWidget.setItem(row, 2, QTableWidgetItem(str(packet_json['network_header']['src_ip'])))
        self.tableWidget.setItem(row, 3, QTableWidgetItem(str(packet_json['network_header']['dst_ip'])))
        self.tableWidget.setItem(row, 4, QTableWidgetItem(str(packet_json['protocol'])))
        self.tableWidget.setItem(row, 5, QTableWidgetItem(str(packet_json['length'])))
        self.tableWidget.setItem(row, 6, QTableWidgetItem(packet.get_info()))


class PacketBrowser(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.initUI()
        self.main_window = main_window

    def initUI(self):
        self.browser = QTextBrowser()
        self.browser.setAcceptRichText(True)
        self.browser.setOpenExternalLinks(True)

        vbox = QVBoxLayout()
        vbox.addWidget(self.browser, 1)
        self.setLayout(vbox)

        self.show()
    
    def print_packet(self, packet):
        packet_json = packet['packet'].get_json()

        #res = "<html><details> {} {} </details></html>".format("<summary>more details</summary>", "<p>here is detail texts</p>")
        self.browser.clear()
        if 'datalink_header' in packet_json.keys():
            res = self.print_json(packet_json['datalink_header'])
            self.browser.append(res)
        if 'network_header' in packet_json.keys():
            self.browser.append("{:=^78}".format(""))
            res = self.print_json(packet_json['network_header'])
            self.browser.append(res)
        if 'transport_header' in packet_json.keys():
            self.browser.append("{:=^78}".format(""))
            res = self.print_json(packet_json['transport_header'])
            self.browser.append(res)
        if 'application_data' in packet_json.keys():
            self.browser.append("{:=^78}".format(""))
            res = self.print_json(packet_json['application_data'])
            self.browser.append(res)

    def print_json(self, ori):
        res = ""
        for i in ori:
            res = res + "{}: {}\n".format(str(i), str(ori[i]))
        return res


if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MainWindow()
   sys.exit(app.exec_())
