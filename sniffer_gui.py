import sys
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from sniffer import *
import time


class Sniffer(QThread):
    def __init__(self, table, args):
        super(Sniffer, self).__init__()
        self.table = table
        self.cnt = 100
        self.opts = (args.necessary_proto, args.except_proto, args.sorceport, args.destport, args.display_layer)
        self.sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
        self.packets = []

    def run(self):
        i=0
        while i<self.cnt:
            raw_data, addr = self.sniffer.recvfrom(65565)
            packet = Packet(raw_data)
            if packet.is_filtered(self.opts):
                self.packets.append(packet)
                self.table.add_packet(packet)
                i = i + 1


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.args = argparser()

    def initUI(self):
        self.setWindowTitle('My First Application')

        #menu bar
        startAction = QAction(QIcon('res/start.png'), 'Exit', self)
        startAction.setShortcut('Ctrl+P')
        startAction.setStatusTip('Start sniffing')
        startAction.triggered.connect(self.sniffing)

        exitAction = QAction(QIcon('res/quit.png'), 'Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(qApp.quit)

        saveAction = QAction(QIcon('res/save.png'), 'Save', self)
        saveAction.setShortcut('Ctrl+S')
        saveAction.setStatusTip('save log')
        #saveAction.triggered.connect(qApp.quit)

        self.statusBar()

        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)
        filemenu = menubar.addMenu('&File')
        filemenu.addAction(startAction)
        filemenu.addAction(exitAction)
        filemenu.addAction(saveAction)

        #tool bar
        self.toolbar = self.addToolBar('Exit')
        self.toolbar.addAction(startAction)
        self.toolbar.addAction(exitAction)
        self.toolbar.addAction(saveAction)

        layout = QVBoxLayout()

        self.packet_list = PacketList()
        layout.addWidget(self.packet_list)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        self.setGeometry(500, 500, 1000, 600)
        self.show()

    def sniffing(self):
        self.sniffer = Sniffer(self.packet_list, self.args)
        self.sniffer.start()


class PacketList(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.tableWidget = QTableWidget()
        #self.tableWidget.setRowCount(20)
        self.tableWidget.setColumnCount(7)

        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        #for i in range(20):
        #    for j in range(4):
        #        self.tableWidget.setItem(i, j, QTableWidgetItem(str(i+j)))

        layout = QVBoxLayout()
        layout.addWidget(self.tableWidget)
        self.setLayout(layout)
    
    def add_packet(self, packet):
        packet_json = packet.get_json()
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        if 'datalink_header' in packet_json.keys():
            self.tableWidget.setItem(row, 0, QTableWidgetItem(str(packet_json['datalink_header'])))
        if 'network_header' in packet_json.keys():
            self.tableWidget.setItem(row, 1, QTableWidgetItem(str(packet_json['network_header'])))
        if 'transport_header' in packet_json.keys():
            self.tableWidget.setItem(row, 2, QTableWidgetItem(str(packet_json['transport_header'])))
        if 'application_data' in packet_json.keys():
            self.tableWidget.setItem(row, 3, QTableWidgetItem(str(packet_json['application_data'])))


if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MyApp()
   sys.exit(app.exec_())
