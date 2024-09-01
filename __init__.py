import os
import pickle
import re, sys
from configparser import ConfigParser

from PyQt4 import QtGui,QtCore

# from PyQt4.QtCore import QString
from PyQt4.QtGui import QApplication, QDialog, QWidget, QMainWindow
from gui import Ui_Dialog, _fromUtf8
import socket,time,sys
from threading import Thread,BoundedSemaphore
class subnet:
    def __init__(self):
        pass
    def get_params(self, network):
        # Get address string and CIDR string from command line
        (addrString, cidrString) = network.split('/')

        # Split address into octets and turn CIDR into int
        addr = addrString.split('.')
        cidr = int(cidrString)
        # Initialize the netmask and calculate based on CIDR mask
        mask = [0, 0, 0, 0]
        for i in range(cidr):
            mask[i/8] = mask[i/8] + (1 << (7 - i % 8))
        # Initialize net and binary and netmask with addr to get network
        net = []
        for i in range(4):
            net.append(int(addr[i]) & mask[i])
        # Duplicate net into broad array, gather host bits, and generate broadcast
        broad = list(net)
        brange = 32 - cidr
        for i in range(brange):
            broad[3 - i/8] = broad[3 - i/8] + (1 << (i % 8))
        netmask =  ".".join(map(str, mask))
        network = ".".join(map(str, net))
        broadcast = ".".join(map(str, broad))
        return network,netmask,broadcast


class Seeker(Ui_Dialog):
    def __init__(self):
        super(Seeker, self).__init__()
        self.estado = ''
        self.main_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.servers = dict()
        self.configfile = ConfigParser()
        self.srvport = 27016
        self.ctrport = 27017
        self.seekport = 27027
        self.timeout = 5
        self.threads = 100
        self.extrainfo = True
        self.lt = list()
        self.pool = list()
        self.semaphore = BoundedSemaphore()
        self.state=False
        self.scanstate=False
        self.proxystate=False
        self.destroystate =False
        self.delay=0.001
        self.ipstart = ''
        self.ipstop = ''
        self.data = '0d020028a91b27f607a479c83291de26990a3312fc10760a3312e08869'#.decode('hex')
        self.progressScan = ''
        self.progreessPercent = 0.0
        path = sys.argv[0].split('/')
        path = path.pop()
        path = sys.argv[0].split(path)
        path.pop()
        self.dir = os.path.abspath(path[0]) + '/'

    def readConfig(self):
        try:
            self.configfile.read(self.dir+'SaDCod.ini')
            self.networks = self.configfile.items('networks')
            self.options = self.configfile.items('global')
            for rango in self.networks:
                self.lt.append(rango[1])
            if self.lt.__len__() == 0:
                self.estadoLabel.setText('<html><head/><body><p><span style=" color:#0000cf;">'
                                         'Sin redes especificadas en SaDCoD.ini, nada para escanear'
                                         '</span></p></body></html>')
        except:
            self.estadoLabel.setText('Archivo de configuracion SaDCod.ini no encontrado o corrupto')
            time.sleep(1.5)
            self.pushButtonScan.setEnabled(False)
            self.pushButtonDestroy.setEnabled(False)
            self.pushButtonConectar.setEnabled(False)
            self.uiTable.setEnabled(False)
        try:
            for opt in self.options:
                if opt[0]== 'timeout':
                    self.timeout = int(opt[1])
                if opt[0]=='extrainfo':
                    if opt[1] == 'no': self.extrainfo = False
                if opt[0]=='retardo':
                    self.delay = float(opt[1])
                if opt[0]=='srvport':
                    self.srvport = int(opt[1])
                if opt[0]=='ctrport':
                    self.ctrport = int(opt[1])
                if opt[0]=='seekport':
                    self.seekport = int(opt[1])
        except:
            pass
    def seek(self):
        self.servers = dict()
        self.estado = ' '
        hilogetip = Thread(target=self.getip)
        hilogetip.setDaemon(1)
        hilogetip.start()
        ipstart = self.ipstart
        ipstop = self.ipstop
        try:
            servers = self.__iprange__(ipstart, ipstop)
        except:
            self.estado= 'Rango de direcciones con error'
            print(self.estado)
            self.pushButtonScan.toggle()
            return
        for server in servers:
            if not self.state:
                return
            # server = str(server)
            try:
                self.progressScan = server
                self.main_socket.sendto(self.data, (server, self.srvport))
            except socket.error:
                pass
            # except:
            #     self.pushButtonScan.toggle()
            #     print server, self.srvport
            #     raise
            time.sleep(self.delay)
        self.scanstate = False
        self.estadoLabel.setText(str('Terminado. Esperando respuestas'))

    def destroy(self):
        import ip
        probe_ip = ip.Packet()
        probe_ip.src = str(self.realserver)
        probe_ip.dst = str(self.realserver)
        probe_ip.p = socket.IPPROTO_UDP
        probe_ip.ttl = 255
        probe_udp = udp.Packet()
        probe_udp.sport = self.srvport
        probe_udp.dport = self.srvport
        probe_udp.data = self.data
        probe_ip.data = udp.assemble(probe_udp,0)
        packet = ip.assemble(probe_ip,0)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        while self.destroystate:
            s.sendto(packet, (self.realserver, 0))
            if self.delay > 0:
                time.sleep(self.delay)

    def getip(self):
        while self.state:
            x,z=self.main_socket.recvfrom(1024)
            if self.servers.has_key(z[0]):continue
            row = self.uiTable.rowCount()
            self.uiTable.insertRow(row)
            item = QtGui.QTableWidgetItem(z[0])
            item.setFlags(QtCore.Qt.ItemIsEnabled|QtCore.Qt.ItemIsSelectable)
            item1 = QtGui.QTableWidgetItem('?')
            item1.setFlags(QtCore.Qt.ItemIsEnabled)
            item1.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
            item2 = QtGui.QTableWidgetItem('?')
            item2.setFlags(QtCore.Qt.ItemIsEnabled)
            item2.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
            item3 = QtGui.QTableWidgetItem('?')
            item3.setFlags(QtCore.Qt.ItemIsEnabled)
            item3.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
            item4 = QtGui.QTableWidgetItem('?')
            item4.setFlags(QtCore.Qt.ItemIsEnabled)
            item4.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
            item5 = QtGui.QTableWidgetItem('?')
            item5.setFlags(QtCore.Qt.ItemIsEnabled)
            item5.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
            self.uiTable.setSortingEnabled(False)
            self.uiTable.setItem(row, 0, item)
            self.uiTable.setItem(row, 1, item1)
            self.uiTable.setItem(row, 2, item2)
            self.uiTable.setItem(row, 3, item3)
            self.uiTable.setItem(row, 4, item4)
            self.uiTable.setItem(row, 5, item5)
            self.uiTable.setSortingEnabled(True)
            self.servers[z[0]] = [item1, item2, item3, item4, item5, []]
            if self.extrainfo:
                hilodetails = Thread(target=self.getipdetails, args=(z[0],))
                hilodetails.setDaemon(1)
                hilodetails.start()
            # print('\rstate', self.state,)
        self.main_socket.close()
    def getipdetails(self, server):
        item1 = self.servers[server][0]
        item2 = self.servers[server][1]
        item3 = self.servers[server][2]
        item4 = self.servers[server][3]
        item5 = self.servers[server][4]
        while self.extrainfo:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto('LOOP.getstatus', (server, self.ctrport))
                s.settimeout(self.timeout / 1.1)
                ss = s.recvfrom(1024)
                data = ss[0]
                hostname = data.split('hostname')[1].split('\\')[1]
                version = data.split('version')[1].split('\\')[1]
                mapname = data.split('mapname')[1].split('\\')[1]
                gametype = data.split('gametype')[1].split('\\')[1]
                maxclients = data.split('maxclients')[1].split('\\')[1]
                self.servers[server][5] = players = data.split('mod')[1].split('\\')[1].split('\n')[1:-1]
                cclient = players.__len__() - 2
                item1.setText(version)
                item2.setText(str(cclient) + '/' + str(maxclients))
                item3.setText(mapname)
                item4.setText(gametype)
                item5.setText(hostname)
                # print 'refreshing', server
                # print self.servers[server][5]
            except socket.timeout:
                item1.setText('v-.-')
                item2.setText('-/-')
                item3.setText('-')
            s.close()
            return (version, hostname, str(cclient) + '/' + str(maxclients))


    def __ip2Int__(self, ip):
        ip = str(ip)
        o = map(int, ip.split('.'))
        res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
        return res
    def __int2ip__(self, ipnum):
        o1 = int(ipnum / 16777216) % 256
        o2 = int(ipnum / 65536) % 256
        o3 = int(ipnum / 256) % 256
        o4 = int(ipnum) % 256
        return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()
    def __iprange__(self, ipstart, ipstop):
        x=list()
        x.append(ipstart)
        ipint = self.__ip2Int__(ipstart)
        ipend = self.__ip2Int__(ipstop)
        if ipend - ipint < 0 :
            raise Exception()
        while(x[-1]!=ipstop):
            x.append(self.__int2ip__(ipint + 1))
            ipint=ipint+1
        return x

    def server(self):
        self.codxyserver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.codxycontrol = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.codxyserver.bind(('', self.srvport))
        # self.codxycontrol.bind(('', self.ctrport))
        self.proxyconexiones = dict()
        while self.proxystate:
            data, client = self.codxyserver.recvfrom(1024)
            if data == '':continue
            if not self.proxyconexiones.has_key(client[0]+str(client[1])):
                self.proxyconexiones[client[0]+str(client[1])] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                hilo = Thread(target=self.sendresponse,args=(client,))
                hilo.setDaemon(1)
                try:
                    hilo.start()
                except:
                    del hilo
            self.proxyconexiones[client[0]+str(client[1])].sendto(data, (self.realserver, self.srvport))
        self.codxyserver.close()
        del self.codxyserver

    def sendresponse(self,client):
        while self.proxystate:
            try:
                self.codxyserver.sendto(self.proxyconexiones[client[0] + str(client[1])].recv(1024), client)
            except:
                self.proxyconexiones.pop(client[0] + str(client[1])).close()
                break

    def updatestatus(self):
        self.scanstate = True
        while self.state and self.scanstate:
            self.estadoLabel.setText(str('Escaneando ' + self.progressScan))
            time.sleep(0.1)
        self.progressScan = ''

class Main(Seeker):
    def seek(self):
        self.uiTable.clearContents()
        self.uiTable.setRowCount(0)
        self.hiloprincipal = Thread(target=super(Main,self).seek)
        self.hiloprincipal.setDaemon(1)
        self.hiloprincipal.start()
        self.hiloprincipal = Thread(target=self.updatestatus)
        self.hiloprincipal.setDaemon(1)
        self.hiloprincipal.start()

    def server(self):
        self.hiloserver = Thread(target=super(Main,self).server)
        self.hiloserver.setDaemon(1)
        self.hiloserver.start()

    def destroy(self):
        self.hilodestroy = Thread(target=super(Main,self).destroy)
        self.hilodestroy.setDaemon(1)
        self.hilodestroy.start()

    def toggleSeek(self):
        self.state = not self.state
        if self.state:
            self.ipstart = self.ipstart_lineEdit.text()
            self.ipstop = self.ipstop_lineEdit.text()
            # print 'iniciando scan'
            self.seek()
            self.pushButtonScan.setText('Parar sondeo')
        else:
            hilo = Thread(target=self.refresh)
            hilo.setDaemon(1)
            hilo.start()
            try:
                self.main_socket.sendto('', ('127.0.0.1', self.seekport))
            except:
                pass
            self.pushButtonScan.setText('Buscar servidores de Call of Duty')
            self.estadoLabel.setText(self.estado)

    def selectserver(self, index):
        self.realserver = str(self.uiTable.item(index.row(), 0).text())
        self.updateplayers(self.realserver)
        # if self.pushButtonConectar.isChecked() and self.pushButtonDestroy.isChecked():return
        # if not self.pushButtonConectar.isChecked():
            # self.pushButtonConectar.setText('Conetctar a '+self.realserver)
            # self.pushButtonConectar.setEnabled(True)
        # if not self.pushButtonDestroy.isChecked():
        #     self.pushButtonDestroy.setText('Destruir '+self.realserver)
        #     self.pushButtonDestroy.setEnabled(True)

    def updateplayers(self, server):
        if self.extrainfo:
            players = self.servers[server][5]
            # print players
            self.uiTable_2.clearContents()
            self.uiTable_2.setRowCount(0)
            regex = re.compile('([0-9]+) ([0-9]+) "(.+)"')
            self.uiTable_2.setSortingEnabled(True)
            for player in players:
                player = regex.match(player).groups()
                # print player
                row = self.uiTable_2.rowCount()
                self.uiTable_2.insertRow(row)
                item1 = QtGui.QTableWidgetItem(player[2])
                item2 = QtGui.QTableWidgetItem(player[0])
                item3 = QtGui.QTableWidgetItem(player[1])
                item1.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                item2.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                item3.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                self.uiTable_2.setItem(row, 0, item1)
                self.uiTable_2.setItem(row, 1, item2)
                self.uiTable_2.setItem(row, 2, item3)

    def readConfig(self, dump=False):
        try:
            if dump:
                with open(self.dir+'sadcod.dat', 'wb') as output:
                    pickle.dump([self.delay, self.timeout, self.srvport,
                                 self.ctrport, self.seekport, self.ipstart,
                                 self.ipstop, self.extrainfo],
                                output)
            else:
                with open(self.dir+'sadcod.dat', 'rb') as input:
                    data = pickle.load(input)
                    self.extrainfo_checkBox.setChecked(data[7])
                    self.ipstop_lineEdit.setText(data[6])
                    self.ipstart_lineEdit.setText(data[5])
                    self.seekport_spinBox.setValue(data[4])
                    self.ctrport_spinBox.setValue(data[3])
                    self.srvport_spinBox.setValue(data[2])
                    self.timeout_spinBox.setValue(data[1])
                    self.delay_doubleSpinBox.setValue(data[0])
        except:
            pass
        finally:
            self.settingsupdate()

    def settingsupdate(self):
        if self.srvport_spinBox.value() == self.seekport_spinBox.value():
            self.seekport_spinBox.stepUp()
        self.extrainfo = self.extrainfo_checkBox.checkState()
        self.timeout = self.timeout_spinBox.value()
        self.srvport = self.srvport_spinBox.value()
        self.ctrport = self.ctrport_spinBox.value()
        self.seekport = self.seekport_spinBox.value()
        self.extrainfo = self.extrainfo_checkBox.isChecked()
        self.delay = self.delay_doubleSpinBox.value()
        self.ipstart = self.ipstart_lineEdit.text()
        self.ipstop = self.ipstop_lineEdit.text()

    def toggleConectar(self):
        self.proxystate = not self.proxystate
        if self.proxystate:
            self.server()
            self.pushButtonConectar.setText('Desconectar de '+self.realserver)
            self.estadoLabel.setText('Poner 127.0.0.1 en el launcher, puerto ' + str(self.srvport))
        else:
            try:
                self.codxyserver.sendto('', ('127.0.0.1', self.srvport))
            finally:
                pass
            self.pushButtonConectar.setText('Conetctar a '+self.realserver+' o selecione servidor')
            self.estadoLabel.setText(' ')

    def connectTo(self, index):
        self.selectserver(index)
        if not self.pushButtonConectar.isChecked():
            self.pushButtonConectar.toggle()

    def toggleDestroy(self):
        self.destroystate = not self.destroystate
        if self.destroystate:
            self.destroy()
            self.pushButtonDestroy.setText('Quitarle el dedo a '+self.realserver)
            self.estadoLabel.setText('Destruyendo ' + self.realserver)
        else:
            self.pushButtonDestroy.setText('Destruir '+self.realserver+' o selecione servidor')
            self.estadoLabel.setText(' ')

    def resetDefaults(self):
        self.srvport_spinBox.setProperty("value", 27016)
        self.seekport_spinBox.setProperty("value", 27000)
        self.ctrport_spinBox.setProperty("value", 27017)
        self.timeout_spinBox.setProperty("value", 5)
        self.delay_doubleSpinBox.setProperty("value", 0.0001)
        self.extrainfo_checkBox.setChecked(True)

    def refresh(self):
        while self.extrainfo:
            time.sleep(self.timeout)
            for server in self.servers.keys():
                time.sleep(0.01)
                # print 'refresh'
                # self.getipdetails(server)
                hilodetails = Thread(target=self.getipdetails, args=(server,))
                hilodetails.setDaemon(1)
                hilodetails.start()
                try: self.updateplayers(self.realserver)
                except: pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QDialog()
    ui = Main()
    ui.setupUi(window)
    ui.readConfig()
    ui.pushButtonScan.toggled.connect(ui.toggleSeek)
    ui.pushButtonReset.clicked.connect(ui.refresh)
    ui.pushButtonReset.clicked.connect(ui.resetDefaults)
    ui.pushButtonConectar.toggled.connect(ui.toggleConectar)
    ui.pushButtonDestroy.toggled.connect(ui.toggleDestroy)
    ui.uiTable.itemClicked.connect(ui.selectserver)
    # ui.uiTable.itemDoubleClicked.connect(ui.connectTo)
    ui.delay_doubleSpinBox.valueChanged.connect(ui.settingsupdate)
    ui.timeout_spinBox.valueChanged.connect(ui.settingsupdate)
    ui.seekport_spinBox.valueChanged.connect(ui.settingsupdate)
    ui.srvport_spinBox.valueChanged.connect(ui.settingsupdate)
    ui.ctrport_spinBox.valueChanged.connect(ui.settingsupdate)
    ui.extrainfo_checkBox.toggled.connect(ui.settingsupdate)
    ui.uiTable.sortByColumn(2, 0)
    icon = QtGui.QIcon()
    icon.addPixmap(QtGui.QPixmap(ui.dir+"logo"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
    # from asd import logo
    # icon.addPixmap(logo)
    # logo = ['7 6 2 1', 'N c None', '. c #e2385a', 'N..N..N', \
    #  '.......', '.......', 'N.....N', 'NN...NN', 'NNN.NNN']
    # window.setWindowIcon(QtGui.QIcon(QtGui.QPixmap(logo)))
    window.show()
    exit = app.exec_()
    ui.readConfig(dump=True)
    try:
        ui.main_socket.close()
    finally:
        sys.exit(exit)