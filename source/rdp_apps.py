# coding=utf-8
from source.writer import Writer


class RemoteApp:
    name = None

    def print_detection_port_sequence(self, ip, count, port, logfile):
        Writer.log_packet(logfile,
                          '\nС адреса {} замечена {} сессия. Перехвачено {} пакетов адресованных на порт {}'.format(
                              ip, self.name, count, port)
                          )

    def serial_validation(self, port, packets, ip, suite):
        Writer.log_packet(suite.outfile, 'Приложение {} еще не поддерживается. Попинайте разработчика'.format(self.name))


class RDP(RemoteApp):
    name = 'RDP'
    ports = [3389]
    key_values = [['rdp'], ['RDP']]
    remote_apps = {'RDP': [3389]}
    packet_count_detection = 49
    analyze = {"ip": {}}

    def serial_validation(self, port, packets, ip, suite):
        if port in self.ports:
            if len(packets) > self.packet_count_detection:
                self.print_detection_port_sequence(ip, len(packets), port, suite.outfile)
                suite.analyze["ip"][ip]['ports'][port] = []


class Telnet(RemoteApp):
    name = 'Telnet'


class Radmin(RemoteApp):
    name = 'Radmin'


class Teamviewer(RemoteApp):
    name = 'TeamViewer'


class AmmyyAdmin(RemoteApp):
    name = 'AmmyyAdmin'
