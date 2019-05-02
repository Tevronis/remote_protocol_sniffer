# coding=utf-8

import pcapy

from source.context import Context
from source.rdp_apps import RDP
from source.utils import *
from source.network_packet import NetworkPacket, IncorrectPacket
from source.writer import *


class Sniffer:
    def __init__(self, argv):
        self.context = Context(argv=argv)

    def setup(self):
        if self.outfile:
            open(self.outfile, 'w').close()
        # list all devices
        devices = pcapy.findalldevs()

        print "Доступные устройства:"
        for d in devices:
            print d

        self.dev = raw_input("Введите название устройства: ")

        print "Сканируемое устройство: " + self.dev

    def run(self):
        cap = pcapy.open_live(self.dev, 65536 * 8, self.context.PROMISCUOUS_MODE, 0)
        while True:
            (header, packet) = cap.next()
            self.parse_packet(packet)

    @property
    def outfile(self):
        return self.context.outfile

    def raw_mode(self, packet):
        packet.print_header(self.outfile)
        if self.context.DATA_PRINT:
            packet.print_data(self.outfile)
        Writer.print_spliter(self.outfile)

    def filter_mode(self, packet):
        result = False

        result |= packet.keyword_detection(self.context.key_values, logfile=self.outfile)

        result |= packet.port_detection(self.context.key_ports, logfile=self.outfile)

        result |= packet.telnet_detection(logfile=self.outfile)

        if not result:
            return

        packet.print_header(self.outfile)
        if self.context.DATA_PRINT:
            packet.print_data(self.outfile)

    def print_port_analyze(self, port, packets, ip):
        if packets is None:
            return

        RDP().serial_validation(port, packets, ip, suite=self)

    def analyze_mode(self, packet):
        import pdb;
        pdb.set_trace()
        words = []
        for item in self.context.key_values:
            fl = True
            data_idx = 0
            for ww in item:
                ff = False
                while data_idx + len(ww) < len(packet.data):
                    # print 'lens: ', len(data[data_idx: data_idx: + len(ww)]), len(ww)
                    if ww in packet.data[data_idx: data_idx + len(ww)]:
                        ff = True
                        break
                    data_idx += 1
                if not ff:
                    fl = False
            if fl:
                words.append(' '.join(item))
        # add changes:
        if self.context.analyze["ip"].get(packet.s_addr) is None:
            self.context.analyze["ip"][packet.s_addr] = {"ports": {}, "words": [], "single_symbol": []}
        if len(packet.data) == 1:
            self.context.analyze["ip"][packet.s_addr]["single_symbol"].append(packet.data)
        if packet.dest_port in self.context.key_ports:
            if self.context.analyze["ip"][packet.s_addr]["ports"].get(packet.dest_port) is None:
                self.context.analyze["ip"][packet.s_addr]["ports"].update({packet.dest_port: []})
            self.context.analyze["ip"][packet.s_addr]["ports"][packet.dest_port].append(
                packet.ip_head + '\nДанные пакета: ' + packet.data)
        if words:
            for word in words:
                self.context.analyze["ip"][packet.s_addr].get("words", []).append(word)
        # check anal
        for ip, ip_data in self.context.analyze["ip"].items():
            for k, val in ip_data.items():
                if k == 'ports':
                    for port, packets in val.items():
                        self.print_port_analyze(port, packets, ip)
                if k == 'words':
                    if val:
                        wds = '; '.join(val)
                        Writer.log_packet(self.outfile,
                                          '\nВ поле данных пакета, адресованного с адреса {} зафиксированы следующие ключевые фразы: '.format(
                                              ip))
                        Writer.log_packet(self.outfile, wds)
                        self.context.analyze["ip"][ip][k] = []
                if k == 'single_symbol':
                    if len(val) > 3:
                        sym = ' '.join(val)
                        Writer.log_packet(self.outfile,
                                          '\nС адреса {} замечена telnet сессия. Замечена серия пакетов, данные которые содержат только один символ'.format(
                                              ip))
                        Writer.log_packet(self.context.outfile, sym)
                        self.context.analyze["ip"][ip][k] = []

    def parse_packet(self, packet):
        try:
            p = NetworkPacket(packet)
        except IncorrectPacket:
            return

        if self.context.RAW_MODE:
            self.raw_mode(p)

        if self.context.REMOTE_CAPTURE_MODE:
            self.filter_mode(p)

        if self.context.ANALYZE_MODE:
            self.analyze_mode(p)


if __name__ == "__main__":
    sniffer = Sniffer(sys.argv)
    sniffer.setup()
    sniffer.run()
