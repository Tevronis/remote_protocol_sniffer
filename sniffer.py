# coding=utf-8

import pcapy
import sys

from sniffer_base import SnifferBase
from source.context import Context
from source.network_packet import NetworkPacket, IncorrectPacket
from source.utils import *


class Sniffer(SnifferBase):
    def __init__(self, argv):
        SnifferBase.__init__(self)
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

    def parse_packet(self, packet):
        try:
            p = NetworkPacket(packet)
        except IncorrectPacket:
            return

        # Save all packets
        if self.context.RAW_MODE:
            self.raw_mode(p)

        # Save packet with remote protocol markers
        if self.context.REMOTE_CAPTURE_MODE:
            self.filter_mode(p)

        # Analyze packets stream
        if self.context.ANALYZE_MODE:
            self.update_stream(p)
            self.analyze_mode(p)


if __name__ == "__main__":
    sniffer = Sniffer(sys.argv)
    sniffer.setup()
    sniffer.run()
