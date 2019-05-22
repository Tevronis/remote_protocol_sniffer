# coding=utf-8
from time import time

from source.network_packet import NetworkPacket, IncorrectPacket
from source.rdp_apps import RDP
from source.stream import TcpStream, UdpStream
from source.writer import Writer


class SnifferBase:
    def __init__(self):
        self.context = None
        self.udp_streams = {}
        self.tcp_streams = {}
        self.analyze_previous_time = time()

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

    def update_stream(self, p):
        if p.protocol_name == 'TCP':
            self.tcp_streams.get(tuple(sorted([p.s_addr, p.d_addr])), []).append(p)
        if p.protocol_name == 'UDP':
            self.udp_streams.get(tuple(sorted([p.s_addr, p.d_addr])), []).append(p)

    def print_port_analyze(self, port, packets, ip):
        if packets is None:
            return

        RDP().serial_validation(port, packets, ip, suite=self)

    def analyze_mode(self, packet):
        self.analyze_stream()

    def analyze_stream(self):
        if time() - self.analyze_previous_time > 10:
            for stream in self.tcp_streams:
                ts = TcpStream(stream)
                # packets len
                # ports
                # flat
                # in_len out_len
            for stream in self.udp_streams:
                us = UdpStream(stream)

    def parse_packet(self, packet):
        try:
            NetworkPacket(packet)
        except IncorrectPacket:
            return
