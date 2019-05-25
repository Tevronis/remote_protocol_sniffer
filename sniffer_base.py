# coding=utf-8
import collections
import json
from pprint import pprint
from time import time

from source.network_packet import NetworkPacket, IncorrectPacket
from source.rdp_apps import RDP
from source.stream import TcpStream, UdpStream
from source.writer import Writer


class SnifferBase:
    def __init__(self):
        self.context = None
        self.udp_streams = collections.defaultdict(list)
        self.tcp_streams = collections.defaultdict(list)
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
            self.tcp_streams[tuple(sorted(['{}:{}'.format(p.s_addr, p.source_port), '{}:{}'.format(p.d_addr, p.dest_port)]))].append(p)
        if p.protocol_name == 'UDP':
            self.udp_streams[tuple(sorted(['{}:{}'.format(p.s_addr, p.source_port), '{}:{}'.format(p.d_addr, p.dest_port)]))].append(p)

    def print_port_analyze(self, port, packets, ip):
        if packets is None:
            return

        RDP().serial_validation(port, packets, ip, suite=self)

    def analyze_mode(self, packet):
        self.analyze_stream()

    def analyze_stream(self):
        def discretion(value, d):
            return (int(value) + d) / d * d

        def check_stream(_stream, label):
            for tuple_hosts, stream in _stream.iteritems():
                host1 = stream[0].s_addr
                host2 = stream[0].d_addr
                len_stat = {host1: collections.defaultdict(int), host2: collections.defaultdict(int)}
                time_delay = collections.defaultdict(int)
                previous = stream[0]
                smb_counter = 0
                for p in stream:
                    if 'SMB' in p.data:
                        smb_counter += 1
                    if previous != p:
                        time_delay[discretion(p.time - previous.time, 1)] += 1
                        previous = p
                    len_stat[p.s_addr][discretion(p.data_len, 60)] += 1
                if smb_counter != 0:
                    print label, tuple_hosts
                    print 'SMB packet detected!'
                    break

                val = (sum(len_stat[host1].keys()) + sum(len_stat[host2].keys())) / (len(len_stat[host1].keys())) + len(len_stat[host2].keys())
                print '[DEBUG] Average packet len:', str(val)
                if val > 300:
                    print label, tuple_hosts
                    if len(time_delay.keys()) > 1:
                        print 'Looks like RDP, detected time-delay between packets'
                    else:
                        print 'Looks like TeamViewer, time-delay not detected'

                # print json.dumps(len_stat, indent=2)
                # print json.dumps(time_delay, indent=2)
        # print time() - self.analyze_previous_time
        if time() - self.analyze_previous_time > 10:
            self.analyze_previous_time = time()
            check_stream(self.tcp_streams, 'TCP')
            check_stream(self.udp_streams, 'UDP')
            self.udp_streams = collections.defaultdict(list)
            self.tcp_streams = collections.defaultdict(list)

    def parse_packet(self, packet):
        try:
            NetworkPacket(packet)
        except IncorrectPacket:
            return
