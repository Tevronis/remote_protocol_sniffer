# coding=utf-8
import logging
from time import time

from source.report import Report
from utils import *

LOGGER = logging.getLogger(__name__)


class IncorrectPacket(Exception):
    pass


class NetworkPacket:
    def __init__(self, packet):
        self.l4_protocol = 0
        self.decode_data = None
        self.source_port = None
        self.dest_port = None
        self.h_length = None
        self.protocol_msg = None
        self.data = None
        self.parse(packet)

    def parse(self, packet):
        self.time = time()
        self.eth_length = 14

        self.eth_header = packet[:self.eth_length]

        if len(self.eth_header) == 0:
            return

        self.eth = unpack('!6s6sH', self.eth_header)
        # print 'UNPACKING RAW ETH_HEADER: ' + str(eth)   # unpacking
        self.eth_protocol = socket.ntohs(self.eth[2])
        # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(
        # packet[6:12]) + ' Protocol : ' + str(eth_protocol)

        # Parse IP packets, IP Protocol number = 8
        if self.eth_protocol == 8:
            # Parse IP header
            l3_data = parse_ip(packet, self.eth_length)
            self.iph_length = l3_data['iph_length']
            self.version = l3_data['version']
            self.ihl = l3_data['ihl']
            self.ttl = l3_data['ttl']
            self.l4_protocol = l3_data['l4_protocol']
            self.s_addr = l3_data['s_addr']
            self.d_addr = l3_data['d_addr']

            if self.l4_protocol == 6 or self.l4_protocol == 17:  # if TCP or UDP
                if self.l4_protocol == 6:  # TCP
                    l4_data = parse_tcp(packet, self.iph_length, self.eth_length)
                if self.l4_protocol == 17:  # UDP
                    l4_data = parse_udp(packet, self.iph_length, self.eth_length)

                if not l4_data:
                    raise IncorrectPacket()

                self.decode_data = l4_data['decode_data']
                self.protocol_msg = l4_data['protocol_msg']
                self.h_length = l4_data['h_length']
                self.source_port = l4_data['source_port']
                self.dest_port = l4_data['dest_port']

            if self.l4_protocol == 1: # if ICMP
                icmp_data = parce_icmp(packet, self.iph_length, self.eth_length)
                self.decode_data = icmp_data['decode_data']
                self.h_length = icmp_data['h_length']
                self.protocol_msg = icmp_data['protocol_msg']

            if not self.decode_data:
                return

            try:
                self.data = pretty_data(self.decode_data.get_data_as_string()[
                                        self.iph_length + self.eth_length + self.h_length + 1:])
            except:
                self.data = pretty_data(self.decode_data[
                                        self.iph_length + self.eth_length + self.h_length + 1:])
            self.data_len = len(self.data)

        else:
            raise IncorrectPacket()

    @property
    def protocol_name(self):
        d = {17: 'UDP', 6: 'TCP'}
        return d.get(self.l4_protocol, '')

    ### PRINT FUNCTIONS ###

    def get_header(self):
        return self.get_light_header()
        # text = 'Заголовок IP: Версия : {} Длинна IP заголовка : {} TTL : {} Протокол : {} Адресс отправения : {} Адресс доставки : {}'
        # ip_head = text.format(self.version, self.ihl, self.ttl, self.protocol_name, self.s_addr, self.d_addr)
        # Writer.log_packet(logfile, '{}\n{}'.format(ip_head, self.protocol_head))

    def get_light_header(self):
        ip_head = 'Заголовок IP: Длинна IP заголовка : {} Протокол : {} Адресс отправения : {} Адресс доставки : {}'.format(
            self.ihl, self.protocol_name, self.s_addr, self.d_addr)
        protocol_head = ''
        if self.protocol_name in ('TCP', 'UDP'):
            protocol_head = 'Заголовок {}: Исходный порт : {} Порт назначения : {} Длина {} заголовка : {} Размер данных : {}\n'.format(
                self.protocol_name, self.source_port, self.dest_port, self.protocol_name, self.h_length, self.data_len)

        return '{}\n{}'.format(ip_head, protocol_head)

    def print_full_header(self):
        pass

    def print_data(self):
        try:
            msg = 'Данные пакета: %s\n' % self.data
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print str(msg)
            # save_log(packet.data[packet.iph_length + packet.eth_length + packet.tcph_length + 1:])
        except Exception as e:
            msg = 'Данные пакета: непечатаемый символ.\n'
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print str(msg)
            print e.message
        print

    ### DETECT FUNCTIONS ###

    def keyword_detection(self, keywords):
        result = False
        for keyword in keywords:
            for elem in keyword:
                if elem not in self.data:
                    break
            else:
                msg = 'Замечено подключение с ключевой фразой: {} с ' \
                      'адресса {}'.format(' '.join(keyword), self.s_addr)
                LOGGER.info(msg)
                if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                    print str(msg)
                result = True
        return result

    def port_detection(self, keyports):
        result = False
        if self.dest_port in keyports:
            msg = 'Замечено подключение на порт {} с адресса {}'.format(self.dest_port, self.s_addr)
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print str(msg)
            result = True
        if self.source_port in keyports:
            msg = 'Замечено подключение на порт {} с адресса {}'.format(self.source_port, self.d_addr)
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print str(msg)
            result = True
        return result

    def telnet_detection(self):
        if len(self.data) == 1:
            msg = 'Размер данных равен 1'
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print str(msg)
            return True
        return False


