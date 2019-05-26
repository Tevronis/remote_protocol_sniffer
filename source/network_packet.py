# coding=utf-8
from time import time

from source.writer import Writer
from utils import *


class IncorrectPacket(Exception):
    pass


class NetworkPacket:
    def __init__(self, packet):
        self.protocol = 0
        self.parse(packet)

    def parse(self, packet):
        self.time = time()
        # telnet 23, STD RDP 3389, Radmin 4899, Teamviewer 80 443 53, ammyy 443 1255 5931
        self.eth_length = 14

        self.eth_header = packet[:self.eth_length]

        if len(self.eth_header) == 0:
            return
        self.eth = unpack('!6s6sH', self.eth_header)
        # print 'UNPACKING RAW ETH_HEADER: ' + str(eth)   # unpacking
        # import pdb; pdb.set_trace()
        self.eth_protocol = socket.ntohs(self.eth[2])
        # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(
        # packet[6:12]) + ' Protocol : ' + str(eth_protocol)

        # Parse IP packets, IP Protocol number = 8
        # print self.eth_protocol
        if self.eth_protocol == 8:
            # Parse IP header
            self.iph_length, self.version, self.ihl, self.ttl, self.protocol, self.s_addr, self.d_addr = parse_IP(packet, self.eth_length)

            if self.protocol == 6 or self.protocol == 17:  # if TCP or UDP
                self.decode_data, self.source_port, self.dest_port, self.tcph_length, self.protocol_head, self.data = [None] * 6
                if self.protocol == 6:  # TCP
                    self.decode_data, self.source_port, self.dest_port, self.tcph_length, self.protocol_head = parse_TCP(packet, self.iph_length, self.eth_length)

                if self.protocol == 17:  # UDP
                    self.decode_data, self.protocol_head, self.tcph_length, self.source_port, self.dest_port = parse_UDP(packet, self.iph_length, self.eth_length)
                try:
                    self.data = clear_data(self.decode_data.get_data_as_string()[self.iph_length + self.eth_length + self.tcph_length + 1:])
                except:
                    self.data = clear_data(self.decode_data[self.iph_length + self.eth_length + self.tcph_length + 1:])
                self.data_len = len(self.data)
        else:
            raise IncorrectPacket()

    @property
    def protocol_name(self):
        d = {17: 'UDP', 6: 'TCP'}
        # print 'pname', self.protocol, type(self.protocol)
        return d.get(self.protocol, '')

    ### PRINT FUNCTIONS ###

    def print_header(self, logfile):
        self.print_light_header(logfile)
        return
        # text = 'Заголовок IP: Версия : {} Длинна IP заголовка : {} TTL : {} Протокол : {} Адресс отправения : {} Адресс доставки : {}'
        # ip_head = text.format(self.version, self.ihl, self.ttl, self.protocol_name, self.s_addr, self.d_addr)
        # Writer.log_packet(logfile, '{}\n{}'.format(ip_head, self.protocol_head))

    def print_light_header(self, logfile):
        ip_head = 'Заголовок IP: Длинна IP заголовка : {} Протокол : {} Адресс отправения : {} Адресс доставки : {}'.format(
            self.ihl, self.protocol_name, self.s_addr, self.d_addr)
        protocol_head = 'Заголовок {}: Исходный порт : {} Порт назначения : {} Длина {} заголовка : {} Размер данных : {}\n'.format(
            self.protocol_name, self.source_port, self.dest_port, self.protocol_name, self.tcph_length, self.data_len)

        Writer.log_packet(logfile, '{}\n{}'.format(ip_head, protocol_head))

    def print_full_header(self, logfile):
        pass

    def print_data(self, logfile):
        try:
            Writer.log_packet(logfile, 'Данные пакета: ', self.data, '\n')
            # save_log(packet.data[packet.iph_length + packet.eth_length + packet.tcph_length + 1:])
        except Exception as e:
            Writer.log_packet(logfile, 'Данные пакета: непечатаемый символ. TODO написать hex формат!', '\n')
            print e.message
        print

    ### DETECT FUNCTIONS ###

    def keyword_detection(self, keywords, logfile):
        result = False
        for keyword in keywords:
            for elem in keyword:
                if elem not in self.data:
                    break
            else:
                Writer.log_packet(logfile, 'Замечено подключение с ключевой фразой: {} с адресса {}'.format(
                    ' '.join(keyword), self.s_addr)
                )
                result = True
        return result

    def port_detection(self, keyports, logfile):
        result = False
        if self.dest_port in keyports:
            Writer.log_packet(logfile, 'Замечено подключение на порт {} с адресса {}'.format(
                self.dest_port, self.s_addr)
            )
            result = True
        if self.source_port in keyports:
            Writer.log_packet(logfile, 'Замечено подключение на порт {} с адресса {}'.format(
                self.source_port, self.d_addr)
            )
            result = True
        return result

    def telnet_detection(self, logfile):
        if len(self.data) == 1:
            Writer.log_packet(logfile, 'Размер данных равен 1')
            return True
        return False


