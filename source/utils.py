# coding=utf-8
import socket
from struct import *
import datetime
import pcapy
import sys
import string
from io import open
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def save_log(s):
    with open('log.log', 'a', encoding='utf-8') as f:
        t = str(datetime.datetime.now().time()) + ' '
        t.encode('utf-8')
        try:
            f.write(u'{} {}\n'.format(t, s))
        except:
            f.write(u'bad symbol\n')


def clear_data(data):
    result = ''
    for item in data:
        if item not in string.printable:
            result += '.'
        else:
            result += item
    return result


def parse_UDP(packet, iph_length, eth_length):
    u = iph_length + eth_length
    udph_length = 8
    udp_header = packet[u:u + 8]

    udph = unpack('!HHHH', udp_header)

    source_port = udph[0]
    dest_port = udph[1]
    length = udph[2]
    checksum = udph[3]

    UDP_str = 'Заголовок UDP Исходный порт {} Порт назначения : {} Длинна : {} Checksum : {}\n'.format(source_port, dest_port, length, checksum)

    h_size = eth_length + iph_length + udph_length
    data_size = len(packet) - h_size

    decode_data = packet[h_size:]
    return decode_data, UDP_str, udph_length, source_port, dest_port


def parce_ICMP(packet, iph_length, eth_length):
    u = iph_length + eth_length
    icmph_length = 4
    icmp_header = packet[u:u + 4]

    icmph = unpack('!BBH', icmp_header)

    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]

    ICMP_str = 'Заголовок ICMP Тип : {} Код : {} Checksum : {}\n'.format(icmp_type, code, checksum)

    h_size = eth_length + iph_length + icmph_length
    data_size = len(packet) - h_size

    data = packet[h_size:]
    return data, ICMP_str


def parse_TCP(packet, iph_length, eth_length):
    t = iph_length + eth_length
    tcp_header = packet[t:t + 20]

    tcph = unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    TCP_str = 'Заголовок TCP: Исходный порт : {} Порт назначения : {} Порядковый номер : {} Подтверждение : {} Длина TCP заголовка : {}\n'.format(
        source_port, dest_port, sequence, acknowledgement, tcph_length)

    h_size = eth_length + iph_length + tcph_length * 4

    decode_data = EthDecoder().decode(packet)  # .get_data_as_string()

    return decode_data, source_port, dest_port, tcph_length, TCP_str


def parse_IP(packet, eth_length):
    ip_header = packet[eth_length:20 + eth_length]

    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    return iph_length, version, ihl, ttl, protocol, s_addr, d_addr
