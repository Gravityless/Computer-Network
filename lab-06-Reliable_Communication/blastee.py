#!/usr/bin/env python3

from secrets import token_bytes
import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        self.blasterIp = blasterIp
        self.ip = '192.168.200.1'
        self.mac = '20:00:00:00:00:01'
        self.midmac = '40:00:00:00:00:02'
        self.num = int(num)

    # 从收到的包中获取序列号、有效负载长度、负载前8个字节
    # 然后调用send_ack函数发送ACK、
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv

        log_info(f"Pkt: {packet}")

        # TODO: 获取seqnum（4字节）将其添加到ACK中
        seqnum = int.from_bytes(packet[3].data[:4], 'big')
        # TODO: 获取length（2字节）
        length = int.from_bytes(packet[3].data[4:6], 'big')
        log_info(f"Get Seqence Num: {seqnum}; Payload Length: {length}")

        # TODO: 保留8字节的payload，若不够则填0
        payload = packet[3].data[6:]
        if length < 8:
            payload += bytes(8 - length)
        else:
            payload = packet[3].data[6:14]
        
        self.send_ack(seqnum, payload)

    # 分别为序列号和payload创建两个包头包含在UDP内
    def send_ack(self, seqnum, payload):
        packet = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        packet[Ethernet].src = self.mac
        packet[Ethernet].dst = self.midmac
        packet[Ethernet].ethertype = EtherType.IPv4
        packet[IPv4].src = self.ip
        packet[IPv4].dst = self.blasterIp
        packet[IPv4].ttl = 64
        packet[UDP].src = 5218
        packet[UDP].dst = 5218
        
        seqnum = (seqnum).to_bytes(4, byteorder="big")       
        packet += RawPacketContents(seqnum)
        packet += RawPacketContents(payload)

        self.net.send_packet("blastee-eth0", packet)
        pass

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
