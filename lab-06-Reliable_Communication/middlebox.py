#!/usr/bin/env python3

import time
import threading
import random

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        self.macmapper = {}
        self.macmapper['middlebox-eth0'] = '40:00:00:00:00:01'
        self.macmapper['middlebox-eth1'] = '40:00:00:00:00:02'
        self.macmapper['blastee-eth0'] = '20:00:00:00:00:01'
        self.macmapper['blaster-eth0'] = '10:00:00:00:00:01'

    # 如果是从blaster来的包，有某个几率直接返回
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_info("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if random.random() < self.dropRate:
                log_info(f"Drop packet: {packet}")
                return
            eth_header = packet[Ethernet]
            eth_header.src = self.macmapper['middlebox-eth1']
            eth_header.dst = self.macmapper['blaster-eth0']
            ip_header = packet[IPv4]
            ip_header.ttl -= 1
            self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1":
            log_info("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            eth_header = packet[Ethernet]
            eth_header.src = self.macmapper['middlebox-eth0']
            eth_header.dst = self.macmapper['blastee-eth0']
            ip_header = packet[IPv4]
            ip_header.ttl -= 1
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_info("Oops :))")

    def start(self):
        '''A running daemon of the router.
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
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
