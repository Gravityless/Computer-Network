#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces = net.interfaces()
        self.macs = [i.ethaddr for i in self.interfaces]
        self.ips = [i.ipaddr for i in self.interfaces]
        self.arptable = {}
        # other initialization stuff here

    def find_mac(self, ipaddr):
        for i in self.interfaces:
            if ipaddr == i.ipaddr:
                return i.ethaddr

    def update_arptable(self, arp, timestamp):
        self.arptable[arp.senderprotoaddr] = [arp.senderhwaddr, timestamp]
        delete_list = []
        for k,v in self.arptable.items():
            if timestamp - v[1] > 30:
                delete_list.append(k)
        for k in delete_list:
            self.arptable.pop(k)
        
        log_info(f"current ARP table is {self.arptable}")

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        if packet.has_header(Arp):
            arp = packet.get_header(Arp)
            if arp.operation == 1:
                self.update_arptable(arp, timestamp)
                if arp.targetprotoaddr in self.ips:
                    targethwaddr = arp.senderhwaddr
                    targetprotoaddr = arp.senderprotoaddr
                    senderprotoaddr = arp.targetprotoaddr
                    senderhwaddr = self.find_mac(senderprotoaddr)
                    arp_reply_packet = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
                    self.net.send_packet(ifaceName, arp_reply_packet)

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

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
