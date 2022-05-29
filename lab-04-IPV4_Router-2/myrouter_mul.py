#!/usr/bin/env python3

'''
Multi thread basic IPv4 router (static routing) in Python.
'''

from collections import deque
import time
import threading
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from threading import Thread, current_thread
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty

# 全局变量
arptable = {}
forwarding_table = {}
lock = threading.Lock()


# 线程集合
next_hop_station = {}

# 线程分组处理函数
# 每个目的IP(next hop)对应一个线程
def packet_handler(next_hop, router):
    print("Enter thread next hop:", next_hop)
    init_time = time.time()
    last_chance = 5
    while True:
        try:
            recvs = next_hop_station[next_hop]
            recv = recvs.popleft()
            print("Get Packet: ", recv)
            # 检查是否存在ARP表中
            # 如果不存在则检查线程运行时间，满足1s则发送ARP Request
            # 如果存在则根据目的IP获取recv队列，调用router发送
            if (IPv4Address(next_hop) not in arptable.keys()):
                print("next hop: ", next_hop, "not in arptable")
                if last_chance == 0:
                    break
                if time.time() - init_time <= 1:
                    next_hop_station[next_hop].appendleft(recv)
                    continue
                print("Call ARP sender...")
                ARP_sender(router, recv)
                next_hop_station[next_hop].appendleft(recv)
                last_chance -= 1
                continue
            print("Call IPv4 sender...")
            IPv4_sender(router, recv)
        except:
            break

def ARP_sender(router, recv):
    timestamp, ifaceName, packet = recv
    ip = packet.get_header(IPv4)
    next_hop, outport = router.look_up_forwarding_table(ip.dst)
    senderhwaddr, senderprotoaddr = router.find_mac_ip_by_port(outport)
    arp_request = create_ip_arp_request(senderhwaddr, senderprotoaddr, next_hop)
    print(f"SEND: ARP request {next_hop}")
    router.net.send_packet(outport, arp_request)

def IPv4_sender(router, recv):
    timestamp, ifaceName, packet = recv
    ip = packet.get_header(IPv4)
    next_hop, outport = router.look_up_forwarding_table(ip.dst)
    next_hop_mac_addr = arptable.get(IPv4Address(next_hop))[0]
    eth_header = Ethernet()
    eth_header.src,ip = router.find_mac_ip_by_port(outport)
    eth_header.dst = next_hop_mac_addr
    eth_header.ethertype = EtherType.IPv4
    del packet[Ethernet]
    packet.insert_header(0, eth_header)
    print(f"SEND: IPv4 Packet {next_hop}, {next_hop_mac_addr}")
    router.net.send_packet(outport, packet)

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces = net.interfaces()
        self.macs = [i.ethaddr for i in self.interfaces]
        self.ips = [i.ipaddr for i in self.interfaces]
        self.init_forwarding_table()

    # 初始化forwarding table
    # 1. 从forwarding_table.txt中获取
    # 2. 从本机接口获取
    def init_forwarding_table(self):
        with open('./forwarding_table.txt', 'r') as f:
            lines = f.readlines()
        for line in lines:
            ip_address, subnet, next_hop, interface = line.strip().split()
            forwarding_table[ip_address] = [subnet, next_hop, interface]
        for i in self.interfaces:
            netaddr = IPv4Network(int(i.ipaddr) & int(i.netmask))
            forwarding_table[str(netaddr)[:-3]] = [str(i.netmask), '0.0.0.0', i.name]
        with open('./writeout_table.txt', 'w') as f:
            for k,v in forwarding_table.items():
                f.write(k + ':' + str(v) + '\n') 

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1)
            except NoPackets:
                continue
            except Shutdown:
                break
            print("RECV Packet: ", recv)
            self.handle_packet(recv)
            print("---------------------------------------")

        self.stop()

    # 根据分组头部，处理收到的分组：
    # 如果是ARP分组，进入ARP处理模块
    # 如果是其他IPv4分组，进去IPv4处理模块
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        if packet.has_header(Arp):
            arp = packet.get_header(Arp)
            self.arp_handler(arp, recv)
            return
        
        if packet.has_header(IPv4):
            ip = packet.get_header(IPv4)
            ip.ttl -= 1
            self.IPv4_handler(ip, recv)
            return

    # 根据operation区分request还是reply
    # request则向同一接口发送相应的reply
    def arp_handler(self, arp, recv):
        timestamp, ifaceName, packet = recv
        self.update_arptable(arp, timestamp)
        print(f"UPDATE: current ARP table is {arptable}")
        if arp.operation == 1:
            print("Send ARP reply for:", arp.targetprotoaddr)
            if arp.targetprotoaddr in self.ips:
                targethwaddr = arp.senderhwaddr
                targetprotoaddr = arp.senderprotoaddr
                senderprotoaddr = arp.targetprotoaddr
                senderhwaddr = self.find_mac_by_ip(senderprotoaddr)
                arp_reply_packet = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
                self.net.send_packet(ifaceName, arp_reply_packet)

    # 处理IPv4分组，转发分组和发送ARP
    # 1. 查看目的地址是否是自身接口，是则结束处理
    # 2. 查看目的地址是否在转发表中，不是则结束处理
    # 3. 查找ARP表中下一跳对应的MAC地址，如果没找到，加入等待队列
    # 4. 如果找到立即发送
    def IPv4_handler(self, ip, recv):
        # TODO：查表转发表，验证是否需要处理
        # 如果需要处理则加入对应下一跳IP的队列
        if ip.dst in self.ips:
            return
        next_hop, outport = self.look_up_forwarding_table(ip.dst)
        print("Get next hop ipaddr: ", next_hop)
        if next_hop != '-1':
            if next_hop not in next_hop_station.keys():
                thread = Thread(target=packet_handler, args=(next_hop, self))
                next_hop_station[next_hop] = deque()
                next_hop_station[next_hop].append(recv)
                thread.start()
                print("Create deque: ", next_hop_station[next_hop])
                print("Created a new thread for: ", next_hop)
            else:
                next_hop_station[next_hop].append(recv)
                print("Already has a deque for: ", next_hop, "add ", recv)
        print("next hop: ", next_hop, " equals -1, so drop")
        
    # 返回next_hop -1表示不在转发表中
    # 如果下一跳地址是0.0.0.0则替换成目标ip地址
    def look_up_forwarding_table(self, destaddr):
        maxlen = 0
        next_hop = '-1'
        outport = '-1'
        for ipaddr, info in forwarding_table.items():
            netaddr = IPv4Network(ipaddr + '/' + info[0])
            prefixlen = netaddr.prefixlen
            if (IPv4Address(destaddr) in netaddr) and (prefixlen > maxlen):
                maxlen = prefixlen
                next_hop = info[1]
                outport = info[2]
                if next_hop == '0.0.0.0':
                    next_hop = destaddr
        return next_hop, outport

    # 更新ARP表
    def update_arptable(self, arp, timestamp):
        arptable[arp.senderprotoaddr] = [arp.senderhwaddr, timestamp]
        delete_list = []
        for k,v in arptable.items():
            if timestamp - v[1] > 30:
                delete_list.append(k)
        for k in delete_list:
            arptable.pop(k)

    # 返回路由器接口ip对应的mac地址
    def find_mac_by_ip(self, ipaddr):
        for i in self.interfaces:
            if ipaddr == i.ipaddr:
                return i.ethaddr

    # 返回路由器接口名对应的mac和ip地址
    def find_mac_ip_by_port(self, outport):
        for i in self.interfaces:
            if outport == i.name:
                return i.ethaddr, i.ipaddr
                
    def stop(self):
        self.net.shutdown()

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
