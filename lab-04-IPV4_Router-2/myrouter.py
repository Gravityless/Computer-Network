#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces = net.interfaces()
        self.macs = [i.ethaddr for i in self.interfaces]
        self.ips = [i.ipaddr for i in self.interfaces]
        self.arptable = {}
        self.arpque = {}
        self.packetque = {}
        self.forwarding_table = {}
        self.init_forwarding_table()

    # 初始化forwarding table
    # 1. 从forwarding_table.txt中获取
    # 2. 从本机接口获取
    def init_forwarding_table(self):
        with open('./forwarding_table.txt', 'r') as f:
            lines = f.readlines()
        for line in lines:
            ip_address, subnet, next_hop, interface = line.strip().split()
            self.forwarding_table[ip_address] = [subnet, next_hop, interface]
        for i in self.interfaces:
            netaddr = IPv4Network(int(i.ipaddr) & int(i.netmask))
            self.forwarding_table[str(netaddr)[:-3]] = [str(i.netmask), '0.0.0.0', i.name]
        with open('./writeout_table.txt', 'w') as f:
            for k,v in self.forwarding_table.items():
                f.write(k + ':' + str(v) + '\n') 

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1)
            except NoPackets:
                if self.arpque:
                    # print(f"NO Packets: current ARP que is {self.arpque}")
                    # print(f"NO Packets: current Packet que is {self.packetque}")
                    # print("NO Packets: handle forwarding que")
                    self.handle_forwarding_que()
                    # print("---------------------------------------")
                continue
            except Shutdown:
                break

            print(f"RECV Packet: current ARP que is {self.arpque}")
            print(f"RECV Packet: current Packet que is {self.packetque}")
            if self.arpque:
                print("RECV Packet: handle forwarding que")
                self.handle_forwarding_que()
            self.handle_packet(recv)
            print("---------------------------------------")

        self.stop()

    # 根据分组头部，处理收到的分组：
    # 如果是ARP分组，进入ARP处理模块
    # 如果是其他IPv4分组，进去IPv4处理模块
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
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
        print(f"UPDATE: current ARP table is {self.arptable}")
        if arp.operation == 1:
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
        timestamp, ifaceName, packet = recv
        # TODO：查表，验证是否需要处理
        if ip.dst in self.ips:
            return
        next_hop, outport = self.look_up_forwarding_table(ip.dst)
        if next_hop != '-1':            
            # TODO: 找到下一跳MAC
            # 如果找不到自动加入转发队列，并发送ARP request，返回查询MAC结果
            next_hop_mac_addr = self.look_up_arp_table(next_hop, outport, ip, recv)
            if next_hop_mac_addr != 'ff-ff-ff-ff-ff-ff':
                # TODO: 准备以太网包
                eth_header = Ethernet()
                eth_header.src,ip = self.find_mac_ip_by_port(outport)
                eth_header.dst = next_hop_mac_addr
                eth_header.ethertype = EtherType.IPv4
                del packet[Ethernet]
                packet.insert_header(0, eth_header)

                # TODO：发送IP包
                self.net.send_packet(outport, packet)

    # TODO: 通过ARP查找MAC地址
    # 创建并发送代表转发表中某项(next hop)的ARP request；
    # 创建对应next hop的分组arp请求标记和packet发送队列；
    def handle_arptable_not_found(self, next_hop, outport, ip, recv):
        already_inqueque = False
        if self.arpque:
            for k,v in self.arpque.items():
                if next_hop == k:
                    already_inqueque = True
        if already_inqueque == False:
            self.arpque[next_hop] = self.arp_waiter(outport)
            self.packetque[next_hop] = []
            senderhwaddr, senderprotoaddr = self.find_mac_ip_by_port(outport)
            arp_request = create_ip_arp_request(senderhwaddr, senderprotoaddr, next_hop)
            self.net.send_packet(outport, arp_request)
            print(f"SEND: ARP request {next_hop}")
        self.packetque[next_hop].insert(0, self.packet_waiter(next_hop, outport, ip, recv))
        return 'ff-ff-ff-ff-ff-ff'

    # 每轮循环开始时，检查等待队列的下一跳mac地址有没有命中arp表
    # 如果命中，将该mac地址加入命中列表，根据命中列表按顺序将排队的分组转发，删除对应等待队列
    # 剩余arp que表项重发机会-1，等于0直接删除
    # 剩余arp que中没有命中的项发送arp分组
    def handle_forwarding_que(self):
        arp_hit_list = []
        for k,v in self.arpque.items():
            if IPv4Address(k) in self.arptable.keys():
                print(f"Comparing {k} with {self.arptable.keys()}")
                arp_hit_list.append(k)
                print('Hit: ' + str(k))

        for i in arp_hit_list:
            for j in self.packetque[i]:
                print(f"Turn to IPv4 Handler: {j}")
                self.IPv4_handler(j.ip, j.recv)
            del self.arpque[i]
            del self.packetque[i]

        delete_list = []
        for k,v in self.arpque.items():
            current = time.time()
            if v.til(current):
                if v.tries == 0:
                    delete_list.append(k)
                    continue
                senderhwaddr, senderprotoaddr = self.find_mac_ip_by_port(v.outport)
                arp_request = create_ip_arp_request(senderhwaddr, senderprotoaddr, k)
                print(f"SEND: ARP request {k}")
                self.net.send_packet(v.outport, arp_request)
                v.time = current
                v.tries -= 1
                
            
        for k in delete_list:    
            del self.arpque[k]
            del self.packetque[k]
        

    # 查找ARP表，如果命中则返回下一跳mac地址
    # 如果未命中，调用处理函数将转发分组加入待发送队列
    def look_up_arp_table(self, next_hop, outport, ip, recv):
        if IPv4Address(next_hop) in self.arptable.keys():
            return self.arptable.get(IPv4Address(next_hop))[0]
        else:
            return self.handle_arptable_not_found(next_hop, outport, ip, recv)

    # 返回next_hop -1表示不在转发表中
    # 如果下一跳地址是0.0.0.0则替换成目标ip地址
    def look_up_forwarding_table(self, destaddr):
        maxlen = 0
        next_hop = '-1'
        outport = '-1'
        for ipaddr, info in self.forwarding_table.items():
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
        self.arptable[arp.senderprotoaddr] = [arp.senderhwaddr, timestamp]
        delete_list = []
        for k,v in self.arptable.items():
            if timestamp - v[1] > 30:
                delete_list.append(k)
        for k in delete_list:
            self.arptable.pop(k)

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

    class packet_waiter:
        def __init__(self, next_hop, outport, ip, recv):
            self.next_hop = next_hop
            self.outport = outport
            self.recv = recv
            self.ip = ip

    class arp_waiter:
        def __init__(self, outport):
            self.outport = outport
            self.time = time.time()
            self.tries = 4

        def til(self, current):
            return current - self.time >= 1

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
