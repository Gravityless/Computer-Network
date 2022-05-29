#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.RHS = 0
        self.LHS = 1
        self.num = int(num)
        self.acklist = [0 for i in range(int(num) + 1)]
        self.acktimer = time.time()
        self.SW = int(senderWindow)
        self.resendlist = []
        self.length = int(length)
        self.timeout = int(timeout)
        self.recvTimeout = int(recvTimeout)
        self.blasteeIp = blasteeIp
        self.ip = '192.168.100.1'
        self.mac = '10:00:00:00:00:01'
        self.midmac = '40:00:00:00:00:01'
        self.tranTime = time.time()
        self.retranNum = 0
        self.timeoutNum = 0

    # 超时返回True，未超时返回False
    def checktime(self):
        return (time.time() - self.acktimer) * 1000 > self.timeout

    # 超时重发窗口中所有未被确认的包
    def resend(self):
        if self.RHS <= self.num:
            for i in range(self.LHS, self.RHS + 1):
                if self.acklist[i - 1] == 0:
                    self.resendlist.append(i) 
                    
    
    # 构造一个指定序列号的包
    def sendseq(self, seqnum):
        # Creating the headers for the packet
        packet = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        packet[Ethernet].src = self.mac
        packet[Ethernet].dst = self.midmac
        packet[Ethernet].ethertype = EtherType.IPv4
        packet[IPv4].src = self.ip
        packet[IPv4].dst = self.blasteeIp
        packet[IPv4].ttl = 64
        packet[UDP].src = 5218
        packet[UDP].dst = 5218

        # Do other things here and send packet
        seqnum = (seqnum).to_bytes(4, byteorder="big")
        length = (self.length).to_bytes(2, byteorder="big")
        payload = bytes(100)
        packet += RawPacketContents(seqnum + length)
        packet += RawPacketContents(payload)

        self.net.send_packet("blaster-eth0", packet)

    # 从收到的ACK中获取序列号，根据序列号更新ACK表
    # 根据ACK表的确认情况右移窗口，如果窗口位置移动则重新计时
    # 最后调用handle_no_packet函数，进入超时管理和发包管理
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv

        # TODO: 获取ACK的序号
        seqnum = int.from_bytes(packet[3].data[:4], 'big')
        self.acklist[seqnum - 1] = 1
        log_info(f"Get ACK Seqence Num: {seqnum}; ACK list at {seqnum}: {self.acklist[seqnum - 1]}")
        
        nextLHS = self.LHS
        for i in range(self.LHS, self.RHS + 2):
            nextLHS = i
            if self.acklist[i - 1] == 0:
                break
        log_info(f"Current LHS = {self.LHS}; Next LHS = {nextLHS}")
        if nextLHS != self.LHS:
            self.LHS = nextLHS
            self.acktimer = time.time()

        # 准备发包
        self.handle_no_packet()

    # 判断LHS指向的包是否确认超时，如果超时进入resend程序，然后返回
    # 判断已发送的包是否等于发送窗口，如果相等则直接返回
    def handle_no_packet(self):

        # 判断是否符合发包条件
        if self.checktime() and (self.resendlist == []):
            log_info("Timeout, generate resend list...")
            self.acktimer = time.time()
            self.timeoutNum += 1
            self.resend()
        
        if self.resendlist:
            self.sendseq(self.resendlist[0])
            self.retranNum += 1
            self.resendlist.pop(0)
            return
        
        log_info(f"sended packets = {self.RHS - self.LHS + 1}; sender window = {self.SW}")
        if self.RHS - self.LHS + 1 >= self.SW:
            log_info("Sender Window full")
            return
        
        # 调用发包
        if self.RHS < self.num:
                self.RHS += 1
                self.sendseq(self.RHS)
                log_info(f"Send a packet {self.RHS}")

        if self.LHS == self.num + 1:
            self.printState()
            self.shutdown()       

    def printState(self):
        log_info(f"Total Transmition Time: {time.time() - self.tranTime}")
        log_info(f"Number of Retransmition: {self.retranNum}")
        log_info(f"Number of Coarse Timeouts: {self.timeoutNum}")
        log_info(f"Throughput: {self.length * (self.retranNum + self.num) / (time.time() - self.tranTime)}")
        log_info(f"Goodput: {self.length * self.num / (time.time() - self.tranTime)}")

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout / 1000.0)
            except NoPackets:
                log_info("Didn't receive anything")
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
