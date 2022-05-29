'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    # Table!!
    trtable = {}

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)

        # Table!!
        if (eth.src in trtable) == False:
            if len(trtable) == 5:
                k = min(trtable.items(), key=lambda x: x[1][1])[0]
                trtable.pop(k)
            trtable[eth.src] = [fromIface, 0]


        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
            continue

        # Table!!
        if eth.dst in trtable:
            target = trtable.get(eth.dst)[0]
            trtable.get(eth.dst)[1] += 1
            log_info (f"Get MAC from mytable, MAC: {eth.dst} is at {target}")
            log_info (f"Send packet {packet} to {target}")
            net.send_packet(target, packet)
        else:
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)

        print (trtable)
    net.shutdown()
