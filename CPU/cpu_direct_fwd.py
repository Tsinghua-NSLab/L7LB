#! 终端运行的发包程序

import argparse
import sys
import socket
import random
import struct
import time
import datetime
import threading
from enum import Enum

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, get_if_addr
from scapy.all import Packet, sniff, srp1, sr1
from scapy.all import Ether, IP, UDP, TCP, ARP, ICMP

args = None # 命令解析结果

iface_name_list = []
iface_list = []
origin_mac_pkt_list = []
ipv4_list = [] # 记录两个端口对应的IP地址

lock = None
# 记录session状态
SESSION_STATE_CLI_SYN = 0x01
SESSION_STATE_CLI_ACK = 0x02
SESSION_STATE_SRV_SYN = 0x04 # SRV端发起了建链
SESSION_STATE_SRV_ACK = 0x10 # SRV端的建链完成了
SESSION_STATE_DONE = 0x20    # 

session_state_map = {} # key: flow, value: session_state
session_cli_seq = {}   # 记录cli的初始seq (从cli-->middle的视角)
session_cli_ack = {}   # 记录cli的初始ack
session_srv_seq = {}   # 记录srv的初始seq (从middle-->srv的视角)
session_srv_ack = {}   # 记录srv的初始ack
session_pkts = {}      # 记录从cli发出的包, 尚未完成相关处理
done_pkts = {}         # 已经处理完毕的包(防止重复处理)


SEND_STEP = 10

# 累计发出的报文
total_send_pkt = 0
total_recv_pkt = 0

# TCP-Flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def print_nop():
    print("================")

def get_if(iface_name='eth0'):
    iface=None # "h1-eth0"
    for i in get_if_list():
        if iface_name in i:
            iface=i
            break
    if not iface:
        print("Cannot find " + iface_name+ " interface")
        exit(1)
    return iface

def get_new_pkt_from_cli(pkt, flow):
    global session_srv_seq, session_srv_ack, session_cli_seq, session_cli_ack, session_state_map, session_pkts, done_pkts, total_send_pkt, total_recv_pkt
    # 修改网包信息(该网包是cli-->CPU), 修改成匹配(CPU->srv)的seq/ack的网包
    new_pkt = pkt
    new_pkt[TCP].seq = session_srv_seq[flow] + pkt[TCP].seq - session_cli_seq[flow]
    new_pkt[TCP].ack = session_srv_ack[flow] + pkt[TCP].ack - session_cli_ack[flow]
    return new_pkt 

def get_new_pkt_from_srv(pkt, flow):
    global session_srv_seq, session_srv_ack, session_cli_seq, session_cli_ack, session_state_map, session_pkts, done_pkts, total_send_pkt, total_recv_pkt
    # 修改网包信息(该网包是srv-->CPU), 修改成匹配(CPU->cli)的seq/ack的网包
    new_pkt = pkt
    new_pkt[TCP].seq = session_cli_seq[flow] + pkt[TCP].seq - session_srv_seq[flow]
    new_pkt[TCP].ack = session_cli_ack[flow] + pkt[TCP].ack - session_srv_ack[flow]
    return new_pkt


def middle_back(pkt, from_iface_idx):
    global iface_list, ipv4_list, lock, session_srv_seq, session_srv_ack, session_cli_seq, session_cli_ack, session_state_map, session_pkts, done_pkts, total_send_pkt, total_recv_pkt
    pkt_type = 'unknown'
    if (ARP in pkt):
        pkt_type = 'ARP'
    elif (ICMP in pkt):
        pkt_type = 'ICMP'
    elif (TCP in pkt):
        pkt_type = 'TCP'
    elif (UDP in pkt):
        pkt_type = 'UDP'
    # print_nop()
    # pkt.show()

    if ( (ARP in pkt) and (pkt[ARP].psrc == ipv4_list[from_iface_idx]) ) or ((ICMP in pkt) and (pkt[IP].src == ipv4_list[from_iface_idx])):
        # ARP网包的源IP地址, ICMP的源IP地址是对应端口的IP地址, 转发到另一个端口
        print("=== Receive a %s packet, forward to %s" % ( pkt_type, iface_list[1 - from_iface_idx]))
        sendp(pkt, iface=iface_list[1 - from_iface_idx], verbose=False)
        return
    elif (ARP in pkt) or (ICMP in pkt):
        # ARP网包, ICMP网包, 并不是从对应端口发出的
        # print("=== Receive a %s packet for the other size" % (pkt_type) )
        return
    elif (TCP in pkt) and (pkt[TCP].flags & RST):
        # 对于RST报文, 直接丢弃
        print("=== Receive a RST packet, drop")
        return
    elif (IP in pkt) and (pkt[IP].dst == ipv4_list[from_iface_idx]):
        # 对于IP报文, IP的dst是对应端口的IP地址, 那么就不需要处理(已经到达对端了)
        # print("=== Receive a %s packet, dst is %s, do not care!" % (pkt_type, ipv4_list[from_iface_idx]))
        return
    elif (TCP in pkt) or (UDP in pkt):
        # 直接把网包转送到对端
        # if (TCP in pkt) and (pkt[TCP].flags & SYN) and (pkt[TCP].flags & ACK != ACK):
        #     # 更新options, 删除所有的timestamp option
        #     new_options = []
        #     for option in pkt[TCP].options:
        #         if option[0] == 'Timestamp':
        #             continue # 不使用时间戳
        #             # new_options.append(('Timestamp', (option[1][0], option[1][1] + 1)))
        #         elif option not in new_options:
        #             new_options.append(option)
        #     new_pkt = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=pkt[Ether].type) / IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq = pkt[TCP].seq, ack=pkt[TCP].ack, window=pkt[TCP].window, options=new_options) / pkt[TCP].payload # 舍弃timestamp选项?
        #     print("=== Create a new TCP packet")
        #     if pkt[TCP].flags & SYN:
        #         print("=== SYN")
        #         new_pkt.show()
        # else:
        #     new_pkt = pkt
        # pkt_cpy = pkt.copy()
        # pkt_cpy[IP].remove_payload()
        # new_pkt = pkt_cpy / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq = pkt[TCP].seq, ack=pkt[TCP].ack, window=pkt[TCP].window, options=pkt[TCP].options) / pkt[TCP].payload
        # print("=== Receive a TCP/UDP packet, forward to %s" % iface_list[1 - from_iface_idx])
        new_pkt = pkt.copy()
        # new_pkt.show()
        sendp(new_pkt, iface=iface_list[1 - from_iface_idx], verbose=False)
    else:
        print_nop()
        print("=== A Strange TCP packet")
        pkt.show()
        print_nop()


def thread_sniff(idx):
    global iface_name_list, iface_list, origin_mac_pkt_list
    # 对于目的MAC地址是中间设备的网包, 不进行处理
    # sniff(iface = iface_list[idx], 
    #     lfilter=lambda pkt: (pkt[Ether].dst != origin_mac_pkt_list[idx].src) and (pkt[Ether].src != origin_mac_pkt_list[idx].src) and (pkt[Ether].src != origin_mac_pkt_list[1 - idx].src) and (pkt[Ether].dst != origin_mac_pkt_list[1 - idx].src), 
        # prn = lambda pkt: middle_back(pkt, idx))
    sniff(iface = iface_list[idx], 
        prn = lambda pkt: middle_back(pkt, idx))


# 中间设备, 收到SYN报文后, 完成相关建链记录相关信息
def middle():
    global iface_name_list, iface_list, origin_mac_pkt_list, ipv4_list, lock
    iface_name_list = [args.iface_cli, args.iface_srv]
    iface_list = [get_if(iface_name_list[0]), get_if(iface_name_list[1])]
    mac_list = [get_if_hwaddr(iface_list[0]), get_if_hwaddr(iface_list[1])]
    origin_mac_pkt_list = [ Ether(src=mac_list[0]), Ether(src=mac_list[1]) ]
    ipv4_list = [args.ip_cli, args.ip_srv]
    lock = threading.Lock() # 初始化锁
    # 监听两个网口
    t1 = threading.Thread(target=thread_sniff, args=(0,))
    t2 = threading.Thread(target=thread_sniff, args=(1,))
    t1.start()
    t2.start()
    

def main():
    middle()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='cpu_run.py')
    parser.add_argument('--iface_cli', type=str, default='veth1', help='interface to send packets')
    parser.add_argument('--iface_srv', type=str, default='veth2', help='interface to receive packets')
    parser.add_argument('--ip_cli', type=str, default='10.0.1.10', help='ip address of client')
    parser.add_argument('--ip_srv', type=str, default='10.0.1.213', help='ip address of server')
    args = parser.parse_args()
    main()