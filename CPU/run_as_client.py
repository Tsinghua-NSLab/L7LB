#! 终端运行的发包程序

import argparse
import sys
import socket
import random
import struct
import time
import datetime

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, get_if_addr
from scapy.all import Packet, sniff, srp1, sr1
from scapy.all import Ether, IP, UDP, TCP, ICMP

# 全局变量
args = None # 命令解析结果
origin_ip_pkt = None # 固定3层报文
send_iface = None
recv_iface = None
# 记录seq\ack的值
client_seq = 100
client_ack = 0
server_seq = 10
server_ack = 0
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

def client_back(back_p):
    global client_ack, client_seq, origin_ip_pkt, total_send_pkt, total_recv_pkt, args, send_iface
    print("Recv a back packet")
    back_p.show()
    if (TCP not in back_p) or (back_p[TCP].flags & RST):
        return
    # 收到SYN+ACK报文后, 回复ACK, 同时开始发送数据
    elif (back_p[TCP].flags & ACK) and (back_p[TCP].flags & SYN):
        print("=== Receive a SYN+ACK packet, send an ACK packet")
        # print_nop()
        # back_p.show()
        # 保存ack值
        client_ack = back_p[TCP].seq + 1
        client_seq += 1
        # 发送ACK报文
        pkt = origin_ip_pkt / TCP(sport=args.sport, dport=args.dport, flags='A', seq=client_seq, ack=client_ack)
        sendp(pkt, iface=send_iface, verbose=False)
        # 尝试发送一个数据并监听回复
        pkt = origin_ip_pkt / TCP(sport=args.sport, dport=args.dport, flags='A', seq=client_seq, ack=client_ack)
        pkt = pkt / "Hello World"
        client_seq += len("Hello World")
        sendp(pkt, iface=send_iface, verbose=False)
        total_send_pkt += 1 # 发出了一个数据包
    elif back_p[TCP].flags & ACK:
        # print_nop()
        # back_p.show()
        # 收到ACK报文后, 向前推送数据的发送
        print("=== ACK for %d with ack %d" % (total_recv_pkt, back_p[TCP].ack))
        total_recv_pkt += 1
    
        while total_send_pkt - total_recv_pkt < 5 and total_send_pkt < 20:
            pkt = origin_ip_pkt / TCP(sport=args.sport, dport=args.dport, flags='A', seq=client_seq, ack=client_ack)
            pkt = pkt / ("DATA" + str(total_send_pkt))    
            client_seq += len("DATA" + str(total_send_pkt))
            print("--- Send a packet with seq %d and ack %d with total %d (S) / %d (R)" % (client_seq, client_ack, total_send_pkt, total_recv_pkt))
            sendp(pkt, iface=send_iface, verbose=False)
            total_send_pkt += 1
    else:
        print("A Strange TCP packet\n")


# Client主动创建TCP报文完成SYN\ACK握手后发包
def client():
    global origin_mac_pkt, send_iface, origin_ip_pkt, client_seq, client_ack, args
    send_iface = get_if(args.iface_send)
    source = get_if_hwaddr(send_iface)
    origin_mac_pkt = Ether(src='de:ef:cb:7c:8a:2e', dst='52:73:65:43:ad:8e', type = 0x0800 )
    # 构造PING网包
    ping_pkt = origin_mac_pkt / IP(src=args.src, dst=args.dst) / ICMP()
    sendp(ping_pkt, iface=send_iface, verbose=False)

    # 构建标准的IP报文--将会保持不变
    origin_ip_pkt = origin_mac_pkt / IP(src=args.src, dst=args.dst)
    # SYN报文
    pkt = origin_ip_pkt / TCP(sport=args.sport, dport=args.dport, flags='S', seq=client_seq, ack=0)
    sendp(pkt, iface=send_iface, verbose=False)
    sniff(iface = send_iface, lfilter=lambda pkt: pkt[Ether].src != origin_mac_pkt.src,  prn = client_back) # 监听收到的报文

def server_back(pkt):
    # print("======RECV======")
    # pkt.show()
    # print_nop()

    global recv_iface, server_seq, server_ack
    if (TCP not in pkt) or (pkt[TCP].flags & RST):
        return
    # 收到SYN报文后回复SYN+ACK报文
    if (pkt[TCP].flags & SYN) and (pkt[TCP].flags & ACK == 0):
        # 构造对应的SYN+ACK报文
        server_ack = pkt[TCP].seq + 1
        new_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='SA', seq= server_seq, ack=pkt[TCP].seq + 1)
        print("=== Receive a SYN packet, send a SYN+ACK packet")
        # print_nop()
        # new_pkt.show()
        # print_nop()
        send(new_pkt, iface=recv_iface, verbose=False)
    elif TCP in pkt and len(pkt[TCP].payload) != 0:
        # 收到其他网包, 直接回复ACK
        new_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='A', seq= server_seq, ack=pkt[TCP].seq + 1)
        # print_nop()
        # print("Back an ACK")
        # new_pkt.show()
        # print_nop()
        send(new_pkt, iface=recv_iface, verbose=False)
        print("=== Receive a packet with seq %d, send an ACK packet" % pkt[TCP].seq)

# Server监听网卡, 收到SYN报文后回复ACK报文, 收到相关报文后都进行ACK回复
def server():
    global origin_mac_pkt, recv_iface
    recv_iface = get_if(args.iface_recv)
    source = get_if_hwaddr(recv_iface)
    origin_mac_pkt = Ether(src=source, dst='ff:ff:ff:ff:ff:ff', type = 0x0800 )
    print("Drop the src mac %s" % origin_mac_pkt.src)
    # 屏蔽所有发送出去的网包
    sniff(iface = recv_iface, lfilter=lambda pkt: pkt[Ether].src != origin_mac_pkt.src,  prn = server_back)

def main():
    if args.role == 'client':
        client()
    elif args.role == 'server':
        server()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='endhost_run.py')
    parser.add_argument('--iface_send', type=str, default='veth2', help='interface to send packets')
    parser.add_argument('--iface_recv', type=str, default='veth1', help='interface to receive packets')
    parser.add_argument('--role', type=str, default='client', help='client/server')
    parser.add_argument('--src', type=str, default='10.0.1.10', help='source ip')
    parser.add_argument('--dst', type=str, default='10.0.1.213',   help='destination IP')
    parser.add_argument('--sport', type=int, default=12345, help='source port')
    parser.add_argument('--dport', type=int, default=5201, help='destination port')

    args = parser.parse_args()
    main()