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
    new_pkt = pkt.copy()
    new_pkt[TCP].seq = session_srv_seq[flow] + pkt[TCP].seq - session_cli_seq[flow]
    new_pkt[TCP].ack = session_srv_ack[flow] + pkt[TCP].ack - session_cli_ack[flow]
    print("=== The from cli seq map is %d -> %d with srv_seq %d amd clie_seq %d" % (pkt[TCP].seq, new_pkt[TCP].seq, session_srv_seq[flow], session_cli_seq[flow]))
    print("=== The from cli ack map is %d -> %d with srv_ack %d amd clie_ack %d" % (pkt[TCP].ack, new_pkt[TCP].ack, session_srv_ack[flow], session_cli_ack[flow]))
    del new_pkt[IP].chksum
    del new_pkt[TCP].chksum
    return new_pkt 

def get_new_pkt_from_srv(pkt, flow):
    global session_srv_seq, session_srv_ack, session_cli_seq, session_cli_ack, session_state_map, session_pkts, done_pkts, total_send_pkt, total_recv_pkt
    # 修改网包信息(该网包是srv-->CPU), 修改成匹配(CPU->cli)的seq/ack的网包
    new_pkt = pkt.copy()
    new_pkt[TCP].seq = session_cli_ack[flow] + pkt[TCP].seq - session_srv_ack[flow]
    new_pkt[TCP].ack = session_cli_seq[flow] + pkt[TCP].ack - session_srv_seq[flow]
    print("=== The from srv seq map is %d -> %d with srv_seq %d amd clie_seq %d" % (pkt[TCP].seq, new_pkt[TCP].seq, session_srv_ack[flow], session_cli_ack[flow]))
    print("=== The from srv ack map is %d -> %d with srv_ack %d amd clie_ack %d" % (pkt[TCP].ack, new_pkt[TCP].ack, session_srv_seq[flow], session_cli_seq[flow]))
    del new_pkt[IP].chksum
    del new_pkt[TCP].chksum
    return new_pkt


def middle_back(pkt, from_iface_idx):
    global iface_list, ipv4_list, lock, session_srv_seq, session_srv_ack, session_cli_seq, session_cli_ack, session_state_map, session_pkts, done_pkts, total_send_pkt, total_recv_pkt

    if ( (ARP in pkt) and (pkt[ARP].psrc == ipv4_list[from_iface_idx]) ) or ((ICMP in pkt) and (pkt[IP].src == ipv4_list[from_iface_idx])):
        # ARP网包的源IP地址, ICMP的源IP地址是对应端口的IP地址, 转发到另一个端口
        print("=== Receive a ARP or ICMP packet, forward to %s" % iface_list[1 - from_iface_idx])
        sendp(pkt, iface=iface_list[1 - from_iface_idx], verbose=False)
        return
    elif (ARP in pkt) or (ICMP in pkt):
        # ARP网包, ICMP网包, 并不是从对应端口发出的
        # print("=== Receive a ARP or ICMP packet, drop")
        return
    elif (TCP in pkt) and (pkt[TCP].flags & RST):
        # 对于RST报文, 直接丢弃
        # print("=== Receive a RST packet, drop")
        return
    elif (IP in pkt) and (pkt[IP].dst == ipv4_list[from_iface_idx]):
        # 对于IP报文, IP的dst是对应端口的IP地址, 那么就不需要处理(已经到达对端了)
        return
    elif (TCP in pkt):
        # 对于SYN报文, 返回建链信息(SYN+ACK), 记录相关状态!
        syn_signal = ((pkt[TCP].flags & SYN) == SYN)
        ack_signal = ((pkt[TCP].flags & ACK) == ACK) # 记录syn和ack标志

        # 查找flow是否已经有了相应的session记录        
        flow = pkt[IP].src + ":" + str(pkt[TCP].sport) + " -> " + pkt[IP].dst + ":" + str(pkt[TCP].dport)
        reverse_flow = pkt[IP].dst + ":" + str(pkt[TCP].dport) + " -> " + pkt[IP].src + ":" + str(pkt[TCP].sport)
        flow_match = 0 # 0: 没有任何匹配, 1: 匹配了flow(意味着这条流是从cli-->srv), 2: 匹配了reverse_flow(srv-->cli)
        if flow in session_state_map:
            flow_match += 1
        if reverse_flow in session_state_map:
            flow_match += 2
        assert(flow_match != 3) # 一条flow只可能是上面两种情况之一
        
        # TODO: 管理网包的处理状态机
        if flow_match == 0:
            # 该流尚未进行记录
            if syn_signal and not ack_signal:
                # 得到了SYN报文
                print("=== Receive a SYN packet, send SYN+ACK")
                # 计算Options情况
                new_options = []
                for option in pkt[TCP].options:
                    if option[0] == 'Timestamp':
                        continue # 删除timestamp(因为不知道如何回应)
                    else:
                        new_options.append(option)
                    
                middle_seq = 100000
                new_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src, type = pkt[Ether].type) / IP(src=pkt[IP].dst, dst=pkt[IP].src ) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, seq = middle_seq, ack = pkt[TCP].seq+1, flags="SA", options = new_options) 
                # 更新checksum
                del new_pkt[IP].chksum
                del new_pkt[TCP].chksum
                sendp(new_pkt, iface=iface_list[from_iface_idx], verbose=False) # 返回一个对应的SYN_ACK包
                # 更新session记录
                lock.acquire()
                session_state_map[flow] = SESSION_STATE_CLI_SYN
                session_cli_seq[flow] = pkt[TCP].seq
                session_cli_ack[flow] = middle_seq # 记录下来对应cli->CPU的链接的seq和ack信息
                session_pkts[flow] = [pkt.copy()]
                lock.release()
            else:
                print("=== A flow with no session and not a SYN packet!")
                pkt.show()
        elif flow_match == 1:
            # 正向流
            lock.acquire()
            if (session_state_map[flow] & SESSION_STATE_CLI_ACK == 0) and (ack_signal and syn_signal == 0):
                # 该流已经完成了建链过程, 但尚未收到过ACK和payload等报文; 只有ACK报文才会进入这个分支
                # 如果网包并不是retransmission, 那么就存储起来
                new_pkt_signal = True
                for old_pkt in session_pkts[flow]:
                    if old_pkt[TCP].seq == pkt[TCP].seq:
                        new_pkt_signal = False
                        break
                if new_pkt_signal:
                    session_pkts[flow].append(pkt) # 增加网包的记录
                session_state_map[flow] |= SESSION_STATE_CLI_ACK # 更新状态
            elif session_state_map[flow] & SESSION_STATE_DONE == SESSION_STATE_DONE:
                # 该流已经完成了相应的映射处理, 对网包直接进行转发(只需要更新ACK和SEQ); 
                # CRITICAL: 这里需要一个保序处理, 只有在把CPU上的缓存网包都发送完毕后才能发送后续的网包
                if len(session_pkts[flow]) == 0:
                    new_pkt = get_new_pkt_from_cli(pkt, flow)
                    sendp(new_pkt, iface=iface_list[1-from_iface_idx], verbose=False) # 转发到另一个端口
                else:
                    session_pkts[flow].append(pkt) # 增加网包的记录
                    # 缓存的网包要完成映射后才能发送
                    for i in range(0, SEND_STEP): # 快点把缓存的网包都发送完毕
                        if len(session_pkts[flow]) == 0: 
                            break
                        new_pkt = get_new_pkt_from_cli(session_pkts[flow][0], flow)
                        sendp(new_pkt, iface=iface_list[1-from_iface_idx], verbose=False) # 发送到另一个端口
                        session_pkts[flow].pop(0)
            elif session_state_map[flow] & SESSION_STATE_SRV_SYN != SESSION_STATE_SRV_SYN:
                # 收到过ACK网包, 还没到达DONE状态; 所有的包都要缓存下来
                session_pkts[flow].append(pkt) # 增加网包的记录
                # 如果缓存的网包数量足够多, 进入到下一个状态, 尝试向srv发起链接请求
                if len(session_pkts[flow]) >= 3:
                    # 发送一个包出去
                    assert( len(session_pkts[flow]) > 0 )
                    new_pkt = session_pkts[flow].pop(0)
                    print("=== SEND A SYNC PACKET TO SRV ===")
                    assert(new_pkt[TCP].flags & SYN) # 首包必然是SYN包
                    # TODO: 更新数据包的len、checksum等
                    # new_pkt.show()
                    session_srv_seq[flow] = new_pkt[TCP].seq # 记录下来对应CPU-->srv的链接的seq信息
                    
                    new_options = []
                    for option in new_pkt[TCP].options:
                        if option[0] == 'Timestamp':
                            continue # 删除timestamp(因为不知道如何回应)
                        else:
                            new_options.append(option)
                    new_pkt[TCP].options = new_options

                    del new_pkt[IP].len
                    del new_pkt[IP].chksum
                    del new_pkt[TCP].dataofs
                    del new_pkt[TCP].chksum
                    sendp(new_pkt, iface=iface_list[1-from_iface_idx], verbose=False) # 直接把首包发送出去, 首包为SYN包
                    session_state_map[flow] |= SESSION_STATE_SRV_SYN
            else:
                print("=== A flow with session and not a SYN packet!")
                pkt.show()
            lock.release()
        elif flow_match == 2:
            # 反向流
            print("=== We receive a packet from srv ===")
            lock.acquire()
            if session_state_map[reverse_flow] & SESSION_STATE_DONE == SESSION_STATE_DONE:
                # 该流的映射已经完成, 反向的包直接修改后发送即可
                new_pkt = get_new_pkt_from_srv(pkt, reverse_flow)
                # new_pkt.show()
                sendp(new_pkt, iface=iface_list[1-from_iface_idx], verbose=False) # 发送到对端就行
            else:
                # 我们必然处在SRV_SYN置位后的状态
                assert(session_state_map[reverse_flow] & SESSION_STATE_SRV_SYN == SESSION_STATE_SRV_SYN)
                # 我们必然是收到了一个SYN_ACK的包
                print("=== RECEIVE A SYNC_ACK PACKET FROM SRV ===")
                # pkt.show()
                assert(pkt[TCP].flags & SYN and pkt[TCP].flags & ACK)
                # 更新session记录
                session_srv_ack[reverse_flow] = pkt[TCP].seq # 收到的SYN_ACK网包的seq就是CPU->srv的ack
                session_state_map[reverse_flow] |= SESSION_STATE_DONE
            lock.release()
    else:
        print_nop()
        print("A Strange TCP packet")
        pkt.show()
        print_nop()


def thread_sniff(idx):
    global iface_name_list, iface_list, origin_mac_pkt_list
    # 对于目的MAC地址是中间设备的网包, 不进行处理
    sniff(iface = iface_list[idx], 
        lfilter=lambda pkt: (pkt[Ether].dst != origin_mac_pkt_list[idx].src) and (pkt[Ether].src != origin_mac_pkt_list[idx].src) and (pkt[Ether].src != origin_mac_pkt_list[1 - idx].src) and (pkt[Ether].dst != origin_mac_pkt_list[1 - idx].src), 
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