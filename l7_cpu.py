# -*- coding: utf-8 -*- 
#  终端运行的发包程序

import argparse
import sys
import socket
import random
import struct
import time
import datetime
import threading

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, get_if_addr
from scapy.all import Packet, sniff, srp1, sr1
from scapy.all import Ether, IP, UDP, TCP, ARP, ICMP


# 配置: 单次发送的最大信息数
SEND_STEP = 10

# session常量
SESSION_STATE_CLI_SYN = 0x01
SESSION_STATE_CLI_ACK = 0x02
SESSION_STATE_SRV_SYN = 0x04 # SRV端发起了建链
SESSION_STATE_SRV_ACK = 0x10 # SRV端的建链完成了
SESSION_STATE_DONE = 0x20    # 

# TCP-Flag常量
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


DEBUG_CHENGJUN = False

def print_nop():
    print("================")

# 搜索端口列表, 确认端口为有意义的端口
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

# 得到新的TCP options(删除timestamp!)
def get_tcp_options_wo_ts(pkt):
    new_options = []
    for option in pkt[TCP].options:
        if option[0] == 'Timestamp':
            continue # 删除timestamp(因为不知道如何回应)
        else:
            new_options.append(option)
    return new_options


class L7CPU:
    # 记录VIP到DIP的映射(在实际场景中, 我们并不是通过这种简单的查表完成的映射, 而要基于payload完成查表)
    #    实际使用中要把get_DIP_Port函数替换成真正的查表函数
    VIP2DIP = [
        ["10.0.1.3:1122", "10.0.1.2:22"],
        ["10.0.1.3:3322", "10.0.1.3:22"]
    ]

    def get_DIP_Port(self, vip ,vport, payload=""):
        # 实际使用中要把payload作为参数传输, 根据payload查找到真正的dip和dport
        vip_val = vip + ":" + str(vport)
        for vip_items in self.VIP2DIP:
            if vip_val == vip_items[0]:
                # 我们找到了vip的结果
                dip, dport = vip_items[1].split(":")
                return dip, int(dport)

    def get_VIP_Port(self, dip, dport):
        dip_val = dip + ":" + str(dport)
        for dip_items in self.VIP2DIP:
            if dip_val == dip_items[1]:
                # 我们找到了vip的结果
                vip, vport = dip_items[0].split(":")
                return vip, int(vport)

    # 用于debug调试, 记录所有的发送网包等
    output_pkts = []
    total_send_pkt = 0
    total_recv_pkt = 0
    
    # 记录接口信息
    cpu_iface = None # CPU的interface
    cpu_mac = None # CPU端口的MAC地址

    # 记录session的相关记录
    session_state_map = {} # key: flow (cli_ip, cli_port, v_ip, v_port), value: session_state
    session_cli_seq = {}   # 记录cli的初始seq (从cli-->middle的视角)
    session_cli_ack = {}   # 记录cli的初始ack
    session_srv_seq = {}   # 记录srv的初始seq (从middle-->srv的视角)
    session_srv_ack = {}   # 记录srv的初始ack
    session_dip_port = {}  # 记录该流对应的DIP和DPORT (因为原来的目的地址是vip+vport)
    session_pkts = {}      # 记录从cli发出的包, 尚未完成相关处理(注意去重以避免重传影响的问题)
    done_pkts = {}         # 已经处理完毕的包(防止重复处理)

    cli_dip_2_flow = {} # 根据cli_ip, cli_port, d_ip, d_port找到对应的flow(这里的flow是cli_ip, cli_port, v_ip, v_port)



    def __init__(self, iface="veth251", mac="a0:a0:a0:a0:a0:a0"):
        self.cpu_iface = iface
        self.cpu_mac = mac

    def get_new_pkt_from_cli(self, pkt, flow):
        '''把cli->VIP的包修改成cli->DIP的包 (修改MAC、IP、Port等, 调用了之前存储的session信息)'''
        new_pkt = pkt.copy()
        # 修改网包的MAC层
        new_pkt[Ether].src = self.cpu_mac
        new_pkt[Ether].dst = pkt[Ether].src # 交换源和目的地址
        # 把DIP更新为VIP
        new_pkt[IP].dst = self.session_dip_port[flow][0]
        new_pkt[IP].dport = self.session_dip_port[flow][1]
        # 更新TCP层的Seq和ACK
        new_pkt[TCP].seq = self.session_srv_seq[flow] + pkt[TCP].seq - self.session_cli_seq[flow]
        new_pkt[TCP].ack = self.session_srv_ack[flow] + pkt[TCP].ack - self.session_cli_ack[flow]
        print("The flow is ", flow)        
        print("=== The from cli seq map is %d -> %d with srv_seq %d amd cli_seq %d" % (pkt[TCP].seq, new_pkt[TCP].seq, self.session_srv_seq[flow], self.session_cli_seq[flow]))
        print("=== The from cli ack map is %d -> %d with srv_ack %d amd cli_ack %d" % (pkt[TCP].ack, new_pkt[TCP].ack, self.session_srv_ack[flow], self.session_cli_ack[flow]))
        del new_pkt[IP].chksum, new_pkt[TCP].chksum
        return new_pkt 

    def get_new_pkt_from_srv(self, pkt, flow):
        '''修改网包信息(该网包是srv-->CPU), 修改成匹配(CPU->cli)的seq/ack的网包
              TODO: 该函数没有把DIP修改为VIP!
        '''
        new_pkt = pkt.copy()
        new_pkt[TCP].seq = self.session_cli_ack[flow] + pkt[TCP].seq - self.session_srv_ack[flow]
        new_pkt[TCP].ack = self.session_cli_seq[flow] + pkt[TCP].ack - self.session_srv_seq[flow]
        print("=== The from srv seq map is %d -> %d with srv_seq %d amd cli_seq %d" % (pkt[TCP].seq, new_pkt[TCP].seq, self.session_srv_ack[flow], self.session_cli_ack[flow]))
        print("=== The from srv ack map is %d -> %d with srv_ack %d amd cli_ack %d" % (pkt[TCP].ack, new_pkt[TCP].ack, self.session_srv_seq[flow], self.session_cli_seq[flow]))
        del new_pkt[IP].chksum, new_pkt[TCP].chksum
        return new_pkt

    def middle_out_pkt(self, pkt):
        '''封装发送网包的命令, 采用debug模式的时候把网包append到本地列表中'''
        self.total_send_pkt += 1
        if DEBUG_CHENGJUN:
            self.output_pkts.append(pkt)
        else:
            sendp(pkt, iface=self.cpu_iface, verbose=False)

    def proxy_back(self, pkt):
        '''收到一个网包, 根据网包信息进行处理'''
        self.total_recv_pkt += 1
        if (ARP in pkt) or (ICMP in pkt):
            # ARP网包, ICMP网包, 直接忽略
            print("=== [INFO] Receive a ARP or ICMP packet, IGNORE it")
            return
        elif (TCP in pkt) and (pkt[TCP].flags & RST):
            # 对于RST报文, 直接丢弃
            print("=== [INFO] Receive a RST packet, IGNORE it")
            return
        elif (TCP in pkt):
            self.proxy_deal_with_tcp(pkt)
        else:
            print_nop()
            print("A Strange packet")
            pkt.show()
            print_nop()

    def proxy_deal_with_tcp(self, pkt):
        '''处理TCP网包'''
        syn_signal = ((pkt[TCP].flags & SYN) == SYN)
        ack_signal = ((pkt[TCP].flags & ACK) == ACK) # 记录syn和ack标志

        # 查找flow是否已经有了相应的session记录        
        flow = pkt[IP].src + ":" + str(pkt[TCP].sport) + " -> " + pkt[IP].dst + ":" + str(pkt[TCP].dport)
        # reverse flow是DIP-->cli, 我们记录了cli->DIP
        cli_dip_flow = pkt[IP].dst + ":" + str(pkt[TCP].dport) + " -> " + pkt[IP].src + ":" + str(pkt[TCP].sport) 
        if cli_dip_flow in self.cli_dip_2_flow:
            reverse_flow = self.cli_dip_2_flow[cli_dip_flow]
        else:
            reverse_flow = "xxxx"
        flow_match = 0 # 0: 没有任何匹配, 1: 匹配了flow(意味着这条流是从cli-->srv), 2: 匹配了reverse_flow(srv-->cli)
        if flow in self.session_state_map:
            flow_match += 1
        if reverse_flow in self.session_state_map:
            flow_match += 2
        assert(flow_match != 3) # 一条flow只可能是上面两种情况之一
        
        # 得到了SYN报文, 总是返回相应的SYN ACK网包(可以应对重复SYN网包)
        if syn_signal and not ack_signal:
            print("=== Receive a SYN packet, send SYN+ACK")
            if flow_match == 0:
                middle_seq = 100000 # TODO: 这里使用的seq可以是随机的
            elif flow_match == 1:
                middle_seq = self.session_cli_ack[flow]
            else:
                middle_seq = 1000
                print("=== [ERROR] flow_match == 2, but we receive a SYN packet, this is impossible")
            new_options = get_tcp_options_wo_ts(pkt)
            new_pkt = Ether(src=self.cpu_mac, dst=pkt[Ether].src, type = pkt[Ether].type) / IP(src=pkt[IP].dst, dst=pkt[IP].src ) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, seq = middle_seq, ack = pkt[TCP].seq+1, flags="SA", options = new_options) 
            # 更新checksum
            del new_pkt[IP].chksum, new_pkt[TCP].chksum
            self.middle_out_pkt(new_pkt) # 返回一个对应的SYN_ACK包
        
        # 更新flow状态机
        if flow_match == 0:
            # 该流尚未进行记录
            if syn_signal and not ack_signal:            
                # 更新session记录 (只对SYN包认为是有新流出现)
                self.session_state_map[flow] = SESSION_STATE_CLI_SYN
                self.session_cli_seq[flow] = pkt[TCP].seq
                self.session_cli_ack[flow] = middle_seq # 记录下来对应cli->CPU的链接的seq和ack信息
                self.session_pkts[flow] = [pkt.copy()] # 记录下第一个SYN包
            else:
                print("=== A flow with no session but recv a packet without SYN!")
                pkt.show()
        elif flow_match == 1:
            flow_state = self.session_state_map[flow]
            # 正向流
            if ( flow_state & SESSION_STATE_CLI_ACK == 0) and (ack_signal and syn_signal == 0):
                # 该流已经完成了建链过程, 但尚未收到过ACK和payload等报文; 只有ACK报文才会进入这个分支
                # 存储中的数据, 防止出现重传的报文
                new_pkt_signal = True
                for old_pkt in self.session_pkts[flow]:
                    if old_pkt[TCP].seq == pkt[TCP].seq and old_pkt[TCP].ack == pkt[TCP].ack and len(old_pkt[TCP].payload) == len(pkt[TCP].payload):
                        new_pkt_signal = False
                        break
                if new_pkt_signal:
                    self.session_pkts[flow].append(pkt) # 增加网包的记录
                self.session_state_map[flow] |= SESSION_STATE_CLI_ACK # 更新状态到CLI已经完成建链
            elif flow_state & SESSION_STATE_SRV_SYN != SESSION_STATE_SRV_SYN:
                # 收到过ACK网包, 还没到达DONE状态; 所有的包都要缓存下来
                self.session_pkts[flow].append(pkt) # 增加网包的记录
                # 如果缓存的网包数量足够多, 进入到下一个状态, 尝试向srv发起链接请求
                if len(self.session_pkts[flow]) >= 3:
                    # 发送一个包出去
                    assert( len(self.session_pkts[flow]) > 0 )
                    new_pkt = self.session_pkts[flow].pop(0)
                    print("=== SEND A SYNC PACKET TO SRV ===")
                    assert(new_pkt[TCP].flags & SYN) # 首包必然是SYN包
                    # 更新报文MAC
                    new_pkt[Ether].src, new_pkt[Ether].dst = self.cpu_mac, new_pkt[Ether].src # 交换MAC地址
                    # 更新目的IP和目的端口, 并记录下来
                    dip, dport = self.get_DIP_Port(new_pkt[IP].dst, new_pkt[TCP].dport) # 找到DIP和DPORT
                    new_pkt[IP].dst, new_pkt[TCP].dport = dip, dport
                    self.session_dip_port[flow] = (dip, dport) # 记录原来的流映射后的DIP和DPORT的信息
                    cli_dip_flow = new_pkt[IP].src + ":" + str(new_pkt[TCP].sport) + " -> " + new_pkt[IP].dst + ":" + str(new_pkt[TCP].dport)
                    self.cli_dip_2_flow[cli_dip_flow] = flow # 记录(cli, dip)到(cli, vip)的映射关系
                    self.session_srv_seq[flow] = new_pkt[TCP].seq # 记录下来对应CPU-->srv的链接的seq信息
                    # 更新包的options
                    new_pkt[TCP].options = get_tcp_options_wo_ts(new_pkt)
                    # 更新checksum等变量信息
                    del new_pkt[IP].len, new_pkt[IP].chksum, new_pkt[TCP].dataofs, new_pkt[TCP].chksum
                    # 把首包发送给srv
                    self.middle_out_pkt(new_pkt) 
                    self.session_state_map[flow] |= SESSION_STATE_SRV_SYN
            elif flow_state & SESSION_STATE_DONE == SESSION_STATE_DONE:
                # 该流已经完成了相应的映射处理, 对网包直接进行转发(只需要更新ACK和SEQ); 
                # CRITICAL: 这里需要一个保序处理, 只有在把CPU上的缓存网包都发送完毕后才能发送后续的网包
                self.session_pkts[flow].append(pkt) # 增加网包的记录
                # 缓存的网包要完成映射后才能发送
                for _ in range(0, SEND_STEP): # 快点把缓存的网包都发送完毕
                    if len(self.session_pkts[flow]) == 0: 
                        break
                    new_pkt = self.get_new_pkt_from_cli( self.session_pkts[flow][0], flow)
                    self.middle_out_pkt(new_pkt) # 发送出去缓存的client网包
                    self.session_pkts[flow].pop(0)
            else:
                self.session_pkts[flow].append(pkt) # 增加网包的记录

        elif flow_match == 2:
            flow_state = self.session_state_map[reverse_flow]
            # 反向流
            print("=== We receive a packet from srv ===")
            if flow_state & SESSION_STATE_DONE == SESSION_STATE_DONE:
                # 该流的映射已经完成, 反向的包直接修改后发送即可
                # 理论上, 这里我们不可能再收到包了!
                print("=== [ERROR] We receive a packet from srv after the session is offload! ===")
                new_pkt = self.get_new_pkt_from_srv(pkt, reverse_flow)
                # new_pkt.show()
                self.middle_out_pkt(new_pkt) # 发送到对端就行
            else:
                # 我们必然处在SRV_SYN置位后的状态
                assert(flow_state & SESSION_STATE_SRV_SYN == SESSION_STATE_SRV_SYN)
                # 我们必然是收到了一个SYN_ACK的包
                print("=== RECEIVE A SYNC_ACK PACKET FROM SRV ===")
                # 这里SYN ACK包处理可能存在问题? 是否有可能SYN ACK丢包, 但我们收到了后续的包?
                assert(pkt[TCP].flags & SYN and pkt[TCP].flags & ACK)
                # 更新session记录
                self.session_srv_ack[reverse_flow] = pkt[TCP].seq # 收到的SYN_ACK网包的seq就是CPU->srv的ack
                self.session_state_map[reverse_flow] |= SESSION_STATE_DONE
                for _ in range(0, SEND_STEP): # 快点把缓存的网包都发送完毕
                    if len(self.session_pkts[reverse_flow]) == 0: 
                        break
                    new_pkt = self.get_new_pkt_from_cli(self.session_pkts[reverse_flow][0], reverse_flow)
                    self.middle_out_pkt(new_pkt) # 发送出去缓存的client网包
                    self.session_pkts[reverse_flow].pop(0)
                # TODO: session已经建立完毕, 需要下放相关配置到switch


    def listen(self):
        '''监听网络端口, 作为proxy, 收到SYN报文后, 完成相关建链记录相关信息'''
        sniff(iface = self.cpu_iface, 
            lfilter=lambda pkt: (pkt[Ether].src != self.cpu_mac), 
            prn = lambda pkt: self.proxy_back(pkt)) # 源mac地址是CPU的mac地址, 说明是从CPU发出的报文, 我们不在乎这些报文    

def main(args):
    cpu_iface = get_if(args.iface) # 检查端口是否存在
    if cpu_iface == None:
        print("[ERROR] No such interface" + args.iface)
        exit(1)
    cpu_mac = get_if_hwaddr(cpu_iface) # 检查端口的MAC地址是否一致
    if args.iface_mac != cpu_mac:
        print("[ERROR] CPU MAC address of interface " + args.iface + " is not " + args.iface_mac + ", but " + cpu_mac)
    cpu_main = L7CPU(cpu_iface, cpu_mac)
    cpu_main.middle()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='cpu_run.py')
    parser.add_argument('--iface', type=str, default='veth251', help='interface to send/recv packets')
    parser.add_argument('--iface_mac', type=str, default='a0:a0:a0:a0:a0:a0', help='interface mac')
    args = parser.parse_args()
    main(args)