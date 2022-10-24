# -*- coding: utf-8 -*-
from l7_cpu import *
import unittest
import random

class TestL7CPU(unittest.TestCase):
    CLI_IP = '10.0.0.2'
    CLI_PORT = 5000
    VIP = '10.0.1.3'
    VPORT = 1122
    DIP = '10.0.1.2'
    DPORT = 22

    def test_dv_ip_map(self):
        cpu_main = L7CPU()
        dip, dport = cpu_main.get_DIP_Port(self.VIP, self.VPORT)
        self.assertEqual(dip, self.DIP)
        self.assertEqual(dport, self.DPORT)
        vip, vport = cpu_main.get_VIP_Port(dip, dport)
        self.assertEqual(vip, self.VIP)
        self.assertEqual(vport, self.VPORT)
    
    def test_get_syn_ack(self):
        cpu_main = L7CPU()
        cpu_main.cpu_mac = "00:00:00:00:00:01"
        src_mac = "00:00:00:00:00:02"
        cli_seq = random.randint(0, 1000000)
        ORIGIN_SEQ = cli_seq
        # 发送一个CLI SYN包
        cli_syn_pkt = Ether(src=src_mac, dst=cpu_main.cpu_mac)/IP(src=self.CLI_IP, dst=self.VIP)/TCP(sport=self.CLI_PORT, dport = self.VPORT, seq = cli_seq, ack = 0, flags="S")
        cpu_main.proxy_back(cli_syn_pkt)
        self.assertEqual(len(cpu_main.output_pkts), 1)
        pkt = cpu_main.output_pkts[0]
        self.assertEqual(pkt[Ether].src, cpu_main.cpu_mac)
        self.assertEqual(pkt[Ether].dst, src_mac)
        self.assertEqual(pkt[TCP].flags, "SA")
        self.assertEqual(pkt[IP].src, self.VIP)
        self.assertEqual(pkt[IP].dst, self.CLI_IP)
        self.assertEqual(pkt[TCP].sport, self.VPORT)
        self.assertEqual(pkt[TCP].dport, self.CLI_PORT)
        self.assertEqual(pkt[TCP].ack, cli_seq + 1)
        cli_ack = pkt[TCP].seq
        cli_seq += 1
        # 发送一个CLI ACK包
        cli_ack_pkt = Ether(src=src_mac, dst=cpu_main.cpu_mac)/IP(src=self.CLI_IP, dst=self.VIP)/TCP(sport=self.CLI_PORT, dport = self.VPORT,  seq = cli_seq, ack = cli_ack, flags="A")
        cpu_main.proxy_back(cli_ack_pkt)
        # 发送2个CLI的payload包
        payload1 = "hello world, I am 1"
        payload2 = "hello world, I am 2"
        cli_payload_pkt = cli_ack_pkt / payload1
        cpu_main.proxy_back(cli_payload_pkt)

        cli_payload_pkt2 = cli_ack_pkt / payload2
        cli_payload_pkt2[TCP].seq = cli_payload_pkt[TCP].seq + len(cli_payload_pkt[TCP].payload)
        cpu_main.proxy_back(cli_payload_pkt2)

        # 当前后端应该收到一个DIP的SYN包(尚未建链完成)
        self.assertEqual(len(cpu_main.output_pkts), 2)
        dip_pkt = cpu_main.output_pkts[1]
        self.assertEqual(dip_pkt[Ether].src, cpu_main.cpu_mac)
        self.assertEqual(dip_pkt[IP].src, self.CLI_IP)
        self.assertEqual(dip_pkt[TCP].sport, self.CLI_PORT)
        self.assertEqual(dip_pkt[IP].dst, self.DIP)
        self.assertEqual(dip_pkt[TCP].dport, self.DPORT)
        self.assertEqual(dip_pkt[TCP].flags, "S")
        self.assertEqual(dip_pkt[TCP].seq, ORIGIN_SEQ)

        d_seq = random.randint(0, 1000000)
        # 回复一个DIP的SYN ACK包
        dip_syn_ack_pkt = Ether(dst=cpu_main.cpu_mac)/IP(src=self.DIP, dst=self.CLI_IP)/TCP(sport=self.DPORT, dport = self.CLI_PORT, seq = d_seq , ack = dip_pkt[TCP].seq+1, flags="SA")
        cpu_main.proxy_back(dip_syn_ack_pkt)

        # 当前后端应该收到一个CLI的ACK包和CLI的所有payload包(2个payload包)
        self.assertEqual(len(cpu_main.output_pkts), 2+1+2)
        
        # 检查seq和ack的记录
        flow = self.CLI_IP + ":" + str(self.CLI_PORT) + " -> " + self.VIP + ":" + str(self.VPORT)
        proxy_cli_seq = cpu_main.session_cli_seq[flow]
        proxy_cli_ack = cpu_main.session_cli_ack[flow]
        proxy_srv_seq = cpu_main.session_srv_seq[flow]
        proxy_srv_ack = cpu_main.session_srv_ack[flow]
        self.assertEqual(proxy_cli_seq, ORIGIN_SEQ)
        self.assertEqual(proxy_cli_ack, 100000)
        self.assertEqual(proxy_srv_seq, ORIGIN_SEQ)
        self.assertEqual(proxy_srv_ack, d_seq)

        dip_ack_pkt = cpu_main.output_pkts[2]
        dip_payload_pkt1 = cpu_main.output_pkts[3]
        dip_payload_pkt2 = cpu_main.output_pkts[4]
        for i in range(2, 5):
            pkt = cpu_main.output_pkts[i]
            self.assertEqual(pkt[Ether].src, cpu_main.cpu_mac)
            self.assertEqual(pkt[IP].src, self.CLI_IP)
            self.assertEqual(pkt[TCP].sport, self.CLI_PORT)
            self.assertEqual(pkt[IP].dst, self.DIP)
            self.assertEqual(pkt[TCP].dport, self.DPORT)
        # 检查数据的payload情况, 发出去的两个网包是否正是目标网包?
        self.assertEqual(dip_ack_pkt[TCP].flags, "A")
        self.assertEqual((dip_payload_pkt1[TCP].payload.load).decode("utf-8"), str(payload1))
        self.assertEqual((dip_payload_pkt2[TCP].payload.load).decode("utf-8"), str(payload2))

        self.assertEqual(dip_ack_pkt[TCP].seq, cli_ack_pkt[TCP].seq)
        self.assertEqual(dip_ack_pkt[TCP].ack, d_seq)
        self.assertEqual(dip_payload_pkt2[TCP].seq, dip_ack_pkt[TCP].seq+len(payload1))
        
if __name__ == '__main__':
    unittest.main()
