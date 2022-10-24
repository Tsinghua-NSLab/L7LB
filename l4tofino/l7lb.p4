/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/


#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"


struct metadata_t {
    bit<16> tcp_udp_checksum;
    bool ipv4_checksum_err;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    Checksum() udp_checksum;

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type, ig_intr_md.ingress_port) {
            (_, 250) : parse_cpu;
            (ETHERTYPE_ARP, _) : parse_arp;
            (ETHERTYPE_IPV4, _) : parse_ipv4;
            default : reject;
        }
    }

    state parse_cpu {
        pkt.extract(hdr.cpu);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        tcp_checksum.subtract({hdr.ipv4.src_addr,hdr.ipv4.dst_addr});
        udp_checksum.subtract({hdr.ipv4.src_addr,hdr.ipv4.dst_addr});
        transition select (hdr.ipv4.ihl) {
            5 : parse_ipv4_no_options;
            6 : parse_ipv4_options;
            default : accept;
        }
    }

    state parse_ipv4_options {
        // Only a single 32-bit option (e.g. router alert) is supported.
        pkt.extract(hdr.ipv4_option);
        ipv4_checksum.add(hdr.ipv4_option);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
        ig_md.ipv4_checksum_err = ipv4_checksum.verify();
        transition select(hdr.ipv4.protocol, hdr.ipv4.frag_offset) {
            (IP_PROTOCOLS_ICMP, 0) : parse_icmp;
            (IP_PROTOCOLS_TCP, 0) : parse_tcp;
            (IP_PROTOCOLS_UDP, 0) : parse_udp;
            // Do NOT parse the next header if IP packet is fragmented.
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        tcp_checksum.subtract_all_and_deposit(ig_md.tcp_udp_checksum);
        tcp_checksum.subtract({hdr.tcp.checksum});
        tcp_checksum.subtract({hdr.tcp.src_port, hdr.tcp.dst_port});
        tcp_checksum.subtract({hdr.tcp.seq_no, hdr.tcp.ack_no});
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        udp_checksum.subtract_all_and_deposit(ig_md.tcp_udp_checksum);
        udp_checksum.subtract({hdr.udp.checksum});
        udp_checksum.subtract({hdr.udp.src_port, hdr.udp.dst_port});
        transition accept;
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }



}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    Checksum() udp_checksum;

    apply {
        if(hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr});
        }
        if(hdr.tcp.isValid()){
            hdr.tcp.checksum = tcp_checksum.update(
                {hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.ack_no,
                hdr.tcp.seq_no,
                ig_md.tcp_udp_checksum});
        }
        if(hdr.udp.isValid()){
            hdr.udp.checksum = udp_checksum.update(
                {hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.udp.src_port,
                hdr.udp.dst_port});
        }
        //TODO checksum
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    Alpm(number_partitions = 1024, subtrees_per_partition = 2) algo_lpm;
    bool bypass_alpm = false;

    action nop(){

    }

    action reply_arp(bit<48> arp_mac) {
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = arp_mac;
        hdr.arp.opcode = 2;
        hdr.arp.sender_hw_addr = arp_mac;
        hdr.arp.sender_proto_addr = hdr.arp.target_proto_addr;
        hdr.arp.target_hw_addr = hdr.ethernet.src_addr;
        hdr.arp.target_proto_addr = hdr.arp.sender_proto_addr;
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action arp_miss() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table arp_table{
        key = {
            hdr.arp.opcode: exact;
            hdr.arp.target_proto_addr: exact;
        }
        actions = {
            reply_arp;
            arp_miss;
        }
        const default_action = arp_miss;
        size = 1024;
    }

    action lb_ip_hit(){
    }

    table lb_ip_look{ // NOTE: only supports tcp
        key = {
            hdr.ipv4.dst_addr : exact;
            hdr.tcp.dst_port : exact;
        }
        actions = {
            lb_ip_hit;
            nop;
        }
        const default_action = nop;
        size = 1024;
    }

    action dip_look_hit(){
    }

    table dip_look{
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.tcp.src_port : exact;
        }
        actions = {
            dip_look_hit;
            nop;
        }
        const default_action = nop;
        size = 1024;
    }

    action session_hit_out(bit<32> seqDiff, bit<32> ackDiff, bit<32> srcIP, bit<16> srcPort){
        hdr.ipv4.src_addr = srcIP;
        hdr.tcp.src_port = srcPort;
        hdr.tcp.seq_no = hdr.tcp.seq_no + seqDiff;
        hdr.tcp.ack_no = hdr.tcp.ack_no + ackDiff;
    }

    action send_to_cpu(bit<48> dst_mac, PortId_t port) {
        hdr.ethernet.dst_addr = dst_mac;
        ig_intr_tm_md.ucast_egress_port = port;
        bypass_alpm = true;
    }

    table session_out{
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            hdr.tcp.src_port: exact;
            hdr.tcp.dst_port: exact;
        }
        actions = {
            session_hit_out;
            send_to_cpu;
        }
        const default_action = send_to_cpu(176611750092960, 64);//0xa0a0a0a0a0a0
        size = 1024;
    }

    action session_hit_in(bit<32> seqDiff, bit<32> ackDiff, bit<32> dstIP, bit<16> dstPort){
        hdr.ipv4.dst_addr = dstIP;
        hdr.tcp.dst_port = dstPort;
        hdr.tcp.seq_no = hdr.tcp.seq_no + seqDiff;
        hdr.tcp.ack_no = hdr.tcp.ack_no + ackDiff;
    }

    table session_in{
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            hdr.tcp.src_port: exact;
            hdr.tcp.dst_port: exact;
        }
        actions = {
            session_hit_in;
            send_to_cpu;
        }
        const default_action = send_to_cpu(176611750092960, 64);//0xa0a0a0a0a0a0
        size = 1024;
    }


    action route(mac_addr_t srcMac, mac_addr_t dstMac, PortId_t dst_port) {
        ig_intr_tm_md.ucast_egress_port = dst_port;
        hdr.ethernet.dst_addr = dstMac;
        hdr.ethernet.src_addr = srcMac;
        ig_intr_dprsr_md.drop_ctl = 0x0;
    }

    table alpm_forward {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }

        actions = {
            route;
        }

        size = 1024;
        alpm = algo_lpm;
    }

    apply {
        if(hdr.arp.isValid()){
            arp_table.apply();
        }else{
            if(dip_look.apply().hit){
                session_out.apply();
            }
            if(lb_ip_look.apply().hit){
                session_in.apply();
            }
            if(!bypass_alpm){
                alpm_forward.apply();
            }
        // No need for egress processing, skip it and use empty controls for egress.
        }
        ig_intr_tm_md.bypass_egress = 1w1;
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
