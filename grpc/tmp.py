#! 终端运行的发包程序

from client import BFRTClient


def write_table(client_ip, client_port, vip, vport, dip, dport, seqdiff, ackdiff):
    # all input arguments are integers
    global bfrt_client, session_in_tbl, session_out_tbl

    # session_in_tbl
    input_match = []
    input_action = []
    input_match.append(['hdr.ipv4.src_addr', client_ip])
    input_match.append(['hdr.ipv4.dst_addr', vip])
    input_match.append(['hdr.tcp.src_port', client_port])
    input_match.append(['hdr.tcp.dst_port', vport])
    input_action.append(['SwitchIngress.session_hit_in'])
    input_action.append(['seqDiff', seqdiff])
    input_action.append(['ackDiff', ackdiff])
    input_action.append(['dstIP', dip])
    input_action.append(['dstPort', dport])
    bfrt_client.write_table(session_in_tbl, input_match, input_action)

    # session_out_tbl
    input_match = []
    input_action = []
    input_match.append(['hdr.ipv4.src_addr', dip])
    input_match.append(['hdr.ipv4.dst_addr', client_ip])
    input_match.append(['hdr.tcp.src_port', dport])
    input_match.append(['hdr.tcp.dst_port', client_port])
    input_action.append(['SwitchIngress.session_hit_out'])
    input_action.append(['seqDiff', seqdiff])
    input_action.append(['ackDiff', ackdiff])
    input_action.append(['srcIP', vip])
    input_action.append(['srcPort', vport])
    bfrt_client.write_table(session_out_tbl, input_match, input_action)

def read_table():
    global bfrt_client, session_in_tbl, session_out_tbl
    print ('current %s table entries' % session_in_tbl)
    bfrt_client.read_table(session_in_tbl)
    print ('current %s table entries' % session_out_tbl)
    bfrt_client.read_table(session_out_tbl)

def init_client():
    global bfrt_client, session_in_tbl, session_out_tbl
    session_in_tble = 'SwitchIngress.seesion_in'
    session_out_tbl = 'SwitchIngress.seesion_in'
    bfrt_client = BFRTClient()

    print ('current %s table entries' % session_in_tbl)
    bfrt_client.read_table(session_in_tbl)
    print ('current %s table entries' % session_out_tbl)
    bfrt_client.read_table(session_out_tbl)
