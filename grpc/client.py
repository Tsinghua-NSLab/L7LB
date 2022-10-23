#! /usr/bin/python3

import sys
import grpc
import bfrt_grpc.bfruntime_pb2_grpc as bfruntime_pb2_grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

class BFRTClient(object):
    def __init__(self, grpc_addr=None, p4_name=None, client_id=0, device_id=0,
            notifications=None, perform_bind=True, perform_subscribe=True):
        if grpc_addr == None or grpc_addr == 'localhost':
            grpc_addr = 'localhost:50052'
        else:
            grpc_addr = grpc_addr + ":50052"

        if perform_bind and not perform_subscribe:
            raise RuntimeError("perform_bind must be equal to perform_subscribe")

        self.bfrt_info = None

        self.interface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=device_id,
                notifications=notifications, perform_subscribe=perform_subscribe)

        self.target = gc.Target(device_id=device_id, pipe_id=0xffff)

        if not p4_name:
            self.bfrt_info = self.interface.bfrt_info_get()
            p4_name = self.bfrt_info.p4_name_get()
        else:
            self.bfrt_info = self.interface.bfrt_info_get(p4_name)

        if perform_bind:
            self.interface.bind_pipeline_config(p4_name)

        self.table = {}

    def read_table(self, table_name):
        if not table_name:
            return
        self.table[table_name] = self.bfrt_info.table_get(table_name)
        for action, match in self.table[table_name].entry_get(self.target):
            print ('match:', match.to_dict())
            print ('action:', action.to_dict())

    def write_table(self, table_name, input_match, input_action):
        if not table_name or not input_match or not input_action:
            return
        if table_name not in self.table:
            self.table[table_name] = self.bfrt_info.table_get(table_name)

        match_tuple = []
        for item in input_match:
            if len(item) == 2:
                match_tuple.append(gc.KeyTuple(item[0], item[1]))
            elif len(item) == 3:
                # len-3 KeyTuple: 'ip_addr', ip, prefix_len
                match_tuple.append(gc.KeyTuple(item[0], item[1], prefix_len=item[2]))
        match = self.table[table_name].make_key(match_tuple)

        action_tuple = []
        action_name = None
        for item in input_action:
            if len(item) == 2:
                action_tuple.append(gc.DataTuple(item[0], item[1]))
            elif len(item) == 1:
                # len-1: action_name
                action_name = item[0]
        action = self.table[table_name].make_data(action_tuple, action_name)

        self.table[table_name].entry_add(self.target, [match], [action])

    def del_table_by_match(self, table_name, input_match):
        if not table_name or not input_match:
            return
        if table_name not in self.table:
            return

        match_tuple = []
        for item in input_match:
            if len(item) == 2:
                match_tuple.append(gc.KeyTuple(item[0], item[1]))
            elif len(item) == 3:
                # len-3 KeyTuple: 'ip_addr', ip, prefix_len
                match_tuple.append(gc.KeyTuple(item[0], item[1], prefix_len=item[2]))
        match = self.table[table_name].make_key(match_tuple)

        self.table[table_name].entry_del(self.target, [match])


def client_test(grpc_addr, p4_name, table_name):
    bfrt_client = BFRTClient(grpc_addr, p4_name)
    print ('read_table')
    bfrt_client.read_table(table_name)

    print ('write_table start')
    input_match = []
    input_action = []
    input_match.append(['hdr.ipv4.src_addr', 0xa000002])
    input_match.append(['hdr.ipv4.dst_addr', 0xa000103])
    input_match.append(['hdr.tcp.src_port', 2638])
    input_match.append(['hdr.tcp.dst_port', 1122])
    input_action.append(['SwitchIngress.session_hit_in'])
    input_action.append(['seqDiff', 1])
    input_action.append(['ackDiff', 1])
    input_action.append(['dstIP', 0xa000102])
    input_action.append(['dstPort', 22])
    bfrt_client.write_table(table_name, input_match, input_action)
    #bfrt_client.del_table_by_match(table_name, input_match)
    print ('write_table done')

    print ('read_table')
    bfrt_client.read_table(table_name)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        grpc_addr = None
        p4_name = None
        table_name = sys.argv[1]
        client_test(grpc_addr, p4_name, table_name)
    else:
        print ('wrong input arguements')
