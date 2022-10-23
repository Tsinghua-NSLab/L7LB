工作过程

1. 发包、收包都使用scapy, 完成模拟TCP级别的互通
2. 增加middle模块, 模拟中间人回复client的SYN包直到接收到Payload包(第1批次), 而后将client的SYN包转发给server, 得到server的ACK包, 完成建链后; (在这中间要完成seq和ack序号的修改), 把缓存的所有包发送到server端; 完成两端的映射结果
3. 发包、收包使用iperf, 完成实际的TCP互通

CPU文件夹下的文件说明:

- cpu_run_l3.py是核心代码(从一个veth收包, 如果是SYN包则返回一个虚假的SYN ACK, 然后等待ACK和首个数据包(中间收到的所有包都缓存下来), 完成后向另一个veth发送SYN以完成建链, 等到cpu->srv建链完毕后, 缓存的包转发到后端, 同时记录相关的seq和ack数据, 通过计算完成两端的映射关系, 之后的包都可以通过映射关系完成seq和ack的修改, 从而完成中间人的功能)
    需要注意的是, 修改包后要del相关checksum和len, 让scapy自动完成新的checksum和len的填充, 否则会导致包在内核协议栈中检查不通过, 从而丢包

- init_veth.sh是初始化veth的脚本, 用于创建veth pair, 并加入各个namespace中; 同时关闭veth pair的checksum offload等, 以便于scapy可以修改包的checksum

其他脚本: cpu_direct_fwd.py(完成两端直接互通的功能, 不做建链)、endhost_run_l3.py(模拟TCP的建链和ACK发包过程, 有client和server之分)

增加匹配的CPU程序：
l7cpu, 直接listen某个端口, 而后转发出去

