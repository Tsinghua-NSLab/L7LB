#!/bin/bash
# 初始化veth端口

# 创建两对veth, veth0 -- veth1, veth2 -- veth3
ip link delete veth0
ip link delete veth2
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3

# 创建netns
ip netns delete ns0
ip netns delete ns1
ip netns delete ns2
ip netns add ns0
ip netns add ns1
ip netns add ns2

# 将veth移动到netns中
ip link set veth0 netns ns0
ip link set veth1 netns ns1
ip link set veth2 netns ns1
ip link set veth3 netns ns2

# 启动端口
ip netns exec ns0 ip link set veth0 up
ip netns exec ns1 ip link set veth1 up
ip netns exec ns1 ip link set veth2 up
ip netns exec ns2 ip link set veth3 up

# 配置IP
ip netns exec ns0 ip addr add 10.0.1.10/24 dev veth0
# ip netns exec ns1 ip addr add 10.0.1.11/25 dev veth1
# ip netns exec ns1 ip addr add 10.0.1.212/25 dev veth2
ip netns exec ns2 ip addr add 10.0.1.213/24 dev veth3

# 关闭offload的相关配置, 否则scapy的抓包会有问题(checksum不对, 或者抓到巨包)
ip netns exec ns0 ethtool -K veth0 tx off rx off sg off tso off gso off gro off lro off # 关闭所有卸载(校验和、分段、分组、大包)
ip netns exec ns1 ethtool -K veth1 tx off rx off sg off tso off gso off gro off lro off
ip netns exec ns1 ethtool -K veth2 tx off rx off sg off tso off gso off gro off lro off
ip netns exec ns2 ethtool -K veth3 tx off rx off sg off tso off gso off gro off lro off
