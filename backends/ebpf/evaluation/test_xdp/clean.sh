# Actually, clean TC and XDP is not mandatory. 
# Delete ns should be enough.
sudo ip netns exec ns0 ip link set dev eth0 xdp off
sudo ip netns exec ns0 ip link set dev eth1 xdp off
sudo ip netns exec ns0 tc filter del dev eth0 ingress
sudo ip netns exec ns0 tc filter del dev eth0 egress
sudo ip netns exec ns0 tc filter del dev eth1 ingress
sudo ip netns exec ns0 tc filter del dev eth1 egress
sudo ip netns exec ns0 tc qdisc del dev eth0 clsact
sudo ip netns exec ns0 tc qdisc del dev eth1 clsact

sudo psabpf-ctl pipeline unload id 1

sudo ip link del dev veth0
sudo ip link del dev veth1

sudo ip netns delete ns0

make clean
rm -f out-xdp.c