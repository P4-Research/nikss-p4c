sudo ip netns exec ns0 sudo ip link set dev eth0 xdp off
sudo ip netns exec ns0 sudo tc filter del dev eth0 ingress
sudo ip netns exec ns0 sudo tc filter del dev eth1 egress

sudo rm -rf /sys/fs/bpf/tc
sudo rm -rf /sys/fs/bpf/xdp
sudo rm -rf /sys/fs/bpf/ip

sudo ip link del dev veth0
sudo ip link del dev veth1
sudo ip link del psa_recirc

sudo ip netns delete ns0