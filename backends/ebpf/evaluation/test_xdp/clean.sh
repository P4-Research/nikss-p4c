sudo ip netns exec ns0 sudo ip link set dev eth0 xdp off
sudo ip netns exec ns0 sudo ip link set dev eth1 xdp off

sudo rm -rf /sys/fs/bpf/ingress_tbl_fwd

sudo ip link del dev veth0
sudo ip link del dev veth1

sudo ip netns delete ns0