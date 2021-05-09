sudo ip netns exec ns0 sudo ip link set dev eth0 xdp off
sudo ip netns exec ns0 sudo tc filter del dev eth0 ingress
sudo ip netns exec ns0 sudo tc filter del dev eth1 egress

# TODO: use recursive delete
sudo rm -rf /sys/fs/bpf/tc
sudo rm -rf /sys/fs/bpf/xdp
sudo rm -rf /sys/fs/bpf/ip
sudo rm -rf /sys/fs/bpf/prog
sudo rm -f /sys/fs/bpf/clone_session_tbl
sudo rm -f /sys/fs/bpf/ingress_tbl_fwd
sudo rm -f /sys/fs/bpf/ingress_tbl_fwd_defaultAction
sudo rm -f /sys/fs/bpf/multicast_grp_tbl
sudo rm -f /sys/fs/bpf/sa
sudo rm -f /sys/fs/bpf/sk

sudo ip link del dev veth0
sudo ip link del dev veth1
sudo ip link del psa_recirc

sudo ip netns delete ns0

make -f ../../runtime/kernel.mk BPFOBJ=out.o clean
rm -f out-tc.*