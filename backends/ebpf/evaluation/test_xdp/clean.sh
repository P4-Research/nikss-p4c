sudo ip netns exec ns0 sudo ip link set dev eth0 xdp off
sudo ip netns exec ns0 sudo ip link set dev eth1 xdp off

sudo nsenter --net=/var/run/netns/ns0 rm -rf /sys/fs/bpf/pipeline1

sudo ip link del dev veth0
sudo ip link del dev veth1

sudo ip netns delete ns0

make clean
rm -f out-xdp.c