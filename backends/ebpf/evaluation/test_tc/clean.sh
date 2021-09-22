# Actually, clean TC is not mandatory. 
# Delete ns should be enough.
sudo ip netns exec ns0 sudo ip link set dev eth0 xdp off
sudo ip netns exec ns0 sudo tc filter del dev eth0 ingress
sudo ip netns exec ns0 sudo tc filter del dev eth1 egress

sudo psabpf-ctl pipeline unload id 1

sudo ip link del dev veth0
sudo ip link del dev veth1
sudo ip link del psa_recirc

sudo ip netns delete ns0

make -f ../../runtime/kernel.mk BPFOBJ=out.o clean
rm -f out-tc.*