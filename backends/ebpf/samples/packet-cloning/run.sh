
echo "Compiling eBPF program.."
clang -O2 -target bpf -c packet-cloning.c -o packet-cloning.o
#clang-6.0 -O2 -target bpf -Weverything -Wno-pedantic -o clone.o packet-cloning.c
if [ $? -ne 0 ]; then
    echo "Compilation failed, aborting.."
    exit
fi

echo "Tearing down previous net namespace machine-1"
sudo ip netns del machine-1
echo "Tearing down previous net namespace machine-2"
sudo ip netns del machine-2
echo "Tearing down previous net namespace machine-3"
sudo ip netns del machine-3
echo "Tearing down previous net namespace switch"
sudo ip netns del switch

echo "Creating netns for switch"
sudo ip netns add switch
echo "Creating netns for machine-1"
sudo ip netns add machine-1
echo "Creating netns for machine-2"
sudo ip netns add machine-2
echo "Creating netns for machine-3"
sudo ip netns add machine-3

echo "Creating a veth pair -- that links netns machine-1 and switch"
sudo ip -n machine-1 link add eth0 type veth peer name eth0 netns switch

echo "Creating a veth pair -- that links netns machine-2 and switch"
sudo ip -n machine-2 link add eth0 type veth peer name eth1 netns switch

echo "Creating a veth pair -- that links netns machine-3 and switch"
sudo ip -n machine-3 link add eth0 type veth peer name eth2 netns switch

echo "Turning on lo interface in machine-1"
sudo ip netns exec machine-1 ip link set lo up
echo "Turning on lo interface in machine-2"
sudo ip netns exec machine-2 ip link set lo up
echo "Turning on lo interface in machine-3"
sudo ip netns exec machine-3 ip link set lo up
echo "Turning on lo interface in switch"
sudo ip netns exec switch ip link set lo up

echo "Adding ip 10.0.0.1/24 to eth0 in machine-1"
sudo ip netns exec machine-1 ip add add 10.0.0.1/24 dev eth0

echo "Adding ip 10.0.0.2/24 to eth0 in machine-2"
sudo ip netns exec machine-2 ip add add 10.0.0.2/24 dev eth0

echo "Adding ip 10.0.0.3/24 to eth0 in machine-3"
sudo ip netns exec machine-3 ip add add 10.0.0.3/24 dev eth0

echo "Turning on eth0 interface in machine-1"
sudo ip netns exec machine-1 ip link set eth0 up
echo "Turning on eth0 interface in machine-2"
sudo ip netns exec machine-2 ip link set eth0 up
echo "Turning on eth0 interface in machine-3"
sudo ip netns exec machine-3 ip link set eth0 up
echo "Turning on eth0 interface in switch"
sudo ip netns exec switch ip link set eth0 up
echo "Turning on eth1 interface in switch"
sudo ip netns exec switch ip link set eth1 up
echo "Turning on eth2 interface in switch"
sudo ip netns exec switch ip link set eth2 up

echo "Adding default TC qdisc to switch"
sudo ip netns exec switch tc qdisc add dev eth0 clsact
sudo ip netns exec switch tc qdisc add dev eth1 clsact
sudo ip netns exec switch tc qdisc add dev eth2 clsact

echo "Adding BPF prog to eth0 of switch"
sudo nsenter --net=/var/run/netns/switch tc filter add dev eth0 ingress bpf da obj packet-cloning.o sec pktclone verbose

sudo nsenter --net=/var/run/netns/switch tc filter add dev eth0 egress bpf da obj packet-cloning.o sec tc-egress verbose
sudo nsenter --net=/var/run/netns/switch tc filter add dev eth1 egress bpf da obj packet-cloning.o sec tc-egress verbose
sudo nsenter --net=/var/run/netns/switch tc filter add dev eth2 egress bpf da obj packet-cloning.o sec tc-egress verbose