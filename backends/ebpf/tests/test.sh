#!/bin/bash

if [ "x$1" = "x--help" ]; then
  echo -e "Usage: \n"
  echo -e "\t $0 --help"
  echo -e "\t $0 file.o\n"
  echo -e "file.o should contain eBPF code for TC ingres, TC egress and XDP."
  exit 0
fi

# Trace all command from this point
set -x

if [ "x$1" = "x" ]; then
  echo "Image with switch code not given (first argument for $0)"
  exit 1
fi
image="$1"

add_port_to_switch() {
  ip netns exec switch ip link set dev "$1" xdp obj "$2" sec xdp-ingress
  ip netns exec switch tc qdisc add dev "$1" clsact
  ip netns exec switch tc filter add dev "$1" ingress bpf da obj "$2" sec tc-ingress
  ip netns exec switch tc filter add dev "$1" egress bpf da obj "$2" sec tc-egress
}

declare -a INTERFACES=("eth0" "eth1" "eth2")

ip netns add switch

# Create PSA_PORT_RECIRCULATE
ip netns exec switch ip link add name psa_recirc type dummy
ip netns exec switch ip link set dev psa_recirc up

# Create PSA_PORT_CPU
ip netns exec switch ip link add name psa_cpu type dummy
ip netns exec switch ip link set dev psa_cpu up

# Normal ports
for intf in "${INTERFACES[@]}" ; do
  ip link add "s1-$intf" type veth peer name "$intf" netns switch
  ip netns exec switch ip link set "$intf" up
  ip link set dev "s1-$intf" up
  add_port_to_switch "$intf" "$image"
done

silent_echo_conf() {
  echo "Switch configuration:"
  ip netns exec switch ip link
} 2> /dev/null
silent_echo_conf

# Start tests
ptf \
  --relax `# Allows for other packets, especially injected by the system`\
  --test-dir ptf/ \
  --interface 0@s1-eth0 --interface 1@s1-eth1 --interface 2@s1-eth2

# cleanup
for intf in "${INTERFACES[@]}" ; do
  ip link del "s1-$intf"
done
ip netns exec switch ip link del psa_recirc
ip netns exec switch ip link del psa_cpu
ip netns pids switch | (xargs kill 2>/dev/null)
ip netns del switch
