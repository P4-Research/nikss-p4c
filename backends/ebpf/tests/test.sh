#!/bin/bash

if [ "x$1" = "x--help" ]; then
  echo -e "Usage: \n"
  echo -e "\t $0 [--help]"
  echo -e "Will execute PTF test and setup/cleanup environment."
  exit 0
fi

function exit_on_error() {
      exit_code=$1
      if [ $exit_code -ne 0 ]; then
          exit $exit_code
      fi
}

function cleanup() {
      echo "Cleaning...."
      for intf in "${INTERFACES[@]}" ; do
        ip link del "s1-$intf"
      done
      ip netns exec switch ip link del psa_recirc
      ip netns exec switch ip link del psa_cpu
      ip netns pids switch | (xargs kill 2>/dev/null)
      ip netns del switch
      echo "Cleaning finished"
}

cleanup
trap cleanup EXIT

# Trace all command from this point
set -x

# make eBPF programs
make -C samples
exit_on_error $?

declare -a INTERFACES=("eth0" "eth1" "eth2")
# For PTF tests parameter
interface_list=$( IFS=$','; echo "${INTERFACES[*]}" )
interface_list="psa_recirc,""$interface_list"
# TODO: similar list with interfaces for ptf

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

  # Disable trash traffic
  sysctl -w net.ipv6.conf."s1-$intf".disable_ipv6=1
  sysctl -w net.ipv6.conf."s1-$intf".autoconf=0
  sysctl -w net.ipv6.conf."s1-$intf".accept_ra=0
done

# Disable trash traffic
ip netns exec switch sysctl -w net.ipv6.conf.all.disable_ipv6=1
ip netns exec switch sysctl -w net.ipv6.conf.all.autoconf=0
ip netns exec switch sysctl -w net.ipv6.conf.all.accept_ra=0

silent_echo_conf() {
  echo "Switch configuration:"
  ip netns exec switch ip link
} 2> /dev/null
silent_echo_conf

TEST_PARAMS='interfaces="'"$interface_list"'";namespace="switch"'

# Start tests
ptf \
  --test-dir ptf/ \
  --test-params=$TEST_PARAMS \
  --interface 0@s1-eth0 --interface 1@s1-eth1 --interface 2@s1-eth2