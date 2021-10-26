#!/bin/bash

function print_help() {
  # Display Help
  echo "Run PTF tests for PSA-eBPF."
  echo "The script will run all combinations of flags if no options are provided."
  echo
  echo "Syntax: ./test.sh [OPTIONS] [TEST_CASE]"
  echo
  echo "OPTIONS:"
  echo "--bpf-hook       A BPF hook that should be used as a main attach point <tc|xdp>"
  echo "--xdp2tc         A mode to pass metadata from XDP to TC programs <meta|head|cpumap>."
  echo "--hdr2map        Allocate header structure in per-CPU map <on|off>."
  echo "--table-caching  Use table cache for tables with LPM and/or ternary key <on|off>."
  echo "--help           Print this message."
  echo
}

function exit_on_error() {
      exit_code=$?
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
      # remove all pinned eBPF objects
      rm -rf /sys/fs/bpf/*
      echo "Cleaning finished"
}

if [ "x$1" = "x--help" ]; then
  print_help
  exit 0
fi

for i in "$@"; do
  case $i in
    --bpf-hook=*)
      BPF_HOOK="${i#*=}"
      shift # past argument=value
      ;;
    --xdp2tc=*)
      XDP2TC_ARG="${i#*=}"
      shift # past argument=value
      ;;
    --hdr2map=*)
      HDR2MAP_ARG="${i#*=}"
      shift # past argument=value
      ;;
    --table-caching=*)
      TABLE_CACHING_ARG="${i#*=}"
      shift # past argument=value
      ;;
    *)
      # unknown option
      ;;
  esac
done

cleanup
trap cleanup EXIT

# Remove any temporary files from previous run. It might be useful to
# preserve these files after test run for inspection
rm -rf ptf_out/*
echo "Removed old temporary files from previous tests"

# Trace all command from this point
set -x

declare -a INTERFACES=("eth0" "eth1" "eth2" "eth3" "eth4" "eth5")
# For PTF tests parameter
interface_list=$( IFS=$','; echo "${INTERFACES[*]}" )
interface_list="psa_recirc,""$interface_list"

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

# Add path to our libbpf
LIBBPF_LD_PATH="`pwd`/../runtime/usr/lib64"
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LIBBPF_LD_PATH

# Docker image by default has lower "max locked memory" limit
ulimit -l 65536

# PTF test params:
# ;xdp=<True|False>;xdp2tc=<meta|head|cpumap>;hdr2Map=<True|False>
declare -a XDP=("False" "True")
declare -a XDP2TC_MODE=("head" "cpumap" "meta")
declare -a HDR2MAP=("False" "True")
declare -a TABLE_CACHING=("False" "True")

if [ ! -z "$BPF_HOOK" ]; then
  if [ "$BPF_HOOK" == "tc" ]; then
    XDP=( "False" )
  elif [ "$BPF_HOOK" == "xdp" ]; then
    XDP=( "True" )
  else
    echo "Wrong --bpf-hook value provided; running script for both hooks."
  fi
fi

if [ ! -z "$XDP2TC_ARG" ]; then
  if [ "$XDP2TC_ARG" == "meta" ] || [ "$XDP2TC_ARG" == "head" ] || [ "$XDP2TC_ARG" == "cpumap" ]; then
    XDP2TC_MODE=( "$XDP2TC_ARG" )
  else
    echo "Wrong --xdp2tc value provided; running script for all XDP2TC modes."
  fi
fi

if [ ! -z "$HDR2MAP_ARG" ]; then
  if [ "$HDR2MAP_ARG" == "on" ]; then
    HDR2MAP=( "True" )
  elif [ "$HDR2MAP_ARG" == "off" ]; then
    HDR2MAP=( "False" )
  else
    echo "Wrong --hdr2map value provided; running script for both enabled/disabled."
  fi
fi

if [ ! -z "$TABLE_CACHING_ARG" ]; then
  if [ "$TABLE_CACHING_ARG" == "on" ]; then
    TABLE_CACHING=( "True" )
  elif [ "$TABLE_CACHING_ARG" == "off" ]; then
    TABLE_CACHING=( "False" )
  else
    echo "Wrong --table-caching value provided; running script for both enabled/disabled."
  fi
fi

TEST_CASE=$@
for xdp_enabled in "${XDP[@]}" ; do
  for xdp2tc_mode in "${XDP2TC_MODE[@]}" ; do
    for hdr2map_enabled in "${HDR2MAP[@]}" ; do
      for table_caching_enabled in "${TABLE_CACHING[@]}" ; do
        # FIXME: hdr2map is not working properly for TC, we should fix it in future
        if [ "$xdp_enabled" == "False" ] && [ "$hdr2map_enabled" == "True" ]; then
          echo "Test skipped because hdr2map doesn't work properly in TC"
          continue
        fi
        TEST_PARAMS='interfaces="'"$interface_list"'";namespace="switch"'
        TEST_PARAMS+=";xdp='$xdp_enabled';xdp2tc='$xdp2tc_mode';hdr2Map='$hdr2map_enabled'"
        TEST_PARAMS+=";table_caching='$table_caching_enabled'"
        # Start tests
        ptf \
          --test-dir ptf/ \
          --test-params="$TEST_PARAMS" \
          --interface 0@s1-eth0 --interface 1@s1-eth1 --interface 2@s1-eth2 --interface 3@s1-eth3 \
          --interface 4@s1-eth4 --interface 5@s1-eth5 $TEST_CASE
        exit_on_error
        rm -rf ptf_out
      done
    done
  done
done
