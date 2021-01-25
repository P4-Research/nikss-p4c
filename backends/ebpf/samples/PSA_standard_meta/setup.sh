#!/bin/bash

log ()
{
echo "--------- INFO --------- $1" >&2
}

log "To test our ebpf programs we will use docker container. Docker will create veth pair for us"

log "Run docker container"
CONTAINER_NAME=testbox
docker stop -t 0 $CONTAINER_NAME &>/dev/null || true && docker rm $CONTAINER_NAME &>/dev/null || true
docker run --rm --name $CONTAINER_NAME -p 9090:9090 -d busybox:latest sh -c "nc -l -p 9090"

ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CONTAINER_NAME)
iflink=$(docker exec -it $CONTAINER_NAME sh -c 'cat /sys/class/net/eth0/iflink')
iflink=$(echo $iflink|tr -d '\r')
veth=$(grep -l $iflink /sys/class/net/veth*/ifindex)
veth=$(echo $veth|sed -e 's;^.*net/\(.*\)/ifindex$;\1;')

log "Container name: $CONTAINER_NAME, host veth name: $veth , IP address $ip"

log "Adding default qdisc"
sudo tc qdisc del dev $veth clsact 2> /dev/null
sudo tc qdisc add dev $veth clsact

log "Compiling eBPF program"
clang -O2 -target bpf -c psa_meta.c -o psa_meta.o

log "Test if we can ping container"
ping -c 3 $ip

log "Loading TC ingress program"
sudo tc filter add dev $veth ingress bpf da obj psa_meta.o sec tc_metadata

log "Loading XDP ingress program"
sudo ip link set dev $veth xdp off
sudo ip link set dev $veth xdp obj psa_meta.o sec xdp_metadata

log "Send ICPM packet"
ping -c 3 $ip

# log "Send TCP packet"
# echo hello | timeout 1 nc -w0 $ip 9090

log "Dump kernel trace logs"
sudo tail -n 35 /sys/kernel/debug/tracing/trace

docker stop -t 0 $CONTAINER_NAME &>/dev/null