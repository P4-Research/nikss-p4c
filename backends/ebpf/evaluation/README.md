# How to run a performance test? 

We provide a `setup_test.sh` script to automate performance testing.

Before setting up a test, make sure that `NetworkManager.service` is disabled on your system. Otherwise, it can periodically refresh
network interfaces, what will cause unloading BPF programs from TC. On Ubuntu 20.04 it can be disabled using:

```bash
sudo systemctl stop NetworkManager.service
sudo systemctl disable NetworkManager.service

sudo systemctl stop NetworkManager-wait-online.service
sudo systemctl disable NetworkManager-wait-online.service

sudo systemctl stop NetworkManager-dispatcher.service
sudo systemctl disable NetworkManager-dispatcher.service

sudo systemctl stop network-manager.service
sudo systemctl disable network-manager.service
```

To set up a performance test just run:

```
$ sudo ./setup_test.sh ens1f0,ens1f1 basic/p4/l2fwd
```

As a first argument you must pass a list of network interfaces. 
As a second argument you must pass a directory, where a *.p4 or *.c file is located. If *.p4 will be found it will be compiled using `p4c-ebpf --arch psa`. Otherwise, a *.c file will be compiled directly to the ELF file. 

**Note!** The following section names are: `xdp-ingress`, `tc-ingress` or `tc-egress`. 

The test utility script will also look for `commands.txt` file, in which you can define control plane operations (e.g. adding table entries). It is recommended to use `bpftool`. 

