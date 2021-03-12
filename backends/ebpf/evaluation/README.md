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
