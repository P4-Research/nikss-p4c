# How to tests meters

0. Uncomment a map update in setup.sh to choose meter configuration you want to check.

1. `make clean`
2. `make`
3. In first terminal run iperf server `make iperfs`
4. In Second terminal run iperf client `make iperfc`