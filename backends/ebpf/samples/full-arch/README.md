The `full-kern.c` file contains eBPF programs implementing the PSA architecture.

# Test cases

To test different packet paths a packet processing logic has been prepared:

- Normal Unicast - packets received on interface 2 are directly sent to interface 4.
- Normal Multicast - packets received on interface 3 are multicasted to interfaces 3 and 4.
- RESUBMIT - packets received on interface 4 are resubmitted (only once) and dropped.
- RECIRCULATE - packets received on interface 3 are sent to port 3 and recirculated (only once) and dropped.
- CE2E - packets sent to interface 4 are cloned E2E. The original packet is sent on interface 4 and a cloned packet is dropped.
- CI2E - packets received on interface 5 are cloned I2E. The original packet is sent to interface 2 and a cloned packet is dropped.