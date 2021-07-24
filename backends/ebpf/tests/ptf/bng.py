#!/usr/bin/env python
from common import *

from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.ppp import PPPoE, PPP

ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_QINQ = 0x88a8
ETH_TYPE_PPPOE = 0x8864
ETH_TYPE_MPLS_UNICAST = 0x8847

PPPOE_CODE_SESSION_STAGE = 0x00

PPPOED_CODE_PADI = 0x09
PPPOED_CODE_PADO = 0x07
PPPOED_CODE_PADR = 0x19
PPPOED_CODE_PADS = 0x65
PPPOED_CODE_PADT = 0xa7

PPPOED_CODES = (
    PPPOED_CODE_PADI,
    PPPOED_CODE_PADO,
    PPPOED_CODE_PADR,
    PPPOED_CODE_PADS,
    PPPOED_CODE_PADT,
)

PORT_TYPE_OTHER     = 0x00
PORT_TYPE_EDGE      = 0x01
PORT_TYPE_INFRA     = 0x02
PORT_TYPE_INTERNAL  = 0x03

FORWARDING_TYPE_BRIDGING = 0
FORWARDING_TYPE_UNICAST_IPV4 = 2
FORWARDING_TYPE_MPLS = 1

DEFAULT_VLAN = 4096
HOST1_MAC = "00:00:00:00:00:01"
VLAN_ID_3 = 300
MPLS_LABEL_2 = 200
DEFAULT_MPLS_TTL = 64

s_tag = vlan_id_outer = 888
c_tag = vlan_id_inner = 777
line_id = 99
pppoe_session_id = 0xbeac
core_router_mac = HOST1_MAC

PORT0 = 0
PORT1 = 1

def pkt_route(pkt, mac_dst):
    new_pkt = pkt.copy()
    new_pkt[Ether].src = pkt[Ether].dst
    new_pkt[Ether].dst = mac_dst
    return new_pkt


def pkt_add_vlan(pkt, vlan_vid=10, vlan_pcp=0, dl_vlan_cfi=0):
    return Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / \
           Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid) / \
           pkt[Ether].payload


def pkt_add_inner_vlan(pkt, vlan_vid=10, vlan_pcp=0, dl_vlan_cfi=0):
    assert Dot1Q in pkt
    return Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=ETH_TYPE_VLAN) / \
           Dot1Q(prio=pkt[Dot1Q].prio, id=pkt[Dot1Q].id, vlan=pkt[Dot1Q].vlan) / \
           Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid) / \
           pkt[Dot1Q].payload


def pkt_add_pppoe(pkt, type, code, session_id):
    return Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / \
           PPPoE(version=1, type=type, code=code, sessionid=session_id) / \
           PPP() / pkt[Ether].payload


def pkt_add_mpls(pkt, label, ttl, cos=0, s=1):
    return Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / \
           MPLS(label=label, cos=cos, s=s, ttl=ttl) / \
           pkt[Ether].payload

def pkt_decrement_ttl(pkt):
    if IP in pkt:
        pkt[IP].ttl -= 1
    return pkt

class BNGTest(P4EbpfTest):

    p4_file_path = "./../evaluation/scenarios/use-cases/p4/bng.p4"
    session_installed = False

    def setUp(self):
        super(BNGTest, self).setUp()

    def tearDown(self):
        super(BNGTest, self).tearDown()

    def setup_port(self, port_id, vlan_id, port_type, tagged=False, double_tagged=False, inner_vlan_id=0):
        if double_tagged:
            self.set_ingress_port_vlan(ingress_port=port_id, vlan_id=vlan_id,
                                       vlan_valid=True, inner_vlan_id=inner_vlan_id, port_type=port_type)
        elif tagged:
            self.set_ingress_port_vlan(ingress_port=port_id, vlan_id=vlan_id,
                                       vlan_valid=True, port_type=port_type)
            self.set_egress_vlan(egress_port=port_id, vlan_id=vlan_id, push_vlan=True)
        else:
            self.set_ingress_port_vlan(ingress_port=port_id,
                                       vlan_valid=False, internal_vlan_id=vlan_id, port_type=port_type)
            self.set_egress_vlan(egress_port=port_id, vlan_id=vlan_id, push_vlan=False)

    def set_ingress_port_vlan(self, ingress_port,
                              vlan_valid=False,
                              vlan_id=0,
                              internal_vlan_id=0,
                              inner_vlan_id=None,
                              port_type=PORT_TYPE_EDGE,
                              ):
        vlan_valid_ = 1 if vlan_valid else 0
        if vlan_valid:
            action_id = 2 # permit
            action_data = [port_type]
        else:
            action_id = 3 # permit_with_internal_vlan
            action_data = [vlan_id, port_type]

        key_vlan_id = "{}^0xffff".format(vlan_id) if vlan_valid else "0^0"
        key_inner_vlan_id = "{}^0xffff".format(inner_vlan_id) if inner_vlan_id is not None else "0^0"
        keys = [ingress_port, key_vlan_id, key_inner_vlan_id, vlan_valid_]
        self.table_add(table="ingress_ingress_port_vlan", keys=keys, action=action_id, data=action_data)

    def set_egress_vlan(self, egress_port, vlan_id, push_vlan=False):
        action_id = 1 if push_vlan else 2
        self.table_add(table="egress_egress_vlan", keys=[vlan_id, egress_port],
                       action=action_id)

    def set_forwarding_type(self, ingress_port, eth_dstAddr, ethertype=ETH_TYPE_IPV4,
                            fwd_type=FORWARDING_TYPE_UNICAST_IPV4):
        if ethertype == ETH_TYPE_IPV4:
            key_eth_type = "0^0"
            key_ip_eth_type = ETH_TYPE_IPV4
        elif ethertype == ETH_TYPE_MPLS_UNICAST:
            key_eth_type = "{}^0xffff".format(ETH_TYPE_MPLS_UNICAST)
            key_ip_eth_type = ETH_TYPE_IPV4
        key_eth_dst = "{}^0xffffffffffff".format(eth_dstAddr) if eth_dstAddr is not None else "0^0"

        matches = [key_eth_dst, ingress_port, key_eth_type, key_ip_eth_type]

        self.table_add(table="ingress_fwd_classifier", keys=matches, action=1, # set_forwarding_type
                       data=[fwd_type])

    def add_forwarding_routing_v4_entry(self, ipv4_dstAddr, ipv4_pLen,
                                        egress_port, smac, dmac):
        self.table_add(table="ingress_routing_v4", keys=["{}/{}".format(ipv4_dstAddr, ipv4_pLen)],
                       action=1, data=[egress_port, smac, dmac])

    def add_next_vlan(self, port_id, new_vlan_id):
        self.table_add(table="ingress_next_vlan", keys=[port_id],
                       action=1, data=[new_vlan_id])

    def set_upstream_pppoe_cp_table(self, pppoe_codes=()):
        for code in pppoe_codes:
            self.table_add(table="ingress_t_pppoe_cp", keys=[code], action=1, priority=1)

    def set_line_map(self, s_tag, c_tag, line_id):
        assert line_id != 0
        self.table_add(table="ingress_t_line_map", keys=[s_tag, c_tag], action=1, data=[line_id])

    def setup_line_v4(self, s_tag, c_tag, line_id, ipv4_addr, mac_src,
                      pppoe_session_id, enabled=True):
        assert s_tag != 0
        assert c_tag != 0
        assert line_id != 0
        assert pppoe_session_id != 0

        # line map common to up and downstream
        self.set_line_map(s_tag=s_tag, c_tag=c_tag, line_id=line_id)
        # Upstream
        if enabled:
            # Enable upstream termination.
            self.table_add(table="ingress_t_pppoe_term_v4", keys=[line_id, str(ipv4_addr), pppoe_session_id], action=1)

        # Downstream
        if enabled:
            self.table_add(table="ingress_t_line_session_map", keys=[line_id],
                           action=1, data=[pppoe_session_id])
        else:
            self.table_add(table="ingress_t_line_session_map", keys=[line_id],
                           action=2)


class BasicTest(BNGTest):

    def doRunTest(self, pkt, tagged2, mpls, line_enabled):
        if not self.session_installed:
            self.setup_line_v4(
                s_tag=s_tag, c_tag=c_tag, line_id=line_id, ipv4_addr=pkt[IP].src,
                mac_src=pkt[Ether].src, pppoe_session_id=pppoe_session_id, enabled=line_enabled)
            self.session_installed = True

        # Input is the given packet with double VLAN tags and PPPoE headers.
        pppoe_pkt = pkt_add_pppoe(pkt, type=1, code=PPPOE_CODE_SESSION_STAGE,
                                  session_id=pppoe_session_id)
        pppoe_pkt = pkt_add_vlan(pppoe_pkt, vlan_vid=vlan_id_inner)
        pppoe_pkt = pkt_add_vlan(pppoe_pkt, vlan_vid=vlan_id_outer)

        # Build expected packet from the input one, we expect it to be routed as
        # if it was without VLAN tags and PPPoE headers.
        exp_pkt = pkt.copy()
        exp_pkt = pkt_route(exp_pkt, core_router_mac)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_3)
        if mpls:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        else:
            exp_pkt = pkt_decrement_ttl(exp_pkt)

        if Dot1Q not in pppoe_pkt:
            pppoe_pkt = pkt_add_vlan(pkt, vlan_vid=s_tag)
            pppoe_pkt = pkt_add_inner_vlan(pkt, vlan_vid=c_tag)
        else:
            try:
                pppoe_pkt[Dot1Q:2]
            except IndexError:
                # Add the not added vlan header
                if pppoe_pkt[Dot1Q:1].vlan == s_tag:
                    pppoe_pkt = pkt_add_inner_vlan(pppoe_pkt, vlan_vid=c_tag)
                elif pkt[Dot1Q:1].vlan == c_tag:
                    pppoe_pkt = pkt_add_vlan(pppoe_pkt, vlan_vid=s_tag)
                else:
                    self.fail("Packet should be without VLANs or with correct VLANs")
        if mpls:
            # If MPLS test, egress_port is assumed to be a spine port, with
            # default vlan untagged.
            next_vlan = DEFAULT_VLAN
            assert not tagged2
        else:
            next_vlan = VLAN_ID_3 if tagged2 else s_tag
        next_id = 100
        group_id = next_id
        mpls_label = MPLS_LABEL_2

        dst_ipv4 = pppoe_pkt[IP].dst
        switch_mac = pppoe_pkt[Ether].dst

        # Setup port 1: packets on this port are double tagged packets
        self.setup_port(4, vlan_id=s_tag, port_type=PORT_TYPE_EDGE, double_tagged=True, inner_vlan_id=c_tag)
        # Setup port 2
        self.setup_port(5, vlan_id=next_vlan, port_type=PORT_TYPE_INFRA, tagged=tagged2)

        self.set_forwarding_type(4, switch_mac, ETH_TYPE_IPV4,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(dst_ipv4, 24, 5, switch_mac, HOST1_MAC)
        self.add_next_vlan(5, next_vlan)

        testutils.send_packet(self, PORT0, pppoe_pkt)
        testutils.verify_packet(self, exp_pkt, PORT1)
        self.verify_no_other_packets()

    def runTest(self):
        self.set_upstream_pppoe_cp_table(PPPOED_CODES)
        print("")
        for line_enabled in [True, False]:
            for out_tagged in [False, True]:
                for mpls in [False, True]:
                    if mpls and out_tagged:
                        continue
                    for pkt_type in ["tcp", "udp", "icmp"]:
                        print("Testing %s packet, line_enabled=%s, " \
                              "out_tagged=%s, mpls=%s ..." \
                              % (pkt_type, line_enabled, out_tagged, mpls))
                        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                            pktlen=120)
                        self.doRunTest(pkt, out_tagged, mpls, line_enabled)