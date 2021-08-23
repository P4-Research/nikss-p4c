#include <core.p4>
#include "psa.p4"


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

#define UDP_PORT_GTPU 2152
#define GTP_GPDU 0xff
#define GTPU_VERSION 0x01
#define GTP_PROTOCOL_TYPE_GTP 0x01

typedef bit<4> destination_t;
const destination_t ACCESS = 4w0;
const destination_t CORE = 4w1;
const destination_t SGi_LAN = 4w2;
const destination_t CP_FUNCTION = 4w3;

#define IP_VERSION_4 4
const bit<8> DEFAULT_IPV4_TTL = 64;
const bit<4> IPV4_MIN_IHL = 5;

#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define GTP_HDR_SIZE 8

#define PACKET_COUNT_WIDTH 32
#define BYTE_COUNT_WIDTH 48
#define PACKET_BYTE_COUNT_WIDTH 80

#define PACKET_COUNT_RANGE (PACKET_BYTE_COUNT_WIDTH-1):BYTE_COUNT_WIDTH
#define BYTE_COUNT_RANGE (BYTE_COUNT_WIDTH-1):0

typedef bit<PACKET_BYTE_COUNT_WIDTH> PacketByteCountState_t;

#define MAX_NUM_URR 512

#define COUNT_UL_VOLUME (1<<0)
#define COUNT_DL_VOLUME (1<<1)


action nop() {
    NoAction();
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    macAddr_t  sha;
    ip4Addr_t  spa;
    macAddr_t  tha;
    ip4Addr_t  tpa;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header gtpu_t {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* next extension hdr present? */
    bit<1>  seq_flag;   /* sequence no. */
    bit<1>  npdu_flag;  /* n-pdn number present ? */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    bit<32> teid;       /* tunnel endpoint id */
}

struct upf_meta_t {
    bit<64>           seid;    
    bit<32>           far_id; 
    bit<32>           urr_id; 
    bit<32>           usage_flags;
    destination_t     src;
    destination_t     dest;
    ip4Addr_t         outer_dst_addr;
    bit<16>           l4_sport;
    bit<16>           l4_dport;
    bit<8>            src_port_range_id; 
    bit<8>            dst_port_range_id; 
    bit<16>           ipv4_len;
    bit<32>           teid;
    bit<32>           ran_ip_addr;
    bit<32>           upf_n3_ip_addr;    
}

struct metadata {
    upf_meta_t upf;
}

struct headers {
    ethernet_t   ethernet;
    arp_t arp;
    ipv4_t gtpu_ipv4;
    udp_t gtpu_udp;
    gtpu_t gtpu;
    ipv4_t inner_ipv4;
    udp_t inner_udp;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
}

struct empty_t {}

parser IngressParserImpl(packet_in packet,
                         out headers hdr,
                         inout metadata user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            PROTO_TCP: parse_tcp;
            PROTO_ICMP: accept;    
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dport) {
             UDP_PORT_GTPU: parse_gtpu;
             default: accept;        
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition parse_inner_ipv4;    
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            PROTO_UDP: parse_inner_udp;
            PROTO_TCP: parse_tcp;
            PROTO_ICMP: accept;       
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    action drop() {
        ingress_drop(ostd);
    }

    @hidden
    action gtpu_decap() {
        hdr.gtpu_ipv4.setInvalid();
        hdr.gtpu_udp.setInvalid();
        hdr.gtpu.setInvalid();
        user_meta.upf.outer_dst_addr=hdr.ipv4.dstAddr;
    }

    action set_seid(bit<64> seid) {
        user_meta.upf.seid=seid;
    }

    action set_far_urr_id(bit<32> far_id, bit<32> urr_id, bit<32> usage_flags) {
        user_meta.upf.far_id=far_id;   
        user_meta.upf.urr_id=urr_id; 
        user_meta.upf.usage_flags=usage_flags;   
    }

    action far_encap_forward(destination_t dest,
                       bit<32> teid,
                       bit<32> ran_ip_addr,
                       bit<32> upf_n3_ip_addr)  {
        user_meta.upf.dest=dest;                       
        user_meta.upf.teid = teid;
        user_meta.upf.ran_ip_addr = ran_ip_addr;
        user_meta.upf.upf_n3_ip_addr = upf_n3_ip_addr;
        user_meta.upf.outer_dst_addr=ran_ip_addr;                       
    }

    action far_forward(destination_t dest)  {
        user_meta.upf.dest=dest;    
    }

    action set_source_interface(destination_t src) {
            user_meta.upf.src=src;
    }


    table source_interface_lookup_by_port {
            key = {
                istd.ingress_port: exact;
            }
            actions = {
                    set_source_interface;
                    @defaultonly nop();
            }
            const default_action = nop();
    }

    table session_lookup_by_ue_ip {
        key = {
            // UE addr for downlink
            hdr.ipv4.dstAddr : exact @name("ipv4_dst");
        }
        actions = {
            set_seid();
            @defaultonly nop();
        }
        const default_action = nop();
    }

    table session_lookup_by_teid {
        key = {
            hdr.gtpu.teid : exact;
        }
        actions = {
            set_seid();    
            nop();
        }
        const default_action = nop();
    }

    table pdr_lookup {
        key= {
            user_meta.upf.seid:  exact;   
            hdr.ipv4.srcAddr: ternary;
//            hdr.ipv4.dstAddr: ternary; 
//            hdr.ipv4.protocol: ternary;
//            user_meta.upf.src_port_range_id: ternary;
//            user_meta.upf.dst_port_range_id: ternary;
//            user_meta.upf.src : exact;   
        }    
        actions = {
            set_far_urr_id();
            @defaultonly drop();
        }
        const default_action = drop();
    }

    table far_lookup {
        key= {
            user_meta.upf.far_id: exact;
        }    
        actions = {
            far_forward();
            far_encap_forward();
            drop();
        }
        const default_action = drop();   
    }

    apply {
        source_interface_lookup_by_port.apply();    
        if (hdr.gtpu.isValid()) {
            if (session_lookup_by_teid.apply().hit) {
                ingress_drop(ostd);
            }
            gtpu_decap();
        } else if (session_lookup_by_ue_ip.apply().hit) {
            return;
        }
        if (pdr_lookup.apply().hit) {
            if (far_lookup.apply().hit) {
                    user_meta.upf.ipv4_len =hdr.ipv4.totalLen;
            }
        }
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        transition accept;
    }

}
control egress(inout headers hdr,
               inout metadata user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}


control IngressDeparserImpl(packet_out packet,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata user_meta,
                            in psa_ingress_output_metadata_t istd)
{
    apply {
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata user_meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    apply {
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;

