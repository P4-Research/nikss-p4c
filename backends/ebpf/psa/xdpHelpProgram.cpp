#include "xdpHelpProgram.h"

namespace EBPF {

cstring XDPProgUsingMetaForXDP2TC = "    void *data = (void *)(long)skb->data;\n"
                                    "    void *data_end = (void *)(long)skb->data_end;\n"
                                    "\n"
                                    "    struct internal_metadata *meta;\n"
                                    "    int ret = bpf_xdp_adjust_meta(skb, -(int)sizeof(*meta));\n"
                                    "    if (ret < 0) {\n"
                                    "        return XDP_ABORTED;\n"
                                    "    }\n"
                                    "    meta = (struct internal_metadata *)(unsigned long)skb->data_meta;\n"
                                    "    data = (void *)(long)skb->data;\n"
                                    "    data_end = (void *)(long)skb->data_end;\n"
                                    "    if ((void *) ((struct internal_metadata *) meta + 1) > data)\n"
                                    "        return XDP_ABORTED;\n"
                                    "\n"
                                    "    struct ethhdr *eth = data;\n"
                                    "    if ((void *)((struct ethhdr *) eth + 1) > data_end) {\n"
                                    "        return XDP_ABORTED;\n"
                                    "    }\n"
                                    "    meta->pkt_ether_type = eth->h_proto;\n"
                                    "    eth->h_proto = bpf_htons(0x0800);\n"
                                    "\n"
                                    "    return XDP_PASS;";

cstring XDPProgUsingHeadForXDP2TC = "    void *data = (void *)(long)skb->data;\n"
                                    "    void *data_end = (void *)(long)skb->data_end;\n"
                                    "    struct ethhdr *eth = data;\n"
                                    "    if ((void *)((struct ethhdr *) eth + 1) > data_end) {\n"
                                    "        return XDP_ABORTED;\n"
                                    "    }\n"
                                    "    __u16 orig_ethtype = eth->h_proto;\n"
                                    "    int ret = bpf_xdp_adjust_head(skb, -14);\n"
                                    "    if (ret < 0) {\n"
                                    "        return XDP_ABORTED;\n"
                                    "    }\n"
                                    "\n"
                                    "    data = (void *)(long)skb->data;\n"
                                    "    data_end = (void *)(long)skb->data_end;\n"
                                    "\n"
                                    "    if ((void *)(data + 28) > data_end) {\n"
                                    "        return XDP_ABORTED;\n"
                                    "    }\n"
                                    "    __builtin_memcpy(data, data + 14, 14);\n"
                                    "    eth = data;\n"
                                    "    if ((void *)((struct ethhdr *) eth + 1) > data_end) {\n"
                                    "        return XDP_ABORTED;\n"
                                    "    }\n"
                                    "    eth->h_proto = bpf_htons(0x0800);\n"
                                    "    __builtin_memcpy(data + 26, &orig_ethtype, 2);\n"
                                    "    "
                                    "\n"
                                    "    return XDP_PASS;";

cstring XDPProgUsingCPUMAPForXDP2TC = "  void *data = (void *)(long)skb->data;\n"
                                    "    void *data_end = (void *)(long)skb->data_end;\n"
                                    "    struct ethhdr *eth = data;\n"
                                    "    if ((void *)((struct ethhdr *) eth + 1) > data_end) {\n"
                                    "        return XDP_ABORTED;\n"
                                    "    }\n"
                                    "    u16 orig_ethtype = eth->h_proto;\n"
                                    "    eth->h_proto = bpf_htons(0x0800);\n"
                                    "    u32 zero = 0;\n"
                                    "    BPF_MAP_UPDATE_ELEM(workaround_cpumap, &zero, &orig_ethtype, BPF_ANY);\n"
                                    "    return XDP_PASS;";

void XDPHelpProgram::emit(CodeBuilder *builder) {
    builder->target->emitCodeSection(builder, sectionName);
    builder->emitIndent();
    builder->appendFormat("int %s(struct xdp_md *%s)",
                          functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();
    builder->emitIndent();


    // this is static program, so we can just paste a piece of code.
    if (options.xdp2tcMode == XDP2TC_META) {
        builder->appendLine(XDPProgUsingMetaForXDP2TC);
    } else if (options.xdp2tcMode == XDP2TC_HEAD) {
        builder->appendLine(XDPProgUsingHeadForXDP2TC);
    } else if (options.xdp2tcMode == XDP2TC_CPUMAP) {
        builder->appendLine(XDPProgUsingCPUMAPForXDP2TC);
    }

    builder->blockEnd(true);  // end of function
}

}  // namespace EBPF
