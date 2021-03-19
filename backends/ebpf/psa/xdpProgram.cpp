#include "xdpProgram.h"

namespace EBPF {

void XDPProgram::emit(CodeBuilder *builder) {
    builder->target->emitCodeSection(builder, sectionName);
    builder->emitIndent();
    builder->appendFormat("int %s(struct xdp_md *%s)",
                          functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();
    builder->emitIndent();

    // this is static program, so we can just paste a piece of code.
    builder->appendLine("void *data = (void *)(long)skb->data;\n"
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
                        "    return XDP_PASS;");

    builder->blockEnd(true);  // end of function
}

}  // namespace EBPF
