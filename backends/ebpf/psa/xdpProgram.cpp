#include "xdpProgram.h"

namespace EBPF {

void XDPProgram::emit(CodeBuilder *builder) {
    builder->target->emitCodeSection(builder, functionName);
    builder->emitIndent();
    builder->appendFormat("int %s(struct xdp_md *%s)",
                          functionName.c_str(), model.CPacketName.str());
    builder->spc();
    builder->blockStart();
    builder->emitIndent();

    // this is static program, so we can just paste a piece of code.
    builder->appendLine("void *data = (void *)(long)ctx->data;\n"
                        "    void *data_end = (void *)(long)ctx->data_end;\n"
                        "\n"
                        "    struct Ethernet_h *eth = data;\n"
                        "    if (eth + 1 > data_end) {\n"
                        "        return TC_ACT_SHOT;\n"
                        "    }\n"
                        "    __u16 pkt_ether_type = eth->ether_type;\n"
                        "    eth->ether_type = bpf_htons(0x0800);");

    builder->blockEnd(true);  // end of function
}

}