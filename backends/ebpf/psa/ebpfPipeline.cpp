#include "ebpfPipeline.h"
#include "backends/ebpf/ebpfParser.h"

namespace EBPF {

void EBPFPipeline::emit(CodeBuilder* builder) {
    cstring msgStr, pathStr;
    // Ingress and egress has different variables which are pointers,
    // clearing is needed to not preserving them between pipelines
    control->codeGen->asPointerVariables.clear();
    builder->target->emitCodeSection(builder, sectionName);
    builder->emitIndent();
    builder->target->emitMain(builder, functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();
    emitGlobalMetadataInitializer(builder);
    emitHeaderInstances(builder);
    emitLocalVariables(builder);
    emitPSAControlDataTypes(builder);
    msgStr = Util::printf_format("%s parser: parsing new packet, path=%%d, pkt_len=%%d",
                                 sectionName);
    pathStr = Util::printf_format("%s.packet_path", control->inputStandardMetadata->name.name);
    builder->target->emitTraceMessage(builder, msgStr.c_str(), 2, pathStr.c_str(),
                                      lengthVar.c_str());
    parser->emit(builder);
    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(":");
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("%s.parser_error = %s",
                          control->inputStandardMetadata->name.name.c_str(), errorVar.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->blockStart();
    // TODO: add more info: packet length, ingress port
    msgStr = Util::printf_format("%s control: packet processing started", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    control->emit(builder);
    builder->blockEnd(true);
    msgStr = Util::printf_format("%s control: packet processing finished", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    builder->emitIndent();
    builder->blockStart();
    msgStr = Util::printf_format("%s deparser: packet deparsing started", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    deparser->emit(builder);
    builder->blockEnd(true);
    msgStr = Util::printf_format("%s deparser: packet deparsing finished", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    this->emitTrafficManager(builder);
    builder->blockEnd(true);
}

void EBPFPipeline::emitLocalVariables(CodeBuilder* builder) {
    builder->emitIndent();
    builder->appendFormat("unsigned %s = 0;", offsetVar.c_str());
    builder->appendFormat("unsigned %s_save = 0;", offsetVar.c_str());
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("%s %s = %s;", errorType.c_str(), errorVar.c_str(),
                          P4::P4CoreLibrary::instance.noError.str());
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("void* %s = %s;",
                          packetStartVar.c_str(),
                          builder->target->dataOffset(model.CPacketName.str()).c_str());
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("void* %s = %s;",
                          packetEndVar.c_str(),
                          builder->target->dataEnd(model.CPacketName.str()).c_str());
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("u32 %s = 0;", zeroKey.c_str());
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("unsigned char %s;", byteVar.c_str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("u32 %s = ", lengthVar.c_str());
    emitPacketLength(builder);
    builder->endOfStatement(true);

    if (!this->control->meters.empty()) {
        builder->emitIndent();
        builder->appendFormat("u64 %s = ", timestampVar.c_str());
        emitTimestamp(builder);
        builder->endOfStatement(true);
    }
}

void EBPFPipeline::emitUserMetadataInstance(CodeBuilder* builder) {
    builder->emitIndent();
    auto user_md_type = typeMap->getType(control->user_metadata);
    if (user_md_type == nullptr) {
        ::error("cannot emit user metadata");
    }
    auto userMetadataType = EBPFTypeFactory::instance->create(user_md_type);
    userMetadataType->declare(builder, control->user_metadata->name.name, false);
    builder->append(" = ");
    userMetadataType->emitInitializer(builder);
    builder->endOfStatement(true);
}

void EBPFPipeline::emitHeaderInstances(CodeBuilder* builder) {
    builder->emitIndent();
    // declaring header instance as volatile optimizes stack size and improves throughput
    builder->append("volatile ");
    parser->headerType->declare(builder, parser->headers->name.name, false);
    builder->append(" = ");
    parser->headerType->emitInitializer(builder);
    builder->endOfStatement(true);
}

void EBPFPipeline::emitGlobalMetadataInitializer(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendLine(
            "struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->cb;");
}

void EBPFPipeline::emitPacketLength(CodeBuilder *builder) {
    builder->appendFormat("%s->len", this->contextVar.c_str());
}

void EBPFPipeline::emitTimestamp(CodeBuilder *builder) {
    builder->appendFormat("%s->tstamp", this->contextVar.c_str());
}

// =====================TCIngressPipeline=============================
void TCIngressPipeline::emitTCWorkaroundUsingMeta(CodeBuilder *builder) {
    builder->append("struct internal_metadata *md = "
                    "(struct internal_metadata *)(unsigned long)skb->data_meta;\n");
    builder->emitIndent();
    builder->append("if ((void *) ((struct internal_metadata *) md + 1) > "
                        "(void *)(long)skb->data) {\n"
                        "           return TC_ACT_SHOT;\n"
                        "       }\n");
    builder->append("    __u16 *ether_type = (__u16 *) ((void *) (long)skb->data + 12);\n"
                        "    if ((void *) ((__u16 *) ether_type + 1) > "
                        "    (void *) (long) skb->data_end) {\n"
                        "        return TC_ACT_SHOT;\n"
                        "    }\n"
                        "    *ether_type = md->pkt_ether_type;\n");
}

void TCIngressPipeline::emitTCWorkaroundUsingHead(CodeBuilder *builder) {
    builder->append("    void *data = (void *)(long)skb->data;\n"
                    "    void *data_end = (void *)(long)skb->data_end;\n"
                    "    __u16 *orig_ethtype = data + 14;\n"
                    "    if ((void *)((__u16 *) orig_ethtype + 1) > data_end) {\n"
                    "        return TC_ACT_SHOT;\n"
                    "    }\n"
                    "    __u16 original_ethtype = *orig_ethtype;\n"
                    "    int ret = bpf_skb_adjust_room(skb, -2, 1, 0);\n"
                    "    if (ret < 0) {\n"
                    "        return TC_ACT_SHOT;\n"
                    "    }\n"
                    "    data = (void *)(long)skb->data;\n"
                    "    data_end = (void *)(long)skb->data_end;\n"
                    "    struct ethhdr *eth = data;\n"
                    "    if ((void *)((struct ethhdr *) eth + 1) > data_end) {\n"
                    "        return TC_ACT_SHOT;\n"
                    "    }\n"
                    "    eth->h_proto = original_ethtype;");
}

void TCIngressPipeline::emitTCWorkaroundUsingCPUMAP(CodeBuilder *builder) {
    builder->append("    void *data = (void *)(long)skb->data;\n"
                    "    void *data_end = (void *)(long)skb->data_end;\n"
                    "    u32 zeroKey = 0;\n"
                    "    u16 *orig_ethtype = BPF_MAP_LOOKUP_ELEM(workaround_cpumap, &zeroKey);\n"
                    "    if (!orig_ethtype) {\n"
                    "        return TC_ACT_SHOT;\n"
                    "    }\n"
                    "    struct ethhdr *eth = data;\n"
                    "    if ((void *)((struct ethhdr *) eth + 1) > data_end) {\n"
                    "        return TC_ACT_SHOT;\n"
                    "    }\n"
                    "    eth->h_proto = *orig_ethtype;\n");
}

void TCIngressPipeline::emit(CodeBuilder *builder) {
    cstring msgStr;
    // firstly emit process() in-lined function and then the actual BPF section.
    builder->append("static __always_inline");
    builder->spc();

    builder->appendFormat(
            "int %s(SK_BUFF *%s, %s %s *%s, struct psa_ingress_output_metadata_t *%s, ",
            processFunctionName, model.CPacketName.str(),
            parser->headerType->to<EBPFStructType>()->kind,
            parser->headerType->to<EBPFStructType>()->name,
            parser->headers->name.name,
            control->outputStandardMetadata->name.name);
    auto type = EBPFTypeFactory::instance->create(
            deparser->to<TCIngressDeparserPSA>()->resubmit_meta->type);
    type->declare(builder,
            deparser->to<TCIngressDeparserPSA>()->resubmit_meta->name.name,
            true);
    builder->append(")");
    builder->newline();
    builder->blockStart();
    emitGlobalMetadataInitializer(builder);
    // workaround to make TC protocol-independent, DO NOT REMOVE
    builder->emitIndent();
    // replace ether_type only if a packet comes from XDP
    builder->append("if (meta->packet_path == NORMAL) ");
    builder->blockStart();
    builder->emitIndent();
    if (options.xdp2tcMode == XDP2TC_META) {
        emitTCWorkaroundUsingMeta(builder);
    } else if (options.xdp2tcMode == XDP2TC_HEAD) {
        emitTCWorkaroundUsingHead(builder);
    } else if (options.xdp2tcMode == XDP2TC_CPUMAP) {
        emitTCWorkaroundUsingCPUMAP(builder);
    } else {
        BUG("no xdp2tc mode specified?");
    }
    builder->blockEnd(true);


    emitUserMetadataInstance(builder);
    emitLocalVariables(builder);

    msgStr = Util::printf_format("%s parser: parsing new packet, path=%%d, pkt_len=%%d",
                                 sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str(), 2,
                                      "meta->packet_path", lengthVar.c_str());
    parser->emit(builder);
    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(":");
    builder->newline();
    builder->emitIndent();
    builder->blockStart();
    emitPSAControlDataTypes(builder);
    // TODO: add more info: packet length, ingress port
    msgStr = Util::printf_format("%s control: packet processing started", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    control->emit(builder);
    builder->blockEnd(true);
    msgStr = Util::printf_format("%s control: packet processing finished", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    builder->emitIndent();
    builder->blockStart();

    deparser->emit(builder);
    builder->blockEnd(true);
    builder->emitIndent();
    builder->appendLine("return TC_ACT_UNSPEC;");
    builder->blockEnd(true);

    builder->target->emitCodeSection(builder, sectionName);
    builder->emitIndent();
    builder->target->emitMain(builder, functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();
    builder->emitIndent();

    builder->appendLine("struct psa_ingress_output_metadata_t ostd = {\n"
                        "            .drop = true,\n"
                        "    };");
    builder->newline();

    builder->emitIndent();
    deparser->to<TCIngressDeparserPSA>()->emitSharedMetadataInitializer(builder);


    emitHeaderInstances(builder);

    builder->emitIndent();
    builder->appendLine("int ret = TC_ACT_UNSPEC;");
    builder->emitIndent();
    builder->appendLine("#pragma clang loop unroll(disable)");
    builder->emitIndent();
    builder->appendFormat("for (int i = 0; i < %d; i++) ", maxResubmitDepth);
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("ostd.resubmit = 0;");
    builder->emitIndent();
    builder->appendFormat("ret = %s(skb, ", processFunctionName);

    builder->appendFormat("(%s %s *) &%s, &ostd, &%s);",
            parser->headerType->to<EBPFStructType>()->kind,
            parser->headerType->to<EBPFStructType>()->name,
            parser->headers->name.name,
            deparser->to<TCIngressDeparserPSA>()->resubmit_meta->name.name);
    builder->newline();
    builder->append("        if (ostd.drop == 1 || ostd.resubmit == 0) {\n"
                    "            break;\n"
                    "        }\n");
    builder->emitIndent();
    builder->appendFormat("__builtin_memset((void *) &%s, 0, sizeof(%s %s));",
                          parser->headers->name.name,
                          parser->headerType->to<EBPFStructType>()->kind,
                          parser->headerType->to<EBPFStructType>()->name);
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendLine("if (ret != TC_ACT_UNSPEC) {\n"
                        "        return ret;\n"
                        "    }");

    this->emitTrafficManager(builder);
    builder->blockEnd(true);
}

void TCIngressPipeline::emitPSAControlDataTypes(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct psa_ingress_input_metadata_t %s = {\n"
                        "            .ingress_port = skb->ifindex,\n"
                        "            .packet_path = meta->packet_path,\n"
                        "            .ingress_timestamp = skb->tstamp,\n"
                        "            .parser_error = %s,\n"
                        "    };", control->inputStandardMetadata->name.name, errorVar.c_str());
    builder->newline();
}

/*
 * The Traffic Manager for Ingress pipeline implements:
 * - Multicast handling
 * - send to port
 */
void TCIngressPipeline::emitTrafficManager(CodeBuilder *builder) {
    cstring mcast_grp = Util::printf_format("ostd.multicast_group");
    builder->emitIndent();
    builder->appendFormat("if (%s != 0) ", mcast_grp.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
        "IngressTM: Performing multicast, multicast_group=%u", 1, mcast_grp.c_str());
    builder->emitIndent();
    builder->appendFormat("do_packet_clones(%s, &multicast_grp_tbl, %s, NORMAL_MULTICAST, 2)",
                          contextVar.c_str(), mcast_grp.c_str());
    builder->endOfStatement(true);
    // In multicast mode, unicast packet is not send
    builder->target->emitTraceMessage(builder, "IngressTM: Multicast done, dropping source packet");
    builder->emitIndent();
    builder->appendFormat("return %s", builder->target->dropReturnCode());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendLine("skb->priority = ostd.class_of_service;");

    builder->target->emitTraceMessage(builder,
            "IngressTM: Sending packet out of port %d with priority %d", 2, "ostd.egress_port",
            "ostd.class_of_service");
    builder->emitIndent();
    builder->appendLine("return bpf_redirect(ostd.egress_port, 0);");
}

// =====================TCEgressPipeline=============================
void TCEgressPipeline::emitPSAControlDataTypes(CodeBuilder* builder) {
    cstring outputMdVar, inputMdVar;
    outputMdVar = control->outputStandardMetadata->name.name;
    inputMdVar = control->inputStandardMetadata->name.name;

    builder->emitIndent();
    builder->appendFormat("struct psa_egress_input_metadata_t %s = {\n"
                          "        .class_of_service = skb->priority,\n"
                          "        .egress_port = skb->ifindex,\n"
                          "        .packet_path = meta->packet_path,\n"
                          "        .instance = meta->instance,\n"
                          "        .egress_timestamp = skb->tstamp,\n"
                          "        .parser_error = %s,\n"
                          "    };", inputMdVar.c_str(), errorVar.c_str());
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("if (%s.egress_port == PSA_PORT_RECIRCULATE) ", inputMdVar.c_str());
    builder->blockStart();
    builder->emitIndent();
    // To be conformant with psa.p4, where PSA_PORT_RECIRCULATE is constant
    builder->appendFormat("%s.egress_port = P4C_PSA_PORT_RECIRCULATE", inputMdVar.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendFormat("struct psa_egress_output_metadata_t %s = {\n", outputMdVar.c_str());
    builder->appendLine("        .clone = false,\n"
                        "        .drop = false,\n"
                        "    };");

    builder->newline();
}

void TCEgressPipeline::emitTrafficManager(CodeBuilder *builder) {
    cstring varStr, outputMdVar, inputMdVar;
    outputMdVar = control->outputStandardMetadata->name.name;
    inputMdVar = control->inputStandardMetadata->name.name;

    // clone support
    builder->emitIndent();
    builder->appendFormat("if (%s.clone) ", outputMdVar.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("do_packet_clones(%s, &clone_session_tbl, %s.clone_session_id, "
                          "CLONE_E2E, 3)",
                          contextVar.c_str(), outputMdVar.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->newline();

    // drop support
    builder->emitIndent();
    builder->appendFormat("if (%s.drop) ", outputMdVar.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "EgressTM: Packet dropped due to metadata");
    builder->emitIndent();
    builder->appendFormat("return %s", builder->target->dropReturnCode().c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->newline();

    // recirculation support
    // TODO: pass recirculation metadata
    // TODO: there is parameter type `psa_egress_deparser_input_metadata_t` to the deparser,
    //  maybe it should be used instead of `istd`?
    builder->emitIndent();
    builder->appendFormat("if (%s.egress_port == P4C_PSA_PORT_RECIRCULATE) ", inputMdVar.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "EgressTM: recirculating packet");
    builder->emitIndent();
    builder->appendFormat("meta->packet_path = RECIRCULATE");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("return bpf_redirect(PSA_PORT_RECIRCULATE, BPF_F_INGRESS)",
                          contextVar.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->newline();

    // normal packet to port
    varStr = Util::printf_format("%s->ifindex", contextVar);
    builder->target->emitTraceMessage(builder, "EgressTM: output packet to port %d",
                                      1, varStr.c_str());
    builder->emitIndent();

    builder->newline();

    builder->appendFormat("return %s", builder->target->forwardReturnCode());
    builder->endOfStatement(true);
}

// =====================XDPPipeline====================================
void XDPPipeline::emitPacketLength(CodeBuilder *builder) {
    builder->appendFormat("%s->data_end - %s->data",
                          this->contextVar.c_str(), this->contextVar.c_str());
}
void XDPPipeline::emitTimestamp(CodeBuilder *builder) {
    builder->appendFormat("bpf_ktime_get_ns()");
}

// =====================XDPIngressPipeline=============================
void XDPIngressPipeline::emit(CodeBuilder *builder) {
    cstring msgStr, varStr;

    control->codeGen->asPointerVariables.clear();
    deparser->codeGen->asPointerVariables.clear();
    builder->target->emitCodeSection(builder, sectionName);
    builder->emitIndent();
    builder->appendFormat("int %s(struct xdp_md *%s)", functionName, model.CPacketName.str());
    builder->spc();

    builder->blockStart();

    builder->emitIndent();
    deparser->to<XDPIngressDeparserPSA>()->emitSharedMetadataInitializer(builder);
    builder->newline();


    emitHeaderInstances(builder);
    builder->newline();

    emitUserMetadataInstance(builder);
    builder->newline();

    emitLocalVariables(builder);
    builder->newline();

    builder->emitIndent();
    builder->appendLine("struct psa_ingress_output_metadata_t ostd = {\n"
                        "        .drop = true,\n"
                        "    };");
    builder->newline();

    // PRS
    // we do not support NM, CI2E, CE2E in XDP, so we hardcode NU as packet path
    msgStr = Util::printf_format("%s parser: parsing new packet, path=0", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    parser->emit(builder);
    builder->newline();

    // CTRL
    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(":");
    builder->spc();
    builder->blockStart();
    emitPSAControlDataTypes(builder);
    msgStr = Util::printf_format("%s control: packet processing started", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    control->emit(builder);
    builder->blockEnd(true);
    msgStr = Util::printf_format("%s control: packet processing finished", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    // DEPRS
    builder->emitIndent();
    builder->blockStart();
    msgStr = Util::printf_format("%s deparser: packet deparsing started", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    deparser->emit(builder);
    builder->blockEnd(true);
    msgStr = Util::printf_format("%s deparser: packet deparsing finished", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    this->emitTrafficManager(builder);
    builder->blockEnd(true);
    builder->newline();
}

void XDPIngressPipeline::emitPSAControlDataTypes(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct psa_ingress_input_metadata_t %s = {\n"
                        "        .ingress_port = skb->ingress_ifindex,\n"
                        "        .ingress_timestamp = bpf_ktime_get_ns(),\n"
                        "        .parser_error = %s,\n"
                        "    };", control->inputStandardMetadata->name.name, errorVar.c_str());
    builder->newline();
}

/*
 * The Traffic Manager for Ingress pipeline SHOULD implements:
 * - Multicast handling
 * - send to port
 */
void XDPIngressPipeline::emitTrafficManager(CodeBuilder *builder) {
    cstring mcast_grp = Util::printf_format("ostd.multicast_group");
    builder->emitIndent();
    builder->appendFormat("if (%s != 0) ", mcast_grp.c_str());
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->abortReturnCode().c_str());
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendLine("return bpf_redirect_map(&tx_port, ostd.egress_port, 0);");
}

// =====================XDPEgressPipeline=============================
void XDPEgressPipeline::emit(CodeBuilder* builder) {
    cstring msgStr, varStr;

    control->codeGen->asPointerVariables.clear();
    deparser->codeGen->asPointerVariables.clear();
    builder->target->emitCodeSection(builder, sectionName);
    builder->appendFormat("int %s(struct xdp_md *%s)",
                            functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();

    emitLocalVariables(builder);
    builder->newline();

    emitHeaderInstances(builder);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("struct psa_egress_output_metadata_t %s = {\n",
                          control->outputStandardMetadata->name.name.c_str());
    builder->appendLine("        .clone = false,\n"
                        "        .drop = false,\n"
                        "    };");

    // we do not support NM, CI2E, CE2E in XDP, so we hardcode NU as packet path
    msgStr = Util::printf_format("%s parser: parsing new packet, path=0",
                                    sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    parser->emit(builder);
    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(":");
    builder->newline();
    builder->emitIndent();
    builder->blockStart();
    emitPSAControlDataTypes(builder);
    builder->newline();
    msgStr = Util::printf_format("%s control: packet processing started",
                                    sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    control->emit(builder);
    builder->blockEnd(true);
    msgStr = Util::printf_format("%s control: packet processing finished",
                                    sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    builder->emitIndent();
    builder->blockStart();
    msgStr = Util::printf_format("%s deparser: packet deparsing started",
                                    sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    deparser->emit(builder);
    builder->blockEnd(true);
    msgStr = Util::printf_format("%s deparser: packet deparsing finished",
                                    sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    this->emitTrafficManager(builder);
    builder->newline();
    builder->blockEnd(true);
}

void XDPEgressPipeline::emitPSAControlDataTypes(CodeBuilder* builder) {
    cstring inputMdVar;
    inputMdVar = control->inputStandardMetadata->name.name;

    builder->emitIndent();
    builder->appendFormat("struct psa_egress_input_metadata_t %s = {\n"
                          "        .egress_port = skb->egress_ifindex,\n"
                          "        .egress_timestamp = bpf_ktime_get_ns(),\n"
                          "        .parser_error = %s,\n"
                          "    };", inputMdVar.c_str(), errorVar.c_str());
    builder->newline();
}

void XDPEgressPipeline::emitTrafficManager(CodeBuilder *builder) {
    cstring varStr, outputMdVar, inputMdVar;
    outputMdVar = control->outputStandardMetadata->name.name;
    inputMdVar = control->inputStandardMetadata->name.name;

    builder->newline();
    builder->emitIndent();
    builder->appendFormat("if (%s.clone || %s.drop) ", outputMdVar.c_str(), outputMdVar.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
                                    "EgressTM: Packet dropped due to metadata");
    builder->emitIndent();
    builder->appendFormat("return %s", builder->target->dropReturnCode().c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->newline();

    // normal packet to port
    varStr = Util::printf_format("%s->egress_ifindex", contextVar);
    builder->target->emitTraceMessage(builder,
                                        "EgressTM: output packet to port %d",
                                      1, varStr.c_str());
    builder->emitIndent();
    builder->appendFormat("return %s", builder->target->forwardReturnCode());
    builder->endOfStatement(true);
}

}  // namespace EBPF
