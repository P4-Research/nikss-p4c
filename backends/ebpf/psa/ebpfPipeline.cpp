#include "ebpfPipeline.h"
#include "backends/ebpf/ebpfParser.h"

namespace EBPF {

void EBPFPipeline::emit(CodeBuilder* builder) {
    cstring msgStr, pathStr;
    // Ingress and egress has different variables which are pointers,
    // clearing is needed to not preserving them between pipelines
    control->codeGen->asPointerVariables.clear();

    if (options.generateHdrInMap) {
        control->codeGen->asPointerVariables.insert(control->headers->name.name);
        control->codeGen->asPointerVariables.insert(control->user_metadata->name.name);

        parser->visitor->asPointerVariables.insert(control->user_metadata->name.name);
        deparser->codeGen->asPointerVariables.insert(control->user_metadata->name.name);
    }

    builder->target->emitCodeSection(builder, sectionName);
    builder->emitIndent();
    builder->target->emitMain(builder, functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();
    emitGlobalMetadataInitializer(builder);
    emitUserMetadataInstance(builder);
    emitLocalVariables(builder);
    emitHeaderInstances(builder);
    if (options.generateHdrInMap) {
        emitCPUMAPInitializers(builder);
        builder->newline();
        emitHeadersFromCPUMAP(builder);
        builder->newline();
        emitMetadataFromCPUMAP(builder);
        builder->newline();
    }

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
    builder->newline();
    builder->emitIndent();
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

    if (shouldEmitTimestamp()) {
        builder->emitIndent();
        builder->appendFormat("u64 %s = ", timestampVar.c_str());
        emitTimestamp(builder);
        builder->endOfStatement(true);
    }
}

void EBPFPipeline::emitLocalUserMetadataInstances(CodeBuilder *builder) {
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

void EBPFPipeline::emitCPUMapUserMetadataInstance(CodeBuilder *builder) {
    builder->emitIndent();
    auto user_md_type = typeMap->getType(control->user_metadata);
    if (user_md_type == nullptr) {
        ::error("cannot emit user metadata");
    }
    auto userMetadataType = EBPFTypeFactory::instance->create(user_md_type);
    userMetadataType->declare(builder, control->user_metadata->name.name, true);
    builder->endOfStatement(true);
}
void EBPFPipeline::emitUserMetadataInstance(CodeBuilder *builder) {
    if (!options.generateHdrInMap) {
        emitLocalUserMetadataInstances(builder);
    } else {
        emitCPUMapUserMetadataInstance(builder);
    }
}

void EBPFPipeline::emitLocalHeaderInstances(CodeBuilder *builder) {
    builder->emitIndent();
    // declaring header instance as volatile optimizes stack size and improves throughput
    builder->append("volatile ");
    parser->headerType->declare(builder, parser->headers->name.name, false);
    builder->append(" = ");
    parser->headerType->emitInitializer(builder);
    builder->endOfStatement(true);
}
void EBPFPipeline::emitLocalHeaderInstancesAsPointers(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct %s *%s;",
                        parser->headerType->to<EBPFStructType>()->name,
                        parser->headers->name.name);
    builder->newline();
}
void EBPFPipeline::emitCPUMAPHeadersInitializers(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendLine("struct hdr_md *hdrMd;");
}
void EBPFPipeline::emitCPUMAPHeaderInstances(CodeBuilder *builder) {
    emitCPUMAPHeadersInitializers(builder);
    builder->emitIndent();
    parser->headerType->declare(builder, parser->headers->name.name, true);
    builder->endOfStatement(false);
}
void EBPFPipeline::emitHeaderInstances(CodeBuilder* builder) {
    if (!options.generateHdrInMap) {
        emitLocalHeaderInstances(builder);
    } else {
        emitCPUMAPHeaderInstances(builder);
    }
}

void EBPFPipeline::emitCPUMAPInitializers(CodeBuilder *builder) {
    builder->emitIndent();
    builder->target->emitTableLookup(builder, "hdr_md_cpumap", zeroKey.c_str(), "hdrMd");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!hdrMd)");
    builder->newline();
    builder->emitIndent();
    builder->emitIndent();
    builder->appendFormat("return %s;", dropReturnCode());
    builder->newline();
    builder->emitIndent();
    builder->appendLine("__builtin_memset(hdrMd, 0, sizeof(struct hdr_md));");
}
void EBPFPipeline::emitHeadersFromCPUMAP(CodeBuilder* builder) {
    builder->emitIndent();
    builder->appendFormat("%s = &(hdrMd->cpumap_hdr);", parser->headers->name.name);
}
void EBPFPipeline::emitMetadataFromCPUMAP(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("%s = &(hdrMd->cpumap_usermeta);",
                            control->user_metadata->name.name);
}

void EBPFPipeline::emitGlobalMetadataInitializer(CodeBuilder *builder) {
    builder->emitIndent();
     builder->appendFormat(
            "struct psa_global_metadata *%s = (struct psa_global_metadata *) skb->cb;",
            compilerGlobalMetadata);
    builder->newline();
}

void EBPFPipeline::emitPacketLength(CodeBuilder *builder) {
    if (this->is<XDPIngressPipeline>() || this->is<XDPEgressPipeline>()) {
        builder->appendFormat("%s->data_end - %s->data",
                              this->contextVar.c_str(), this->contextVar.c_str());
    } else {
        builder->appendFormat("%s->len", this->contextVar.c_str());
    }
}

void EBPFPipeline::emitTimestamp(CodeBuilder *builder) {
    builder->appendFormat("bpf_ktime_get_ns()");
}

// =====================EBPFIngressPipeline===========================
void EBPFIngressPipeline::emitPSAControlDataTypes(CodeBuilder *builder) {
        builder->emitIndent();
        builder->appendFormat("struct psa_ingress_input_metadata_t %s = {\n"
                              "            .ingress_port = %s,\n"
                              "            .packet_path = %s,\n"
                              "            .parser_error = %s,\n"
                              "    };",
                              control->inputStandardMetadata->name.name,
                              ifindexVar.c_str(), packetPathVar.c_str(), errorVar.c_str());
        builder->newline();
        if (shouldEmitTimestamp()) {
            builder->emitIndent();
            builder->appendFormat("%s.ingress_timestamp = %s",
                                  control->inputStandardMetadata->name.name,
                                  timestampVar.c_str());
            builder->endOfStatement(true);
        }
}

// =====================EBPFEgressPipeline============================
void EBPFEgressPipeline::emitPSAControlDataTypes(CodeBuilder *builder) {
    cstring outputMdVar, inputMdVar;
    outputMdVar = control->outputStandardMetadata->name.name;
    inputMdVar = control->inputStandardMetadata->name.name;

    builder->emitIndent();
    builder->appendFormat("struct psa_egress_input_metadata_t %s = {\n"
                          "            .class_of_service = %s,\n"
                          "            .egress_port = %s,\n"
                          "            .packet_path = %s,\n"
                          "            .instance = %s,\n"
                          "            .parser_error = %s,\n"
                          "        };",
                          inputMdVar.c_str(),  priorityVar.c_str(), ifindexVar.c_str(),
                          packetPathVar.c_str(), pktInstanceVar.c_str(), errorVar.c_str());
    builder->newline();
    if (shouldEmitTimestamp()) {
        builder->emitIndent();
        builder->appendFormat("%s.egress_timestamp = %s", inputMdVar.c_str(),
                              timestampVar.c_str());
        builder->endOfStatement(true);
    }
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
    builder->appendLine("            .clone = false,\n"
                        "            .drop = false,\n"
                        "        };");

    builder->newline();
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
    cstring varStr;
    // firstly emit process() in-lined function and then the actual BPF section.
    builder->append("static __always_inline");
    builder->spc();

    if (options.generateHdrInMap) {
        parser->visitor->asPointerVariables.insert(control->user_metadata->name.name);
        deparser->codeGen->asPointerVariables.insert(control->user_metadata->name.name);
    }

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
    builder->appendFormat("if (%s->packet_path == NORMAL) ",
                        compilerGlobalMetadata);
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

    emitLocalVariables(builder);

    builder->newline();
    emitUserMetadataInstance(builder);
    if (options.generateHdrInMap) {
        emitCPUMAPHeadersInitializers(builder);
        builder->newline();
        emitCPUMAPInitializers(builder);
        builder->newline();
        emitMetadataFromCPUMAP(builder);
        builder->newline();
        emitHeadersFromCPUMAP(builder);
    }
    builder->newline();

    msgStr = Util::printf_format("%s parser: parsing new packet, path=%%d, pkt_len=%%d",
                                 sectionName);
    varStr = Util::printf_format("%s->packet_path", compilerGlobalMetadata);
    builder->target->emitTraceMessage(builder, msgStr.c_str(), 2,
                                      varStr, lengthVar.c_str());
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
    builder->newline();

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

    if (!options.generateHdrInMap) {
        builder->appendFormat("(%s %s *) &%s, &ostd, &%s);",
                    parser->headerType->to<EBPFStructType>()->kind,
                    parser->headerType->to<EBPFStructType>()->name,
                    parser->headers->name.name,
                    deparser->to<TCIngressDeparserPSA>()->resubmit_meta->name.name);
    } else {
        builder->appendFormat("(%s %s *) %s, &ostd, &%s);",
                    parser->headerType->to<EBPFStructType>()->kind,
                    parser->headerType->to<EBPFStructType>()->name,
                    parser->headers->name.name,
                    deparser->to<TCIngressDeparserPSA>()->resubmit_meta->name.name);
    }
    builder->newline();
    builder->append("        if (ostd.drop == 1 || ostd.resubmit == 0) {\n"
                    "            break;\n"
                    "        }\n");
    builder->emitIndent();
    if (!options.generateHdrInMap) {
        builder->appendFormat("__builtin_memset((void *) &%s, 0, sizeof(%s %s));",
                    parser->headers->name.name,
                    parser->headerType->to<EBPFStructType>()->kind,
                    parser->headerType->to<EBPFStructType>()->name);
    } else {
        builder->appendFormat("__builtin_memset((void *) %s, 0, sizeof(%s %s));",
                    parser->headers->name.name,
                    parser->headerType->to<EBPFStructType>()->kind,
                    parser->headerType->to<EBPFStructType>()->name);
    }
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendLine("if (ret != TC_ACT_UNSPEC) {\n"
                        "        return ret;\n"
                        "    }");

    this->emitTrafficManager(builder);
    builder->blockEnd(true);
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
    builder->appendFormat("return %s", dropReturnCode());
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
    builder->appendFormat("return %s;", dropReturnCode());
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
    builder->appendFormat("%s->packet_path = RECIRCULATE", compilerGlobalMetadata);
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
    builder->emitIndent();
    builder->appendFormat("return %s", forwardReturnCode());
    builder->endOfStatement(true);
}

// =====================XDPIngressPipeline=============================
void XDPIngressPipeline::emit(CodeBuilder *builder) {
    cstring msgStr, varStr;
    control->codeGen->asPointerVariables.clear();
    deparser->codeGen->asPointerVariables.clear();

    if (options.generateHdrInMap) {
        control->codeGen->asPointerVariables.insert(control->headers->name.name);
        control->codeGen->asPointerVariables.insert(control->user_metadata->name.name);
        parser->visitor->asPointerVariables.insert(control->user_metadata->name.name);
        deparser->codeGen->asPointerVariables.insert(control->headers->name.name);
        deparser->codeGen->asPointerVariables.insert(control->user_metadata->name.name);
    }

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

    if (options.generateHdrInMap) {
        emitCPUMAPInitializers(builder);
        builder->newline();
        emitHeadersFromCPUMAP(builder);
        builder->newline();
        emitMetadataFromCPUMAP(builder);
        builder->newline();
    }

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

void XDPIngressPipeline::emitTrafficManager(CodeBuilder *builder) {
    // do not handle multicast; it has been handled earlier by PreDeparser.
    builder->emitIndent();
    builder->appendLine("return bpf_redirect_map(&tx_port, ostd.egress_port%DEVMAP_SIZE, 0);");
}

// =====================XDPEgressPipeline=============================
void XDPEgressPipeline::emit(CodeBuilder* builder) {
    cstring msgStr, varStr;

    control->codeGen->asPointerVariables.clear();
    deparser->codeGen->asPointerVariables.clear();
    if (options.generateHdrInMap) {
        control->codeGen->asPointerVariables.insert(control->headers->name.name);
        control->codeGen->asPointerVariables.insert(control->user_metadata->name.name);

        parser->visitor->asPointerVariables.insert(control->user_metadata->name.name);
        deparser->codeGen->asPointerVariables.insert(control->user_metadata->name.name);
        deparser->codeGen->asPointerVariables.insert(control->headers->name.name);
    }

    builder->target->emitCodeSection(builder, sectionName);
    builder->appendFormat("int %s(struct xdp_md *%s)",
                            functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();

    emitUserMetadataInstance(builder);
    builder->newline();

    emitLocalVariables(builder);
    builder->newline();

    emitHeaderInstances(builder);
    builder->newline();

    if (options.generateHdrInMap) {
        emitCPUMAPInitializers(builder);
        builder->newline();
        emitHeadersFromCPUMAP(builder);
        builder->newline();
        emitMetadataFromCPUMAP(builder);
        builder->newline();
    }

    emitPSAControlDataTypes(builder);

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
    builder->appendFormat("%s.parser_error = %s",
                          control->inputStandardMetadata->name.name.c_str(), errorVar.c_str());
    builder->endOfStatement(true);
    builder->newline();
    builder->emitIndent();
    builder->blockStart();
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
    builder->appendFormat("return %s", dropReturnCode());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->newline();

    // normal packet to port
    varStr = Util::printf_format("%s->egress_ifindex", contextVar);
    builder->target->emitTraceMessage(builder,
                                        "EgressTM: output packet to port %d",
                                      1, varStr.c_str());
    builder->emitIndent();
    builder->appendFormat("return %s", forwardReturnCode());
    builder->endOfStatement(true);
}

// =====================TCTrafficManagerForXDP=============================
void TCTrafficManagerForXDP::emitReadXDP2TCMetadataFromHead(CodeBuilder *builder) {
        builder->emitIndent();
        builder->append("    void *data = (void *)(long)skb->data;\n"
            "    void *data_end = (void *)(long)skb->data_end;\n"
            "    if (((char *) data + 14 + sizeof(struct xdp2tc_metadata)) > (char *) data_end) {\n"
            "        return TC_ACT_SHOT;\n"
            "    }\n");
        builder->emitIndent();
        builder->appendLine("struct xdp2tc_metadata xdp2tc_md = {};");
        builder->emitIndent();
        builder->appendFormat("bpf_skb_load_bytes(%s, 14, &xdp2tc_md, "
                              "sizeof(struct xdp2tc_metadata))",
                              model.CPacketName.str());
        builder->endOfStatement(true);
        builder->emitIndent();
        builder->append("    __u16 *ether_type = (__u16 *) ((void *) (long)skb->data + 12);\n"
                        "    if ((void *) ((__u16 *) ether_type + 1) > "
                        "    (void *) (long) skb->data_end) {\n"
                        "        return TC_ACT_SHOT;\n"
                        "    }\n"
                        "    *ether_type = xdp2tc_md.pkt_ether_type;\n");
        builder->emitIndent();
        builder->appendLine("struct psa_ingress_output_metadata_t ostd = xdp2tc_md.ostd;");
        builder->emitIndent();
        // declaring header instance as volatile optimizes stack size and improves throughput
        if (!options.generateHdrInMap) {
            builder->append("volatile ");
            parser->headerType->declare(builder, parser->headers->name.name, false);
            builder->appendLine(" = xdp2tc_md.headers;");
        } else {
            emitLocalHeaderInstancesAsPointers(builder);
            builder->emitIndent();
            builder->appendFormat("%s = &(xdp2tc_md.headers);", parser->headers->name.name);
            builder->newline();
        }
        builder->emitIndent();
        builder->appendFormat("%s = xdp2tc_md.packetOffsetInBits;", offsetVar.c_str());

        builder->newline();
        builder->emitIndent();
        builder->appendFormat("int ret = bpf_skb_adjust_room(%s, -(int)%s, 1, 0)",
                              model.CPacketName.str(),
                              "sizeof(struct xdp2tc_metadata)");
        builder->endOfStatement(true);
        builder->emitIndent();
        builder->append("if (ret) ");
        builder->blockStart();
        builder->target->emitTraceMessage(builder,
                      "Deparser: failed to remove XDP2TC metadata from packet, ret=%d",
                      1, "ret");
        builder->emitIndent();
        builder->appendFormat("return %s;", builder->target->abortReturnCode().c_str());
        builder->newline();
        builder->blockEnd(true);
}

void TCTrafficManagerForXDP::emitReadXDP2TCMetadataFromCPUMAP(CodeBuilder *builder) {
    builder->emitIndent();
    builder->target->emitTableLookup(builder, "xdp2tc_shared_map", this->zeroKey.c_str(),
                                     "struct xdp2tc_metadata *md");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!md) ");
    builder->blockStart();
    builder->appendFormat("return %s;", dropReturnCode());
    builder->newline();
    builder->blockEnd(true);
    builder->emitIndent();

    builder->emitIndent();
    // declaring header instance as volatile optimizes stack size and improves throughput
    if (!options.generateHdrInMap) {
        builder->append("volatile ");
        parser->headerType->declare(builder, parser->headers->name.name, false);
        builder->appendLine(" = md->headers;");
    } else {
        emitLocalHeaderInstancesAsPointers(builder);
        builder->emitIndent();
        builder->appendFormat("%s = &(md->headers);", parser->headers->name.name);
        builder->newline();
    }
    builder->emitIndent();
    builder->appendLine("struct psa_ingress_output_metadata_t ostd = md->ostd;");
    builder->emitIndent();
    builder->appendFormat("%s = md->packetOffsetInBits;", offsetVar.c_str());

    builder->emitIndent();
    builder->append("    __u16 *ether_type = (__u16 *) ((void *) (long)skb->data + 12);\n"
                    "    if ((void *) ((__u16 *) ether_type + 1) > "
                    "    (void *) (long) skb->data_end) {\n"
                    "        return TC_ACT_SHOT;\n"
                    "    }\n"
                    "    *ether_type = md->pkt_ether_type;\n");

    builder->emitIndent();
}

void TCTrafficManagerForXDP::emit(CodeBuilder *builder) {
    cstring msgStr;
    builder->target->emitCodeSection(builder, sectionName);
    builder->emitIndent();
    builder->target->emitMain(builder, functionName, model.CPacketName.str());
    builder->spc();
    builder->blockStart();
    builder->emitIndent();
    emitLocalVariables(builder);

    if (options.xdp2tcMode == XDP2TC_CPUMAP) {
        emitReadXDP2TCMetadataFromCPUMAP(builder);
    } else if (options.xdp2tcMode == XDP2TC_HEAD) {
        emitReadXDP2TCMetadataFromHead(builder);
    }

    msgStr = Util::printf_format("%s deparser: packet deparsing started", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    builder->emitIndent();
    deparser->emit(builder);
    msgStr = Util::printf_format("%s deparser: packet deparsing finished", sectionName);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    this->emitTrafficManager(builder);

    builder->emitIndent();
    builder->blockEnd(true);
}
}  // namespace EBPF
