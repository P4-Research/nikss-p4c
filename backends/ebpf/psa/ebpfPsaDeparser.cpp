#include "ebpfPsaDeparser.h"
#include "ebpfPipeline.h"

namespace EBPF {

DeparserBodyTranslator::DeparserBodyTranslator(const EBPFDeparserPSA *deparser) :
                        CodeGenInspector(deparser->program->refMap, deparser->program->typeMap),
                        ControlBodyTranslator(deparser), deparser(deparser) {
    setName("DeparserBodyTranslator");
}

void DeparserBodyTranslator::processFunction(const P4::ExternFunction *function) {
    if (function->method->name.name == "psa_resubmit") {
        builder->appendFormat("!%s->drop && %s->resubmit",
                              deparser->istd->name.name, deparser->istd->name.name);
    }
}

void DeparserBodyTranslator::processMethod(const P4::ExternMethod *method) {
    auto externName = method->originalExternType->name.name;
    if (externName == "InternetChecksum" || externName == "Checksum") {
        auto instance = method->object->getName().name;
        auto methodName = method->method->getName().name;
        deparser->getChecksum(instance)->processMethod(builder, methodName, method->expr, this);
        return;
    } else if (method->method->name.name == "emit") {
        // do not use visitor to generate emit() methods
        return;
    } else if (method->method->name.name == "pack") {
        // Emit digest pack method
        auto obj = method->object;
        auto di = obj->to<IR::Declaration_Instance>();
        auto arg = method->expr->arguments->front();
        builder->appendFormat("bpf_map_push_elem(&%s, &", di->name.name);
        this->visit(arg);
        builder->appendFormat(", BPF_EXIST)");
        return;
    }
    ControlBodyTranslator::processMethod(method);
}

void EBPFDeparserPSA::emitPreparePacketBuffer(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("int %s = 0", this->outerHdrLengthVar.c_str());
    builder->endOfStatement(true);

    for (unsigned long i = 0; i < this->headersToEmit.size(); i++) {
        auto headerToEmit = headersToEmit[i];
        auto headerExpression = headersExpressions[i];
        unsigned width = headerToEmit->width_bits();
        builder->emitIndent();
        builder->append("if (");
        builder->append(headerExpression);
        if (program->options.xdpEgressOptimization && this->is<XDPIngressDeparserPSA>()) {
            builder->append(".ingress_ebpf_valid) ");
        } else {
            builder->append(".ebpf_valid) ");
        }
        builder->blockStart();
        builder->emitIndent();
        builder->appendFormat("%s += %d;", this->outerHdrLengthVar.c_str(), width);
        builder->newline();
        builder->blockEnd(true);
    }

    builder->newline();
    builder->emitIndent();

    cstring offsetVar = "";
    if (program->options.xdpEgressOptimization && this->is<XDPIngressDeparserPSA>()) {
        offsetVar = "ingress_" + program->offsetVar;
    } else if (program->options.xdpEgressOptimization && this->is<XDPEgressDeparserPSA>()) {
        offsetVar = "egress_" + program->offsetVar;
    } else {
        offsetVar = program->offsetVar;
    }
    builder->appendFormat("int %s = BYTES(%s) - BYTES(%s)",
                          this->outerHdrOffsetVar.c_str(),
                          this->outerHdrLengthVar.c_str(),
                          offsetVar.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("if (%s != 0) ", this->outerHdrOffsetVar.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjusting by %d B",
                                      1, this->outerHdrOffsetVar.c_str());
    builder->emitIndent();
    builder->appendFormat("int %s = 0", this->returnCode.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    emitResizeHead(builder);

    builder->emitIndent();
    builder->appendFormat("if (%s) ", this->returnCode.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjust failed");
    builder->emitIndent();
    // We immediately return instead of jumping to reject state.
    // It avoids reaching BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    builder->appendFormat("return %s;", builder->target->abortReturnCode().c_str());
    builder->newline();
    builder->blockEnd(true);
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjusted");
    builder->blockEnd(true);
}

void EBPFDeparserPSA::emit(CodeBuilder* builder) {
    codeGen->setBuilder(builder);

    for (auto a : controlBlock->container->controlLocals)
        emitDeclaration(builder, a);

    emitDeparserExternCalls(builder);
    builder->newline();

    emitPreDeparser(builder);
    emitPreparePacketBuffer(builder);

    builder->emitIndent();
    builder->appendFormat("%s = %s;",
                          program->packetStartVar,
                          builder->target->dataOffset(program->model.CPacketName.str()));
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("%s = %s;",
                          program->packetEndVar,
                          builder->target->dataEnd(program->model.CPacketName.str()));
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("%s = 0", program->offsetVar.c_str());
    builder->endOfStatement(true);

    for (unsigned long i = 0; i < this->headersToEmit.size(); i++) {
        auto headerToEmit = headersToEmit[i];
        auto headerExpression = headersExpressions[i];
        emitHeader(builder, headerToEmit, headerExpression);
    }
    builder->newline();
}

void EBPFDeparserPSA::emitHeader(CodeBuilder* builder, const IR::Type_Header* headerToEmit,
                                 cstring& headerExpression) const {
    cstring msgStr;
    builder->emitIndent();
    builder->append("if (");
    builder->append(headerExpression);
    builder->append(".ebpf_valid) ");
    builder->blockStart();
    auto program = EBPFControl::program;
    unsigned width = headerToEmit->width_bits();
    msgStr = Util::printf_format("Deparser: emitting header %s", headerExpression);
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    builder->emitIndent();
    builder->appendFormat("if (%s < %s + BYTES(%s + %d)) ",
                          program->packetEndVar.c_str(),
                          program->packetStartVar.c_str(),
                          program->offsetVar.c_str(), width);
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Deparser: invalid packet (packet too short)");
    builder->emitIndent();
    // We immediately return instead of jumping to reject state.
    // It avoids reaching BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    builder->appendFormat("return %s;", builder->target->abortReturnCode().c_str());
    builder->newline();
    builder->blockEnd(true);
    builder->emitIndent();
    builder->newline();
    unsigned alignment = 0;
    for (auto f : headerToEmit->fields) {
        auto ftype = this->program->typeMap->getType(f);
        auto etype = EBPFTypeFactory::instance->create(ftype);
        auto et = dynamic_cast<EBPF::IHasWidth *>(etype);
        if (et == nullptr) {
            ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                    "Only headers with fixed widths supported %1%", f);
            return;
        }
        emitField(builder, headerExpression, f->name, alignment, etype);
        alignment += et->widthInBits();
        alignment %= 8;
    }
    msgStr = Util::printf_format("Deparser: emitted %s", headerExpression);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    builder->blockEnd(true);
}

void EBPFDeparserPSA::emitField(CodeBuilder* builder, cstring headerExpression,
                                cstring field, unsigned int alignment,
                                EBPF::EBPFType* type) const {
    auto et = dynamic_cast<EBPF::IHasWidth *>(type);
    if (et == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "Only headers with fixed widths supported %1%", headerExpression);
        return;
    }
    unsigned widthToEmit = et->widthInBits();
    unsigned loadSize = 0;
    cstring swap = "", msgStr;

    if (widthToEmit <= 64) {
        cstring tmp = Util::printf_format("(unsigned long long) %s.%s",
                                          headerExpression, field);
        msgStr = Util::printf_format("Deparser: emitting field %s=0x%%llx (%u bits)",
                                     field, widthToEmit);
        builder->target->emitTraceMessage(builder, msgStr.c_str(), 1, tmp.c_str());
    } else {
        msgStr = Util::printf_format("Deparser: emitting field %s (%u bits)", field, widthToEmit);
        builder->target->emitTraceMessage(builder, msgStr.c_str());
    }

    if (widthToEmit <= 8) {
        loadSize = 8;
    } else if (widthToEmit <= 16) {
        swap = "bpf_htons";
        loadSize = 16;
    } else if (widthToEmit <= 32) {
        swap = "htonl";
        loadSize = 32;
    } else if (widthToEmit <= 64) {
        swap = "htonll";
        loadSize = 64;
    }
    unsigned bytes = ROUNDUP(widthToEmit, 8);
    unsigned shift = widthToEmit < 8 ?
                     (loadSize - alignment - widthToEmit) : (loadSize - widthToEmit);
    if (!swap.isNullOrEmpty()) {
        builder->emitIndent();
        builder->append(headerExpression);
        builder->appendFormat(".%s = %s(", field.c_str(), swap);
        builder->append(headerExpression);
        builder->appendFormat(".%s", field.c_str());
        if (shift != 0)
            builder->appendFormat(" << %d", shift);
        builder->append(")");
        builder->endOfStatement(true);
    }
    unsigned bitsInFirstByte = widthToEmit % 8;
    if (bitsInFirstByte == 0) bitsInFirstByte = 8;
    unsigned bitsInCurrentByte = bitsInFirstByte;
    unsigned left = widthToEmit;
    for (unsigned i = 0; i < (widthToEmit + 7) / 8; i++) {
        builder->emitIndent();
        builder->appendFormat("%s = ((char*)(&", program->byteVar.c_str());
        builder->append(headerExpression);
        builder->appendFormat(".%s))[%d]", field.c_str(), i);
        builder->endOfStatement(true);
        unsigned freeBits = alignment != 0 ? (8 - alignment) : 8;
        bitsInCurrentByte = left >= 8 ? 8 : left;
        unsigned bitsToWrite =
                bitsInCurrentByte > freeBits ? freeBits : bitsInCurrentByte;
        BUG_CHECK((bitsToWrite > 0) && (bitsToWrite <= 8),
                  "invalid bitsToWrite %d", bitsToWrite);
        builder->emitIndent();
        if (alignment == 0 && bitsToWrite == 8) {  // write whole byte
            builder->appendFormat(
                    "write_byte(%s, BYTES(%s) + %d, (%s))",
                    program->packetStartVar.c_str(),
                    program->offsetVar.c_str(),
                    widthToEmit > 64 ? bytes - i - 1 : i,  // reversed order for wider fields
                    program->byteVar.c_str());
        } else {  // write partial
            shift = (8 - alignment - bitsToWrite);
            builder->appendFormat(
                    "write_partial(%s + BYTES(%s) + %d, %d, %d, (%s >> %d))",
                    program->packetStartVar.c_str(),
                    program->offsetVar.c_str(),
                    widthToEmit > 64 ? bytes - i - 1 : i,  // reversed order for wider fields
                    bitsToWrite,
                    shift,
                    program->byteVar.c_str(),
                    widthToEmit > freeBits ? alignment == 0 ? shift : alignment : 0);
        }
        builder->endOfStatement(true);
        left -= bitsToWrite;
        bitsInCurrentByte -= bitsToWrite;
        alignment = (alignment + bitsToWrite) % 8;
        bitsToWrite = (8 - bitsToWrite);
        if (bitsInCurrentByte > 0) {
            builder->emitIndent();
            if (bitsToWrite == 8) {
                builder->appendFormat(
                        "write_byte(%s, BYTES(%s) + %d + 1, (%s << %d))",
                        program->packetStartVar.c_str(),
                        program->offsetVar.c_str(),
                        widthToEmit > 64 ? bytes - i - 1 : i,  // reversed order for wider fields
                        program->byteVar.c_str(),
                        8 - alignment % 8);
            } else {
                builder->appendFormat(
                        "write_partial(%s + BYTES(%s) + %d + 1, %d, %d, (%s))",
                        program->packetStartVar.c_str(),
                        program->offsetVar.c_str(),
                        widthToEmit > 64 ? bytes - i - 1 : i,  // reversed order for wider fields
                        bitsToWrite,
                        8 + alignment - bitsToWrite,
                        program->byteVar.c_str());
            }
            builder->endOfStatement(true);
            left -= bitsToWrite;
        }
        alignment = (alignment + bitsToWrite) % 8;
    }
    builder->emitIndent();
    builder->appendFormat("%s += %d", program->offsetVar.c_str(),
                          widthToEmit);
    builder->endOfStatement(true);

    msgStr = Util::printf_format("Deparser: emitted %s", field);
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    builder->newline();
}

void EBPFDeparserPSA::emitDigestInstances(CodeBuilder* builder) const {
    for (auto digest : digests) {
        builder->appendFormat("REGISTER_TABLE(%s, %s, 0, sizeof( ",
                              digest.first, "BPF_MAP_TYPE_QUEUE");
        auto type = EBPFTypeFactory::instance->create(digest.second->to<IR::Type_Type>()->type);
        type->declare(builder, "", false);
        builder->appendFormat("), %d)", maxDigestQueueSize);
        builder->newline();
    }
}

void EBPFDeparserPSA::emitDeclaration(CodeBuilder* builder, const IR::Declaration* decl) {
    if (decl->is<IR::Declaration_Instance>()) {
        auto di = decl->to<IR::Declaration_Instance>();
        auto type = di->type->to<IR::Type_Name>();
        auto typeSpec = di->type->to<IR::Type_Specialized>();
        cstring name = di->name.name;

        if (type != nullptr && type->path->name.name == "InternetChecksum") {
            auto instance = new EBPFInternetChecksumPSA(program, di, name);
            checksums.emplace(name, instance);
            instance->emitVariables(builder);
            return;
        }

        if (typeSpec != nullptr &&
                typeSpec->baseType->to<IR::Type_Name>()->path->name.name == "Checksum") {
            auto instance = new EBPFChecksumPSA(program, di, name);
            checksums.emplace(name, instance);
            instance->emitVariables(builder);
            return;
        }
    }

    EBPFControlPSA::emitDeclaration(builder, decl);
}

void TCDeparserPSA::emitResizeHead(CodeBuilder *builder) {
    builder->appendFormat("%s = bpf_skb_adjust_room(%s, %s, 1, 0)",
                          this->returnCode.c_str(),
                          program->model.CPacketName.str(),
                          this->outerHdrOffsetVar.c_str());
    builder->endOfStatement(true);
}

// =====================TCIngressDeparserPSA=============================
bool TCIngressDeparserPSA::build() {
    auto pl = controlBlock->container->type->applyParams;
    auto it = pl->parameters.begin();
    packet_out = *it;
    headers = *(it + 4);
    resubmit_meta = *(it + 2);

    auto ht = program->typeMap->getType(headers);
    if (ht == nullptr) {
        return false;
    }
    headerType = EBPFTypeFactory::instance->create(ht);

    codeGen->asPointerVariables.insert(resubmit_meta->name.name);
    codeGen->substitute(this->headers, parserHeaders);
    return true;
}

/*
 * PreDeparser for Ingress pipeline implements:
 * - packet cloning (using clone sessions)
 * - early packet drop
 * - resubmission
 */
void TCIngressDeparserPSA::emitPreDeparser(CodeBuilder *builder) {
    builder->emitIndent();

    builder->newline();
    builder->emitIndent();

    // clone support
    builder->appendFormat("if (%s->clone) ", istd->name.name);
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("do_packet_clones(%s, &clone_session_tbl, %s->clone_session_id,"
                          " CLONE_I2E, 1);", program->model.CPacketName.str(), istd->name.name);
    builder->newline();
    builder->blockEnd(true);

    // early drop
    builder->emitIndent();
    builder->appendFormat("if (%s->drop) ", istd->name.name);
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "PreDeparser: dropping packet..");
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->abortReturnCode().c_str());
    builder->blockEnd(true);

    // if packet should be resubmitted, we skip deparser
    builder->emitIndent();
    builder->appendFormat("if (%s->resubmit) ", istd->name.name);
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "PreDeparser: resubmitting packet, "
                                               "skipping deparser..");
    builder->emitIndent();
    const EBPFPipeline* pipelineProgram = dynamic_cast<const EBPFPipeline*>(program);
    builder->appendFormat("%s->packet_path = RESUBMIT;",
                    pipelineProgram->compilerGlobalMetadata);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("return TC_ACT_UNSPEC;");
    builder->blockEnd(true);
}

void TCIngressDeparserPSA::emitSharedMetadataInitializer(CodeBuilder *builder) {
    auto type = EBPFTypeFactory::instance->create(resubmit_meta->type);
    type->declare(builder, resubmit_meta->name.name, false);
    builder->endOfStatement(true);
}

// =====================TCIngressDeparserForTrafficManagerPSA===========
void TCIngressDeparserForTrafficManagerPSA::emitPreDeparser(CodeBuilder *builder) {
    // clone support
    builder->appendFormat("if (%s.clone) ", this->istd->name.name);
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("do_packet_clones(%s, &clone_session_tbl, %s.clone_session_id,"
                          " CLONE_I2E, 1);",
                          program->model.CPacketName.str(),
                          this->istd->name.name);
    builder->newline();
    builder->blockEnd(true);
}

// =====================TCEgressDeparserPSA=============================
bool TCEgressDeparserPSA::build() {
    auto pl = controlBlock->container->type->applyParams;
    auto it = pl->parameters.begin();
    packet_out = *it;
    headers = *(it + 3);

    auto ht = program->typeMap->getType(headers);
    if (ht == nullptr) {
        return false;
    }
    headerType = EBPFTypeFactory::instance->create(ht);

    return true;
}

void XDPDeparserPSA::emitResizeHead(CodeBuilder *builder) {
    builder->appendFormat("%s = bpf_xdp_adjust_head(%s, -%s)",
                          this->returnCode.c_str(),
                          program->model.CPacketName.str(),
                          this->outerHdrOffsetVar.c_str());
    builder->endOfStatement(true);
}

// =====================XDPIngressDeparserPSA=============================
bool XDPIngressDeparserPSA::build() {
    auto pl = controlBlock->container->type->applyParams;
    auto it = pl->parameters.begin();
    packet_out = *it;
    headers = *(it + 4);
    resubmit_meta = *(it + 2);

    auto ht = program->typeMap->getType(headers);
    if (ht == nullptr) {
        return false;
    }
    headerType = EBPFTypeFactory::instance->create(ht);

    codeGen->asPointerVariables.insert(resubmit_meta->name.name);
    codeGen->substitute(this->headers, parserHeaders);
    return true;
}

/*
 * 
 */
void XDPIngressDeparserPSA::emitPreDeparser(CodeBuilder *builder) {
    builder->emitIndent();
    // perform early multicast detection; if multicast is invoked, a packet will be
    // passed up anyway, so we can do deparsing entirely in TC
    builder->appendFormat("if (%s.clone || %s.multicast_group != 0) ",
                          istd->name.name,
                          istd->name.name);
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("struct xdp2tc_metadata xdp2tc_md = {};");
    builder->emitIndent();
    if (program->options.generateHdrInMap) {
        builder->appendFormat("xdp2tc_md.headers = *%s", this->headers->name.name);
    } else {
        builder->appendFormat("xdp2tc_md.headers = %s", this->headers->name.name);
    }

    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("xdp2tc_md.ostd = %s", this->istd->name.name);
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("xdp2tc_md.packetOffsetInBits = %s", this->program->offsetVar);
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("    void *data = (void *)(long)skb->data;\n"
                    "    void *data_end = (void *)(long)skb->data_end;\n"
                    "    struct ethhdr *eth = data;\n"
                    "    if ((void *)((struct ethhdr *) eth + 1) > data_end) {\n"
                    "        return XDP_ABORTED;\n"
                    "    }\n"
                    "    xdp2tc_md.pkt_ether_type = eth->h_proto;\n"
                    "    eth->h_proto = bpf_htons(0x0800);\n");
    if (program->options.xdp2tcMode == XDP2TC_HEAD) {
        builder->emitIndent();
        builder->appendFormat("int ret = bpf_xdp_adjust_head(%s, -(int)%s)",
                              program->model.CPacketName.str(),
                              "sizeof(struct xdp2tc_metadata)");
        builder->endOfStatement(true);
        builder->emitIndent();
        builder->append("if (ret) ");
        builder->blockStart();
        builder->target->emitTraceMessage(builder, "Deparser: failed to push XDP2TC metadata");
        builder->emitIndent();
        builder->appendFormat("return %s;", builder->target->abortReturnCode().c_str());
        builder->newline();
        builder->blockEnd(true);
        builder->emitIndent();
        builder->append("    data = (void *)(long)skb->data;\n"
            "    data_end = (void *)(long)skb->data_end;\n"
            "    if (((char *) data + 14 + sizeof(struct xdp2tc_metadata)) > (char *) data_end) {\n"
            "        return XDP_ABORTED;\n"
            "    }\n");
        builder->appendLine("__builtin_memmove(data, data + sizeof(struct xdp2tc_metadata), 14);");
        builder->appendLine("__builtin_memcpy(data + 14, "
                            "&xdp2tc_md, sizeof(struct xdp2tc_metadata));");
    } else if (program->options.xdp2tcMode == XDP2TC_CPUMAP) {
        builder->emitIndent();
        builder->target->emitTableUpdate(builder, "xdp2tc_shared_map",
                                         this->program->zeroKey.c_str(), "xdp2tc_md");
        builder->newline();
    }
    builder->target->emitTraceMessage(builder,
                                      "Sending packet up to TC for cloning");
    builder->emitIndent();
    builder->appendFormat("return %s", builder->target->forwardReturnCode());
    builder->endOfStatement(true);
    builder->blockEnd(true);
    builder->emitIndent();
    builder->appendFormat("if (%s.drop || %s.resubmit) ",
                           istd->name.name, istd->name.name);
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "PreDeparser: dropping packet..");
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->abortReturnCode().c_str());
    builder->blockEnd(true);
}

void XDPIngressDeparserPSA::emitSharedMetadataInitializer(CodeBuilder *builder) {
    auto type = EBPFTypeFactory::instance->create(resubmit_meta->type);
    type->declare(builder, resubmit_meta->name.name, false);
    builder->endOfStatement(true);
}

// =====================XDPEgressDeparserPSA=============================
bool XDPEgressDeparserPSA::build() {
    auto pl = controlBlock->container->type->applyParams;
    auto it = pl->parameters.begin();
    packet_out = *it;
    headers = *(it + 3);

    auto ht = program->typeMap->getType(headers);
    if (ht == nullptr) {
        return false;
    }
    headerType = EBPFTypeFactory::instance->create(ht);

    return true;
}

void XDPEgressDeparserPSA::emitPreDeparser(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("if (%s.drop) ",
                          istd->name.name);
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "PreDeparser: dropping packet..");
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->abortReturnCode().c_str());
    builder->blockEnd(true);
}


void OptimizedXDPIngressDeparserPSA::emitHeader(CodeBuilder *builder, const IR::Type_Header *headerToEmit,
                                                cstring &headerExpression) const {
    cstring msgStr;
    builder->emitIndent();
    builder->append("if (");
    builder->append(headerExpression);
    builder->append(".ingress_ebpf_valid) ");
    builder->blockStart();
    auto program = EBPFControl::program;
    unsigned width = headerToEmit->width_bits();
    msgStr = Util::printf_format("Deparser: emitting header %s", headerExpression);
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    builder->emitIndent();
    builder->appendFormat("if (%s < %s + BYTES(%s + %d)) ",
                          program->packetEndVar.c_str(),
                          program->packetStartVar.c_str(),
                          program->offsetVar.c_str(), width);
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Deparser: invalid packet (packet too short)");
    builder->emitIndent();
    // We immediately return instead of jumping to reject state.
    // It avoids reaching BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    builder->appendFormat("return %s;", builder->target->abortReturnCode().c_str());
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->newline();
    unsigned alignment = 0;
    for (auto f : headerToEmit->fields) {
        auto ftype = this->program->typeMap->getType(f);
        auto etype = EBPFTypeFactory::instance->create(ftype);
        auto et = dynamic_cast<EBPF::IHasWidth *>(etype);
        if (et == nullptr) {
            ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                    "Only headers with fixed widths supported %1%", f);
            return;
        }
        emitField(builder, headerExpression, f->name, alignment, etype);
        alignment += et->widthInBits();
        alignment %= 8;
    }
    msgStr = Util::printf_format("Deparser: emitted %s", headerExpression);
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    builder->blockEnd(true);
}


// =====================OptimizedCombinedDeparser=============================
void OptimizedCombinedDeparser::emit(CodeBuilder *builder) {
    // emit firstly ingress deparser
    ig_dprs->codeGen->setBuilder(builder);

    for (auto a : ig_dprs->controlBlock->container->controlLocals)
        ig_dprs->emitDeclaration(builder, a);
    for (auto a : eg_dprs->controlBlock->container->controlLocals)
        eg_dprs->emitDeclaration(builder, a);

    ig_dprs->emitDeparserExternCalls(builder);
    builder->newline();

    ig_dprs->emitPreDeparser(builder);

    builder->emitIndent();
    builder->appendFormat("int %s = 0", ig_dprs->outerHdrLengthVar.c_str());
    builder->endOfStatement(true);

    for (unsigned long i = 0; i < ig_dprs->headersToEmit.size(); i++) {
        auto headerToEmit = ig_dprs->headersToEmit[i];
        auto headerExpression = ig_dprs->headersExpressions[i];
        unsigned width = headerToEmit->width_bits();
        builder->emitIndent();
        builder->append("if (");
        builder->append(headerExpression);
        builder->append(".ingress_ebpf_valid) ");
        builder->blockStart();
        builder->emitIndent();
        builder->appendFormat("%s += %d;", ig_dprs->outerHdrLengthVar.c_str(), width);
        builder->newline();
        builder->blockEnd(true);
    }

    builder->newline();
    builder->emitIndent();

    cstring offsetVar =  "ingress_" + ig_dprs->program->offsetVar;
    builder->appendFormat("int %s = BYTES(%s) - BYTES(%s)",
                          ig_dprs->outerHdrOffsetVar.c_str(),
                          ig_dprs->outerHdrLengthVar.c_str(),
                          offsetVar.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("int %s = 0", eg_dprs->outerHdrLengthVar.c_str());
    builder->endOfStatement(true);

    for (auto const& el : removedHeadersToEmit) {
        auto headerToEmit = el.second;
        auto headerExpression = el.first;
        unsigned width = headerToEmit->width_bits();
        builder->emitIndent();
        builder->append("if (");
        builder->append(headerExpression);
        builder->append(".ebpf_valid) ");
        builder->blockStart();
        builder->emitIndent();
        builder->appendFormat("%s += %d;", eg_dprs->outerHdrLengthVar.c_str(), width);
        builder->newline();
        builder->blockEnd(true);
    }

    for (unsigned long i = 0; i < eg_dprs->headersToEmit.size(); i++) {
        auto headerToEmit = eg_dprs->headersToEmit[i];
        auto headerExpression = eg_dprs->headersExpressions[i];
        unsigned width = headerToEmit->width_bits();
        builder->emitIndent();
        builder->append("if (");
        builder->append(headerExpression);
        builder->append(".ebpf_valid) ");
        builder->blockStart();
        builder->emitIndent();
        builder->appendFormat("%s += %d;", eg_dprs->outerHdrLengthVar.c_str(), width);
        builder->newline();
        builder->blockEnd(true);
    }

    builder->newline();

    offsetVar =  "egress_" + eg_dprs->program->offsetVar;
    builder->emitIndent();
    builder->appendFormat("int %s = BYTES(%s) - BYTES(%s)",
                          eg_dprs->outerHdrOffsetVar.c_str(),
                          eg_dprs->outerHdrLengthVar.c_str(),
                          offsetVar.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("int total_outHeaderOffset = %s + %s",
                          ig_dprs->outerHdrOffsetVar, eg_dprs->outerHdrOffsetVar);
    builder->endOfStatement(true);
    builder->emitIndent();

    builder->append("if (total_outHeaderOffset != 0) ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjusting by %d B",
                                      1, "total_outHeaderOffset");
    builder->emitIndent();
    builder->appendFormat("int %s = 0", ig_dprs->returnCode.c_str());
    builder->endOfStatement(true);


    builder->emitIndent();
    builder->appendFormat("%s = bpf_xdp_adjust_head(%s, -total_outHeaderOffset)",
                          eg_dprs->returnCode.c_str(),
                          eg_dprs->program->model.CPacketName.str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("if (%s) ", eg_dprs->returnCode.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjust failed");
    builder->emitIndent();
    // We immediately return instead of jumping to reject state.
    // It avoids reaching BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    builder->appendFormat("return %s;", builder->target->abortReturnCode().c_str());
    builder->newline();
    builder->blockEnd(true);
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjusted");
    builder->emitIndent();
    builder->appendFormat("%s = %s;",
                          ig_dprs->program->packetStartVar,
                          builder->target->dataOffset(ig_dprs->program->model.CPacketName.str()));
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("%s = %s;",
                          ig_dprs->program->packetEndVar,
                          builder->target->dataEnd(ig_dprs->program->model.CPacketName.str()));
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendFormat("%s = 0", ig_dprs->program->offsetVar.c_str());
    builder->endOfStatement(true);

    for (unsigned long i = 0; i < ig_dprs->headersToEmit.size(); i++) {
        auto headerToEmit = ig_dprs->headersToEmit[i];
        auto headerExpression = ig_dprs->headersExpressions[i];
        ig_dprs->emitHeader(builder, headerToEmit, headerExpression);
    }
    builder->newline();

    eg_dprs->emitPreDeparser(builder);

    builder->emitIndent();
    builder->appendFormat("%s = %d", eg_dprs->program->offsetVar.c_str(), egressStartPacketOffset);
    builder->endOfStatement(true);

    for (unsigned long i = 0; i < eg_dprs->headersToEmit.size(); i++) {
        auto headerToEmit = eg_dprs->headersToEmit[i];
        auto headerExpression = eg_dprs->headersExpressions[i];
        eg_dprs->emitHeader(builder, headerToEmit, headerExpression);
    }
    builder->newline();
}

bool OptimizedCombinedDeparser::isProcessedByParserStates(const IR::IndexedVector<IR::ParserState> states, cstring hdrName) {
    for (auto state : states) {
        for (auto c : state->components) {
            if (c->is<IR::MethodCallStatement>()) {
                auto mce = c->to<IR::MethodCallStatement>()->methodCall;
                auto mi = P4::MethodInstance::resolve(mce,
                                                      eg_dprs->program->refMap,
                                                      eg_dprs->program->typeMap);
                auto extMethod = mi->to<P4::ExternMethod>();
                if (extMethod != nullptr) {
                    auto extractedHdr = extMethod->expr->arguments->at(0)->expression;
                    if (extractedHdr->is<IR::Member>() &&
                        extractedHdr->to<IR::Member>()->expr->is<IR::PathExpression>()) {
                        auto name = extractedHdr->to<IR::Member>()->member.name;
                        auto headers = extractedHdr->to<IR::Member>()->expr->to<IR::PathExpression>()->path->name.name;
                        if (headers + "." + name == hdrName) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool OptimizedCombinedDeparser::isEmittedByDeparser(EBPFDeparserPSA *deparser, cstring hdrName) {
    return std::find(deparser->headersExpressions.begin(),
                     deparser->headersExpressions.end(),
                     hdrName) != deparser->headersExpressions.end();
}

void OptimizedCombinedDeparser::optimizeHeadersToEmit(EBPFOptimizedEgressParserPSA* eg_prs) {
    // remove headers from ingress deparser that are deparsed at ingress, but are removed from packet by egress.
    for (unsigned long i = 0; i < ig_dprs->headersToEmit.size(); i++) {
        cstring hdr = ig_dprs->headersExpressions[i];
        if (isEmittedByDeparser(ig_dprs, hdr) && isProcessedByParserStates(eg_prs->parserBlock->states, hdr) &&
            !isEmittedByDeparser(eg_dprs, hdr)) {
            eg_prs->headersToSkipMovingOffset.insert(ig_dprs->headersExpressions[i]);
            ig_dprs->headersToEmit.erase(ig_dprs->headersToEmit.begin() + (unsigned int) i);
            ig_dprs->headersExpressions.erase(ig_dprs->headersExpressions.begin() + (unsigned int) i);
        }
    }

    /*
     * Optimize a common case:
     * if the first header to emit in both ingress and egress is the same,
     * remove it from egress deparser.
     * Continue removing until we meet inconsistency between ingress and egress deparser.
     * Once we met inconsistency, we cannot do the same for further headers.
     */
    for (unsigned long i = 0; i < ig_dprs->headersToEmit.size(); i++) {
        cstring hdr = ig_dprs->headersExpressions[i];

        if (eg_dprs->headersExpressions.size() == 0) {
            break;
        }

        if (hdr == eg_dprs->headersExpressions[i]) {
            removedHeadersToEmit.emplace(hdr, eg_dprs->headersToEmit[i]);
            egressStartPacketOffset += eg_dprs->headersToEmit[i]->width_bits();
            eg_dprs->headersToEmit.erase(std::find(
                    eg_dprs->headersToEmit.begin(),
                    eg_dprs->headersToEmit.end(),
                    eg_dprs->headersToEmit[i]));
            eg_dprs->headersExpressions.erase(std::find(
                    eg_dprs->headersExpressions.begin(),
                    eg_dprs->headersExpressions.end(),
                    eg_dprs->headersExpressions[i]));
        } else {
            break;
        }
    }

}

}  // namespace EBPF
