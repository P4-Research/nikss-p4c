#include "ebpfPsaDeparser.h"
#include "ebpfPipeline.h"

namespace EBPF {

DeparserBodyTranslator::DeparserBodyTranslator(const EBPFDeparserPSA *deparser) :
                        CodeGenInspector(deparser->program->refMap, deparser->program->typeMap),
                        ControlBodyTranslator(deparser), deparser(deparser) {
    setName("DeparserBodyTranslator");
}

bool DeparserBodyTranslator::preorder(const IR::MethodCallExpression* expression) {
    auto mi = P4::MethodInstance::resolve(expression,
                                          control->program->refMap,
                                          control->program->typeMap);
    auto ext = mi->to<P4::ExternMethod>();
    if (ext != nullptr) {
        // We skip headers emit processing which is handled by DeparserHdrEmitTranslator
        if (ext->method->name.name == p4lib.packetOut.emit.name)
            return false;
    }

    return ControlBodyTranslator::preorder(expression);
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
    } else if (method->method->name.name == p4lib.packetOut.emit.name) {
        // do not use this visitor to generate emit() methods
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

DeparserPrepareBufferTranslator::DeparserPrepareBufferTranslator(const EBPFDeparserPSA *deparser) :
        CodeGenInspector(deparser->program->refMap, deparser->program->typeMap),
        ControlBodyTranslator(deparser), deparser(deparser) {
    setName("DeparserPrepareBufferTranslator");
}

bool DeparserPrepareBufferTranslator::preorder(const IR::BlockStatement* s) {
    for (auto a : s->components) {
        if (auto method = a->to<IR::MethodCallStatement>()) {
            if (auto expr = method->methodCall->method->to<IR::Member>()) {
                if (expr->member.name == p4lib.packetOut.emit.name) {
                    visit(a);
                }
            }
        }
    }

    return false;
}

bool DeparserPrepareBufferTranslator::preorder(const IR::MethodCallExpression* expression) {
    auto mi = P4::MethodInstance::resolve(expression,
                                          control->program->refMap,
                                          control->program->typeMap);
    auto ext = mi->to<P4::ExternMethod>();
    if (ext != nullptr) {
        processMethod(ext);
        return false;
    }

    return false;
}

void DeparserPrepareBufferTranslator::processMethod(const P4::ExternMethod *method) {
    if (method->method->name.name == p4lib.packetOut.emit.name) {
        auto decl = method->object;
        if (decl == deparser->packet_out) {
            auto expr = method->expr->arguments->at(0)->expression;
            auto exprType = deparser->program->typeMap->getType(expr);
            auto headerToEmit = exprType->to<IR::Type_Header>();
            if (headerToEmit == nullptr) {
                ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                        "Cannot emit a non-header type %1%", expr);
            }

            unsigned width = headerToEmit->width_bits();
            builder->emitIndent();
            builder->append("if (");
            this->visit(expr);
            builder->append(".ebpf_valid) ");
            builder->blockStart();
            builder->emitIndent();
            builder->appendFormat("%s += %d;",
                                  this->deparser->outerHdrLengthVar.c_str(), width);
            builder->newline();
            builder->blockEnd(true);
        }
    }
}

DeparserHdrEmitTranslator::DeparserHdrEmitTranslator(const EBPFDeparserPSA *deparser) :
        CodeGenInspector(deparser->program->refMap, deparser->program->typeMap),
        DeparserPrepareBufferTranslator(deparser), deparser(deparser) {
    setName("DeparserHdrEmitTranslator");
}

void DeparserHdrEmitTranslator::processMethod(const P4::ExternMethod *method) {
    if (method->method->name.name == p4lib.packetOut.emit.name) {
        auto decl = method->object;
        if (decl == deparser->packet_out) {
            auto expr = method->expr->arguments->at(0)->expression;
            auto exprType = deparser->program->typeMap->getType(expr);
            auto headerToEmit = exprType->to<IR::Type_Header>();
            if (headerToEmit == nullptr) {
                ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                        "Cannot emit a non-header type %1%", expr);
            }

            cstring msgStr;
            builder->emitIndent();
            builder->append("if (");
            this->visit(expr);
            builder->append(".ebpf_valid) ");
            builder->blockStart();
            auto program = deparser->program;
            unsigned width = headerToEmit->width_bits();
            msgStr = Util::printf_format("Deparser: emitting header %s",
                                         expr->toString().c_str());
            builder->target->emitTraceMessage(builder, msgStr.c_str());

            builder->emitIndent();
            builder->appendFormat("if (%s < %s + BYTES(%s + %d)) ",
                                  program->packetEndVar.c_str(),
                                  program->packetStartVar.c_str(),
                                  program->offsetVar.c_str(), width);
            builder->blockStart();
            builder->target->emitTraceMessage(builder,
                                              "Deparser: invalid packet (packet too short)");
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
                auto ftype = deparser->program->typeMap->getType(f);
                auto etype = EBPFTypeFactory::instance->create(ftype);
                auto et = dynamic_cast<EBPF::IHasWidth *>(etype);
                if (et == nullptr) {
                    ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                            "Only headers with fixed widths supported %1%", f);
                    return;
                }
                emitField(builder, f->name, expr, alignment, etype);
                alignment += et->widthInBits();
                alignment %= 8;
            }
            builder->blockEnd(true);
        }
    }
}

void DeparserHdrEmitTranslator::emitField(CodeBuilder* builder, cstring field,
                                          const IR::Expression* hdrExpr, unsigned int alignment,
                                          EBPF::EBPFType* type) {
    auto program = deparser->program;

    auto et = dynamic_cast<EBPF::IHasWidth *>(type);
    if (et == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "Only headers with fixed widths supported %1%", hdrExpr);
        return;
    }
    unsigned widthToEmit = et->widthInBits();
    unsigned loadSize = 0;
    cstring swap = "", msgStr;

    if (widthToEmit <= 64) {
        cstring tmp = Util::printf_format("(unsigned long long) %s.%s",
                                          hdrExpr->toString(), field);
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
        visit(hdrExpr);
        builder->appendFormat(".%s = %s(", field, swap);
        visit(hdrExpr);
        builder->appendFormat(".%s", field);
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
        visit(hdrExpr);
        builder->appendFormat(".%s))[%d]", field, i);
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
    builder->newline();
}

void EBPFDeparserPSA::emit(CodeBuilder* builder) {
    codeGen->setBuilder(builder);
    codeGen->asPointerVariables.insert(this->headers->name.name);

    for (auto a : controlBlock->container->controlLocals)
        emitDeclaration(builder, a);

    emitDeparserExternCalls(builder);
    builder->newline();

    emitPreDeparser(builder);

    builder->emitIndent();
    builder->appendFormat("int %s = 0", this->outerHdrLengthVar.c_str());
    builder->endOfStatement(true);

    auto prepareBufferTranslator = new DeparserPrepareBufferTranslator(this);
    prepareBufferTranslator->setBuilder(builder);
    prepareBufferTranslator->asPointerVariables.insert(this->headers->name.name);
    prepareBufferTranslator->substitute(this->headers, this->parserHeaders);
    controlBlock->container->body->apply(*prepareBufferTranslator);

    emitBufferAdjusts(builder);

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

    // emit headers
    auto hdrEmitTranslator = new DeparserHdrEmitTranslator(this);
    hdrEmitTranslator->setBuilder(builder);
    hdrEmitTranslator->asPointerVariables.insert(this->headers->name.name);
    hdrEmitTranslator->substitute(this->headers, this->parserHeaders);
    controlBlock->container->body->apply(*hdrEmitTranslator);

    builder->newline();
}

void EBPFDeparserPSA::emitBufferAdjusts(CodeBuilder *builder) const {
    builder->newline();
    builder->emitIndent();

    cstring offsetVar = program->offsetVar;
    builder->appendFormat("int %s = BYTES(%s) - BYTES(%s)",
                          outerHdrOffsetVar.c_str(),
                          outerHdrLengthVar.c_str(),
                          offsetVar.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("if (%s != 0) ", outerHdrOffsetVar.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjusting by %d B",
                                      1, outerHdrOffsetVar.c_str());
    builder->emitIndent();
    builder->appendFormat("int %s = 0", returnCode.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("%s = ", returnCode.c_str());
    program->target->emitResizeBuffer(builder, program->model.CPacketName.str(),
                                       outerHdrOffsetVar);
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("if (%s) ", returnCode.c_str());
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

void EBPFDeparserPSA::emitDigestInstances(CodeBuilder* builder) const {
    for (auto digest : digests) {
        builder->appendFormat("REGISTER_TABLE_NO_KEY_TYPE(%s, %s, 0, ",
                              digest.first, "BPF_MAP_TYPE_QUEUE");
        auto type = EBPFTypeFactory::instance->create(digest.second->to<IR::Type_Type>()->type);
        type->declare(builder, "", false);
        builder->appendFormat(", %d)", maxDigestQueueSize);
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

// =====================IngressDeparserPSA=============================
bool IngressDeparserPSA::build() {
    auto pl = controlBlock->container->type->applyParams;
    auto it = pl->parameters.begin();
    packet_out = *it;
    headers = *(it + 4);
    user_metadata = *(it + 5);
    resubmit_meta = *(it + 2);

    auto ht = program->typeMap->getType(headers);
    if (ht == nullptr) {
        return false;
    }
    headerType = EBPFTypeFactory::instance->create(ht);

    codeGen->asPointerVariables.insert(resubmit_meta->name.name);
    codeGen->asPointerVariables.insert(user_metadata->name.name);
    codeGen->substitute(this->headers, parserHeaders);
    return true;
}

// =====================EgressDeparserPSA=============================
bool EgressDeparserPSA::build() {
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

// =====================TCIngressDeparserPSA=============================
/*
 * PreDeparser for Ingress pipeline implements:
 * - packet cloning (using clone sessions)
 * - early packet dropEBPFProgram
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

// =====================TCIngressDeparserForTrafficManagerPSA===========
void TCIngressDeparserForTrafficManagerPSA::emitPreDeparser(CodeBuilder *builder) {
    // clone support
    builder->emitIndent();
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

// =====================XDPIngressDeparserPSA=============================
void XDPIngressDeparserPSA::emitPreDeparser(CodeBuilder *builder) {
    builder->emitIndent();
    // perform early multicast detection; if multicast is invoked, a packet will be
    // passed up anyway, so we can do deparsing entirely in TC
    builder->appendFormat("if (%s->clone || %s->multicast_group != 0) ",
                          istd->name.name,
                          istd->name.name);
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("struct xdp2tc_metadata xdp2tc_md = {};");
    builder->emitIndent();
    builder->appendFormat("xdp2tc_md.headers = *%s", this->parserHeaders->name.name);

    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("xdp2tc_md.ostd = *%s", this->istd->name.name);
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
    builder->appendFormat("if (%s->drop) ",
                           istd->name.name, istd->name.name);
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
    builder->appendFormat("%s->packet_path = RESUBMIT;",
                          program->to<EBPFPipeline>()->compilerGlobalMetadata);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("return -1;");
    builder->blockEnd(true);
}

// =====================XDPEgressDeparserPSA=============================
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

}  // namespace EBPF
