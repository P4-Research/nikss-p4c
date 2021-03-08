#include "ebpfPsaDeparser.h"
#include "ebpfPipeline.h"

namespace EBPF {

DeparserBodyTranslator::DeparserBodyTranslator(const EBPFDeparserPSA *deparser) :
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
    if (method->method->name.name == "emit") {
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

void EBPFDeparserPSA::emit(CodeBuilder* builder) {
    codeGen->setBuilder(builder);

    for (auto a : controlBlock->container->controlLocals)
        emitDeclaration(builder, a);

    controlBlock->container->body->apply(*codeGen);
    builder->newline();

    emitPreDeparser(builder);

    const EBPFPipeline* pipelineProgram = dynamic_cast<const EBPFPipeline*>(program);
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
        builder->append(".ebpf_valid) ");
        builder->blockStart();
        builder->emitIndent();
        builder->appendFormat("%s += %d;", this->outerHdrLengthVar.c_str(), width);
        builder->newline();
        builder->blockEnd(true);
    }

    builder->newline();
    builder->emitIndent();
    builder->appendFormat("int %s = BYTES(%s) - BYTES(%s)",
                          this->outerHdrOffsetVar.c_str(),
                          this->outerHdrLengthVar.c_str(),
                          pipelineProgram->offsetVar.c_str());
    builder->endOfStatement(true);
    builder->target->emitTraceMessage(builder, "Deparser: pkt_len adjusting by %d B",
                                      1, this->outerHdrOffsetVar.c_str());

    builder->emitIndent();
    builder->appendFormat("int %s = 0", this->returnCode.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("%s = bpf_skb_adjust_room(%s, %s, 1, 0)",
                          this->returnCode.c_str(),
                          pipelineProgram->contextVar.c_str(),
                          this->outerHdrOffsetVar.c_str());
    builder->endOfStatement(true);

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
    builder->appendFormat("%s = 0", pipelineProgram->offsetVar.c_str());
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

// =====================EBPFIngressDeparserPSA=============================
bool EBPFIngressDeparserPSA::build() {
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
void EBPFIngressDeparserPSA::emitPreDeparser(CodeBuilder *builder) {
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
    builder->appendLine("meta->packet_path = RESUBMIT;");
    builder->emitIndent();
    builder->appendLine("return TC_ACT_UNSPEC;");
    builder->blockEnd(true);
}

void EBPFIngressDeparserPSA::emitSharedMetadataInitializer(CodeBuilder *builder) {
    auto type = EBPFTypeFactory::instance->create(resubmit_meta->type);
    type->declare(builder, resubmit_meta->name.name, false);
    builder->endOfStatement(true);
}

// =====================EBPFEgressDeparserPSA=============================
bool EBPFEgressDeparserPSA::build() {
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
}  // namespace EBPF
