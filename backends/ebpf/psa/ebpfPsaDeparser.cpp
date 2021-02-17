#include "ebpfPsaDeparser.h"
#include "ebpfPipeline.h"

namespace EBPF {

void EBPFPsaDeparser::emit(CodeBuilder* builder) {
    builder->emitIndent();
    this->headerType->declare(builder, this->headers->name.name, false);
    builder->append(" = ");
    this->headerType->emitInitializer(builder);
    builder->endOfStatement(true);

    this->hdrVoidPointerVar = this->headers->name.name + this->hdrVoidPointerVar;
    builder->emitIndent();
    builder->appendFormat("void* %s = (void*)(&%s);",
                          this->hdrVoidPointerVar, this->headers->name.name);
    builder->newline();

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
        builder->newline();
		builder->emitIndent();
		builder->emitIndent();
        builder->appendFormat("%s += %d;", this->outerHdrLengthVar.c_str(), width);
        builder->newline();
    }

    builder->newline();
    builder->emitIndent();
    builder->appendFormat("int %s = BYTES(%s) - BYTES(%s)",
                          this->outerHdrOffsetVar.c_str(),
                          this->outerHdrLengthVar.c_str(),
                          pipelineProgram->offsetVar.c_str());
    builder->endOfStatement(true);
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
    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::reject.c_str());
    builder->newline();
    builder->blockEnd(true);

//    builder->emitIndent();
//    builder->appendFormat("%s += %s",
//                          pipelineProgram->lengthVar.c_str(),
//                          this->outerHdrOffsetVar.c_str());
//    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("%s = 0", pipelineProgram->offsetVar.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->newline();
    for (unsigned long i = 0; i < this->headersToEmit.size(); i++) {
        auto headerToEmit = headersToEmit[i];
        auto headerExpression = headersExpressions[i];
        emitHeader(builder, headerToEmit, headerExpression);
    }
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("%s = bpf_skb_store_bytes(%s, 0, %s, BYTES(%s), 0)",
                          this->returnCode.c_str(),
                          pipelineProgram->contextVar.c_str(),
                          this->hdrVoidPointerVar.c_str(),
                          this->outerHdrLengthVar.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("if (%s) ", this->returnCode.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::reject.c_str());
    builder->newline();
    builder->blockEnd(true);
}

void EBPFPsaDeparser::emitHeader(CodeBuilder* builder, const IR::Type_Header* headerToEmit,
                                 cstring& headerExpression) const {
    const EBPFPipeline* pipelineProgram = dynamic_cast<const EBPFPipeline*>(program);
    builder->emitIndent();
    builder->append("if (");
    builder->append(headerExpression);
    builder->append(".ebpf_valid) ");
    builder->blockStart();
    auto program = EBPFControl::program;
    unsigned width = headerToEmit->width_bits();
    builder->emitIndent();
    builder->appendFormat("if (%s->len < BYTES(%s + %d)) ",
                          pipelineProgram->contextVar.c_str(),
                          program->offsetVar.c_str(), width);
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::reject.c_str());
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
    builder->blockEnd(true);
}

void EBPFPsaDeparser::emitField(CodeBuilder* builder, cstring headerExpression,
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
    cstring swap = "";
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
                    this->hdrVoidPointerVar.c_str(),
                    program->offsetVar.c_str(),
                    widthToEmit > 64 ? bytes - i - 1 : i,  // reversed order for wider fields
                    program->byteVar.c_str());
        } else {  // write partial
            shift = (8 - alignment - bitsToWrite);
            builder->appendFormat(
                    "write_partial(%s + BYTES(%s) + %d, %d, %d, (%s >> %d))",
                    this->hdrVoidPointerVar.c_str(),
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
                        this->hdrVoidPointerVar.c_str(),
                        program->offsetVar.c_str(),
                        widthToEmit > 64 ? bytes - i - 1 : i,  // reversed order for wider fields
                        program->byteVar.c_str(),
                        8 - alignment % 8);
            } else {
                builder->appendFormat(
                        "write_partial(%s + BYTES(%s) + %d + 1, %d, %d, (%s))",
                        this->hdrVoidPointerVar.c_str(),
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

}  // namespace EBPF
