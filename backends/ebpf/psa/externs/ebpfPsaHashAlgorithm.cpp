#include "ebpfPsaHashAlgorithm.h"
#include "backends/ebpf/ebpfProgram.h"
#include "backends/ebpf/ebpfType.h"

namespace EBPF {

EBPFHashAlgorithmPSA::argumentsList EBPFHashAlgorithmPSA::unpackArguments(
        const IR::MethodCallExpression * expr, int dataPos) {
    BUG_CHECK(expr->arguments->size() > ((size_t) dataPos),
              "Data position %1% is outside of the arguments: %2%", dataPos, expr);

    std::vector<const IR::Expression *> arguments;

    if (expr->arguments->at(dataPos)->expression->is<IR::ListExpression>()) {
        auto argList = expr->arguments->at(dataPos)->expression->to<IR::ListExpression>();
        for (auto field : argList->components)
            arguments.push_back(field);
    } else {
        arguments.push_back(expr->arguments->at(dataPos)->expression);
    }

    return arguments;
}

void EBPFHashAlgorithmPSA::emitVariables(CodeBuilder* builder,
                                         const IR::Declaration_Instance* decl) {
    (void) builder; (void) decl;
}

void EBPFHashAlgorithmPSA::emitClear(CodeBuilder *builder) {
    (void) builder;
}

void EBPFHashAlgorithmPSA::emitAddData(CodeBuilder *builder, int dataPos,
                                       const IR::MethodCallExpression *expr) {
    emitAddData(builder, unpackArguments(expr, dataPos));
}

void EBPFHashAlgorithmPSA::emitAddData(CodeBuilder* builder, const argumentsList & arguments) {
    (void) builder; (void) arguments;
}

void EBPFHashAlgorithmPSA::emitGet(CodeBuilder *builder) {
    (void) builder;
}

void EBPFHashAlgorithmPSA::emitSubtractData(CodeBuilder *builder, int dataPos,
                                            const IR::MethodCallExpression *expr) {
    emitSubtractData(builder, unpackArguments(expr, dataPos));
}

void EBPFHashAlgorithmPSA::emitSubtractData(CodeBuilder *builder,
                                            const argumentsList & arguments) {
    (void) builder; (void) arguments;
}

void EBPFHashAlgorithmPSA::emitGetInternalState(CodeBuilder *builder) {
    (void) builder;
}

void EBPFHashAlgorithmPSA::emitSetInternalState(CodeBuilder *builder,
                                                const IR::MethodCallExpression *expr) {
    (void) builder; (void) expr;
}

// ===========================InternetChecksumAlgorithm===========================

void InternetChecksumAlgorithm::updateChecksum(CodeBuilder* builder,
                                               const argumentsList & arguments,
                                               bool addData) {
    cstring tmpVar = program->refMap->newName(baseName + "_tmp");

    builder->emitIndent();
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("u16 %s = 0", tmpVar.c_str());
    builder->endOfStatement(true);

    int remainingBits = 16, bitsToRead;
    for (auto field : arguments) {
        auto fieldType = field->type->to<IR::Type_Bits>();
        if (fieldType == nullptr) {
            ::error(ErrorType::ERR_UNSUPPORTED, "Only bits types are supported %1%", field);
            return;
        }
        const int width = fieldType->width_bits();
        bitsToRead = width;

        if (width > 64) {
            BUG("Fields wider than 64 bits are not supported yet", field);
        }

        while (bitsToRead > 0) {
            if (remainingBits == 16) {
                builder->emitIndent();
                builder->appendFormat("%s = ", tmpVar.c_str());
            } else {
                builder->append(" | ");
            }

            // TODO: add masks for fields, however they should not exceed declared width
            if (bitsToRead < remainingBits) {
                remainingBits -= bitsToRead;
                builder->append("(");
                visitor->visit(field);
                builder->appendFormat(" << %d)", remainingBits);
                bitsToRead = 0;
            } else if (bitsToRead == remainingBits) {
                remainingBits = 0;
                visitor->visit(field);
                bitsToRead = 0;
            } else if (bitsToRead > remainingBits) {
                bitsToRead -= remainingBits;
                remainingBits = 0;
                builder->append("(");
                visitor->visit(field);
                builder->appendFormat(" >> %d)", bitsToRead);
            }

            if (remainingBits == 0) {
                remainingBits = 16;
                builder->endOfStatement(true);

                // update checksum
                builder->target->emitTraceMessage(builder, "InternetChecksum: word=0x%llx",
                                                  1, tmpVar.c_str());
                builder->emitIndent();
                if (addData) {
                    builder->appendFormat("%s = csum16_add(%s, %s)", stateVar.c_str(),
                                          stateVar.c_str(), tmpVar.c_str());
                } else {
                    builder->appendFormat("%s = csum16_sub(%s, %s)", stateVar.c_str(),
                                          stateVar.c_str(), tmpVar.c_str());
                }
                builder->endOfStatement(true);
            }
        }
    }

    builder->target->emitTraceMessage(builder, "InternetChecksum: new state=0x%llx",
                                      1, stateVar.c_str());
    builder->blockEnd(true);
}

void InternetChecksumAlgorithm::emitGlobals(CodeBuilder* builder) {
    builder->appendLine("inline u16 csum16_add(u16 csum, u16 addend) {\n"
                        "    u16 res = csum;\n"
                        "    res += addend;\n"
                        "    return (res + (res < addend));\n"
                        "}\n"
                        "inline u16 csum16_sub(u16 csum, u16 addend) {\n"
                        "    return csum16_add(csum, ~addend);\n"
                        "}");
}

void InternetChecksumAlgorithm::emitVariables(CodeBuilder* builder,
                                              const IR::Declaration_Instance* decl) {
    (void) decl;
    stateVar = program->refMap->newName(baseName + "_state");
    builder->emitIndent();
    builder->appendFormat("u16 %s = 0", stateVar.c_str());
    builder->endOfStatement(true);
}

void InternetChecksumAlgorithm::emitClear(CodeBuilder* builder) {
    builder->emitIndent();
    builder->appendFormat("%s = 0", stateVar.c_str());
    builder->endOfStatement(true);
}

void InternetChecksumAlgorithm::emitAddData(CodeBuilder* builder,
                                            const argumentsList & arguments) {
    updateChecksum(builder, arguments, true);
}

void InternetChecksumAlgorithm::emitGet(CodeBuilder* builder) {
    builder->appendFormat("((u16) (~%s))", stateVar.c_str());
}

void InternetChecksumAlgorithm::emitSubtractData(CodeBuilder* builder,
                                                 const argumentsList & arguments) {
    updateChecksum(builder, arguments, false);
}

void InternetChecksumAlgorithm::emitGetInternalState(CodeBuilder* builder) {
    builder->append(stateVar);
}

// FIXME: works for constant value, but might not for other cases
void InternetChecksumAlgorithm::emitSetInternalState(CodeBuilder* builder,
                                                     const IR::MethodCallExpression * expr) {
    if (expr->arguments->size() != 1) {
        ::error(ErrorType::ERR_UNEXPECTED, "Expected exactly 1 argument %1%", expr);
        return;
    }
    builder->emitIndent();
    builder->appendFormat("%s = ", stateVar.c_str());
    visitor->visit(expr->arguments->at(0)->expression);
    builder->endOfStatement(true);
}

// ===========================CRCChecksumAlgorithm===========================

cstring CRCChecksumAlgorithm::reflect(cstring str) {
    BUG_CHECK(crcWidth <= 64, "CRC checksum width up to 64 bits is supported");
    unsigned long long poly = std::stoull(str.c_str(), nullptr, 16);
    unsigned long long result, i, j;

    result = 0;
    i = 1ull << (crcWidth - 1);
    j = 1;

    for (; i != 0; i >>=1, j <<= 1) {
        if (i & poly)
            result |= j;
    }

    return Util::printf_format("%llu", result);
}

void CRCChecksumAlgorithm::emitUpdateMethod(CodeBuilder* builder, int crcWidth) {
    // Note that this update method is optimized for our CRC16 and CRC32, custom
    // version may require other method of update. To deal with byte order data
    // is read from the end of buffer.
    cstring code = "static __always_inline\n"
        "void crc%w%_update(u%w% * reg, const u8 * data, u16 data_size, const u%w% poly) {\n"
        "    data += data_size - 1;\n"
        "    for (u16 i = 0; i < data_size; i++) {\n"
        "        bpf_trace_message(\"CRC%w%: data byte: %x\\n\", *data);\n"
        "        *reg ^= *data;\n"
        "        for (u8 bit = 0; bit < 8; bit++) {\n"
        "            *reg = (*reg) & 1 ? ((*reg) >> 1) ^ poly : (*reg) >> 1;\n"
        "        }\n"
        "        data--;\n"
        "    }\n"
        "}";
    code = code.replace("%w%", Util::printf_format("%d", crcWidth));
    builder->appendLine(code);
}

void CRCChecksumAlgorithm::emitVariables(CodeBuilder* builder,
                                         const IR::Declaration_Instance* decl) {
    registerVar = program->refMap->newName(baseName + "_reg");

    builder->emitIndent();

    if (decl != nullptr) {
        BUG_CHECK(decl->type->is<IR::Type_Specialized>(), "Must be a specialized type %1%", decl);
        auto ts = decl->type->to<IR::Type_Specialized>();
        BUG_CHECK(ts->arguments->size() == 1, "Expected 1 specialized type %1%", decl);

        auto otype = ts->arguments->at(0);
        if (!otype->is<IR::Type_Bits>()) {
            ::error(ErrorType::ERR_UNSUPPORTED, "Must be bit or int type: %1%", ts);
            return;
        }
        if (otype->width_bits() != crcWidth) {
            ::error(ErrorType::ERR_TYPE_ERROR, "Must be %1%-bits width: %2%", crcWidth, ts);
            return;
        }

        auto registerType = EBPFTypeFactory::instance->create(otype);
        registerType->emit(builder);
    } else {
        if (crcWidth == 16)
            builder->append("u16");
        else if (crcWidth == 32)
            builder->append("u32");
        else
            BUG("Unsupported CRC width %1%", crcWidth);
    }

    builder->appendFormat(" %s = %s", registerVar.c_str(), initialValue.c_str());
    builder->endOfStatement(true);
}

void CRCChecksumAlgorithm::emitClear(CodeBuilder* builder) {
    builder->emitIndent();
    builder->appendFormat("%s = %s", registerVar.c_str(), initialValue.c_str());
    builder->endOfStatement(true);
}

void CRCChecksumAlgorithm::emitAddData(CodeBuilder* builder,
                                       const argumentsList & arguments) {
    cstring tmpVar = program->refMap->newName(baseName + "_tmp");

    builder->emitIndent();
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("u8 %s = 0", tmpVar.c_str());
    builder->endOfStatement(true);

    bool concatenateBits = false;
    int remainingBits = 8;
    for (auto field : arguments) {
        auto fieldType = field->type->to<IR::Type_Bits>();
        if (fieldType == nullptr) {
            ::error(ErrorType::ERR_UNSUPPORTED, "Only bits types are supported %1%", field);
            return;
        }
        const int width = fieldType->width_bits();

        if (width < 8 || concatenateBits) {
            concatenateBits = true;
            if (width > remainingBits) {
                ::error(ErrorType::ERR_UNSUPPORTED,
                        "Sub-byte fields have to be aligned to bytes %1%", field);
                return;
            }
            if (remainingBits == 8) {
                // start processing sub-byte fields
                builder->emitIndent();
                builder->appendFormat("%s = ", tmpVar.c_str());
            } else {
                builder->append(" | ");
            }

            remainingBits -= width;
            builder->append("(");
            visitor->visit(field);
            builder->appendFormat(" << %d)", remainingBits);

            if (remainingBits == 0) {
                // last bit, update the crc
                concatenateBits = false;
                builder->endOfStatement(true);
                builder->emitIndent();
                builder->appendFormat("%s(&%s, &%s, 1, %s)", updateMethod.c_str(),
                                      registerVar.c_str(), tmpVar.c_str(), polynomial.c_str());
                builder->endOfStatement(true);
            }
        } else {
            // fields larger than 8 bits
            if (width % 8 != 0) {
                ::error(ErrorType::ERR_UNSUPPORTED,
                        "Fields larger than 8 bits have to be aligned to bytes %1%", field);
                return;
            }
            builder->emitIndent();
            builder->appendFormat("%s(&%s, (u8 *) &(", updateMethod.c_str(), registerVar.c_str());
            visitor->visit(field);
            builder->appendFormat("), %d, %s)", width / 8, polynomial.c_str());
            builder->endOfStatement(true);
        }
    }

    cstring varStr = Util::printf_format("(u64) %s", registerVar.c_str());
    builder->target->emitTraceMessage(builder, "CRC: checksum state: %llx", 1, varStr.c_str());

    cstring final_crc = Util::printf_format("(u64) %s(%s, %s)", finalizeMethod.c_str(),
                                            registerVar.c_str(), polynomial.c_str());
    builder->target->emitTraceMessage(builder, "CRC: final checksum: %llx", 1, final_crc.c_str());

    builder->blockEnd(true);
}

void CRCChecksumAlgorithm::emitGet(CodeBuilder* builder) {
    builder->appendFormat("%s(%s, %s)", finalizeMethod.c_str(),
                          registerVar.c_str(), polynomial.c_str());
}

void CRCChecksumAlgorithm::emitSubtractData(CodeBuilder* builder,
                                            const argumentsList & arguments) {
    (void) builder; (void) arguments;
    BUG("Not implementable");
}

void CRCChecksumAlgorithm::emitGetInternalState(CodeBuilder* builder) {
    (void) builder;
    BUG("Not implemented");
}

void CRCChecksumAlgorithm::emitSetInternalState(CodeBuilder* builder,
                                                const IR::MethodCallExpression * expr) {
    (void) builder; (void) expr;
    BUG("Not implemented");
}

// ===========================CRC16ChecksumAlgorithm===========================

void CRC16ChecksumAlgorithm::emitGlobals(CodeBuilder* builder) {
    CRCChecksumAlgorithm::emitUpdateMethod(builder, 16);

    cstring code ="static __always_inline "
        "u16 crc16_finalize(u16 reg, const u16 poly) {\n"
        "    return reg;\n"
        "}";
    builder->appendLine(code);
}

// ===========================CRC32ChecksumAlgorithm===========================

void CRC32ChecksumAlgorithm::emitGlobals(CodeBuilder* builder) {
    CRCChecksumAlgorithm::emitUpdateMethod(builder, 32);

    cstring code = "static __always_inline "
        "u32 crc32_finalize(u32 reg, const u32 poly) {\n"
        "    return reg ^ 0xFFFFFFFF;\n"
        "}";
    builder->appendLine(code);
}


}  // namespace EBPF