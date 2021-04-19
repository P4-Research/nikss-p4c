#include "ebpfPsaHashAlgorithm.h"
#include "backends/ebpf/ebpfProgram.h"

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

// ===========================InternetChecksumAlgorithm===========================

void InternetChecksumAlgorithm::updateChecksum(CodeBuilder* builder, int dataPos,
                                               const IR::MethodCallExpression * expr,
                                               bool addData) {
    cstring tmpVar = program->refMap->newName(baseName + "_tmp");

    builder->emitIndent();
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("u16 %s = 0", tmpVar.c_str());
    builder->endOfStatement(true);

    auto arguments = unpackArguments(expr, dataPos);

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

void InternetChecksumAlgorithm::emitAddData(CodeBuilder* builder, int dataPos,
                                            const IR::MethodCallExpression * expr) {
    updateChecksum(builder, dataPos, expr, true);
}

void InternetChecksumAlgorithm::emitGet(CodeBuilder* builder) {
    builder->appendFormat("((u16) (~%s))", stateVar.c_str());
}

void InternetChecksumAlgorithm::emitSubtractData(CodeBuilder* builder, int dataPos,
                                                 const IR::MethodCallExpression * expr) {
    updateChecksum(builder, dataPos, expr, false);
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

// ===========================CRC16ChecksumAlgorithm===========================

void CRC16ChecksumAlgorithm::emitGlobals(CodeBuilder* builder) {
    builder->appendLine("static __always_inline\n"
        "void crc16_update(u16 * reg, const u8 * data, u16 data_size) {\n"
        "    data += data_size - 1;\n"
        "    for (u16 i = 0; i < data_size; i++) {\n"
        "        bpf_trace_message(\"CRC16 byte : %x\\n\", *data);\n"
        "        for (u8 bit = 0; bit < 8; bit++) {\n"
        "            u16 bit_flag = *reg >> 15;\n"
        "            *reg <<= 1;\n"
        "            *reg |= (*data >> bit) & 1;\n"
        "            if(bit_flag)\n"
        "                *reg ^= 0x8005;\n"
        "        }\n"
        "        data--;\n"
        "    }\n"
        "}\n"
        "static __always_inline\n"
        "void crc16_finalize(u16 * reg) {\n"
        "    for (u8 i = 0; i < 16; i++) {\n"
        "        u16 bit_flag = *reg >> 15;\n"
        "        *reg <<= 1;\n"
        "        if(bit_flag)\n"
        "            *reg ^= 0x8005;\n"
        "    }\n"
        "    u16 result = 0, i = 0x8000, j = 0x0001;\n"
        "    for (; i != 0; i >>=1, j <<= 1) {\n"
        "        if (i & (*reg)) result |= j;\n"
        "    }\n"
        "    *reg = result;\n"
        "}");
}

void CRC16ChecksumAlgorithm::emitVariables(CodeBuilder* builder,
                                           const IR::Declaration_Instance* decl) {
    registerVar = program->refMap->newName(baseName + "_reg");

    BUG_CHECK(decl->type->is<IR::Type_Specialized>(), "Must be a specialized type %1%", decl);
    auto ts = decl->type->to<IR::Type_Specialized>();
    BUG_CHECK(ts->arguments->size() == 1, "Expected 1 specialized type %1%", decl);

    auto otype = ts->arguments->at(0);
    if (!otype->is<IR::Type_Bits>()) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Must be bit or int type: %1%", ts);
        return;
    }
    if (otype->width_bits() != 16) {
        ::error(ErrorType::ERR_TYPE_ERROR, "Must be 16-bits width for CRC16: %1%", ts);
        return;
    }

    auto registerType = EBPFTypeFactory::instance->create(otype);

    builder->emitIndent();
    registerType->emit(builder);
    builder->appendFormat(" %s = 0", registerVar.c_str());
    builder->endOfStatement(true);
}

void CRC16ChecksumAlgorithm::emitClear(CodeBuilder* builder) {
    builder->emitIndent();
    builder->appendFormat("%s = 0", registerVar.c_str());
    builder->endOfStatement(true);
}

void CRC16ChecksumAlgorithm::emitAddData(CodeBuilder* builder, int dataPos,
                                         const IR::MethodCallExpression * expr) {
    cstring tmpVar = program->refMap->newName(baseName + "_tmp");
    auto arguments = unpackArguments(expr, dataPos);

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
                builder->appendFormat("crc16_update(&%s, &%s, 1)",
                                      registerVar.c_str(), tmpVar.c_str());
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
            builder->appendFormat("crc16_update(&%s, (u8 *) &(", registerVar.c_str());
            visitor->visit(field);
            builder->appendFormat("), %d)", width / 8);
            builder->endOfStatement(true);
        }
    }

    builder->emitIndent();
    builder->appendFormat("crc16_finalize(&%s)", registerVar.c_str());
    builder->endOfStatement(true);

    builder->target->emitTraceMessage(builder, "CRC16 checksum: %x", 1, registerVar.c_str());

    builder->blockEnd(true);
}

void CRC16ChecksumAlgorithm::emitGet(CodeBuilder* builder) {
    builder->append(registerVar);
}

void CRC16ChecksumAlgorithm::emitSubtractData(CodeBuilder* builder, int dataPos,
                                              const IR::MethodCallExpression * expr) {
    (void) builder; (void) expr; (void) dataPos;
    BUG("Not implementable");
}

void CRC16ChecksumAlgorithm::emitGetInternalState(CodeBuilder* builder) {
    (void) builder;
    BUG("Not implemented");
}

void CRC16ChecksumAlgorithm::emitSetInternalState(CodeBuilder* builder,
                          const IR::MethodCallExpression * expr) {
    (void) builder; (void) expr;
    BUG("Not implemented");
}

}  // namespace EBPF
