#include "ebpfPsaHashAlgorithm.h"
#include "backends/ebpf/ebpfProgram.h"

namespace EBPF {

// ===========================InternetChecksumAlgorithm===========================

void InternetChecksumAlgorithm::updateChecksum(CodeBuilder* builder,
                                               const IR::MethodCallExpression * expr,
                                               bool addData) {
    if (expr->arguments->size() != 1) {
        ::error(ErrorType::ERR_UNEXPECTED, "Expected exactly 1 argument %1%", expr);
        return;
    }

    cstring tmpVar = program->refMap->newName(baseName + "_tmp");

    builder->emitIndent();
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("u16 %s = 0", tmpVar.c_str());
    builder->endOfStatement(true);

    std::vector<const IR::Expression *> arguments;

    if (expr->arguments->at(0)->expression->is<IR::ListExpression>()) {
        auto argList = expr->arguments->at(0)->expression->to<IR::ListExpression>();
        for (auto field : argList->components)
            arguments.push_back(field);
    } else {
        arguments.push_back(expr->arguments->at(0)->expression);
    }

    int remainingBits = 16, bitsToRead;
    for (auto field : arguments) {
        cstring fieldName = field->toString();
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
                builder->appendFormat("(%s << %d)", fieldName.c_str(), remainingBits);
                bitsToRead = 0;
            } else if (bitsToRead == remainingBits) {
                remainingBits = 0;
                builder->append(fieldName);
                bitsToRead = 0;
            } else if (bitsToRead > remainingBits) {
                bitsToRead -= remainingBits;
                remainingBits = 0;
                builder->appendFormat("(%s >> %d)", fieldName.c_str(), bitsToRead);
            }

            if (remainingBits == 0) {
                remainingBits = 16;
                builder->endOfStatement(true);

                // update checksum
                builder->target->emitTraceMessage(builder, "InternetChecksum: word=0x%llx",
                                                  1, tmpVar.c_str());
                builder->emitIndent();
                if (addData) {
                    builder->appendFormat("%s = csum_replace2(%s, 0, %s)", stateVar.c_str(),
                                          stateVar.c_str(), tmpVar.c_str());
                } else {
                    builder->appendFormat("%s = csum_replace2(%s, %s, 0)", stateVar.c_str(),
                                          stateVar.c_str(), tmpVar.c_str());
                }
                builder->endOfStatement(true);
            }
        }
    }

    builder->target->emitTraceMessage(builder, "InternetChecksum: new checksum=0x%llx",
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
                        "}\n"
                        "inline u16 csum_replace2(u16 csum, u16 old, u16 new) {\n"
                        "    return (~csum16_add(csum16_sub(~csum, old), new));\n"
                        "}");
}

void InternetChecksumAlgorithm::emitVariables(CodeBuilder* builder, const IR::Declaration* decl) {
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
                                            const IR::MethodCallExpression * expr) {
    updateChecksum(builder, expr, true);
}

void InternetChecksumAlgorithm::emitGet(CodeBuilder* builder) {
    builder->append(stateVar);
}

void InternetChecksumAlgorithm::emitSubtractData(CodeBuilder* builder,
                                                 const IR::MethodCallExpression * expr) {
    updateChecksum(builder, expr, false);
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


}  // namespace EBPF
