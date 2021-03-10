#include "ebpfPsaChecksum.h"
#include "ebpfPsaHashAlgorithm.h"

namespace EBPF {

void EBPFPsaChecksum::init(const EBPFProgram* program, const IR::Declaration* block,
          cstring name, Visitor * visitor, int type) {
    (void) block;
    engine = EBPFPsaHashAlgorithmTypeFactory::create(type, program, name, visitor);
}

EBPFPsaChecksum::EBPFPsaChecksum(const EBPFProgram* program, const IR::Declaration* block,
                                 cstring name, Visitor * visitor) {
    engine = nullptr;
    auto di = block->to<IR::Declaration_Instance>();
    if (di->arguments->size() != 1) {
        ::error(ErrorType::ERR_UNEXPECTED, "Expected exactly 1 argument %1%", block);
        return;
    }
    int type = di->arguments->at(0)->expression->to<IR::Constant>()->asInt();
    init(program, block, name, visitor, type);
}

EBPFPsaChecksum::EBPFPsaChecksum(const EBPFProgram* program, const IR::Declaration* block,
                cstring name, Visitor * visitor, int type) {
    init(program, block, name, visitor, type);
}

void EBPFPsaChecksum::processMethod(CodeBuilder* builder, cstring method,
                                    const IR::MethodCallExpression * expr) {
    if (method == "clear") {
        engine->emitClear(builder);
    } else if (method == "update") {
        engine->emitAddData(builder, expr);
    } else if (method == "get") {
        engine->emitGet(builder);
    } else {
        ::error(ErrorType::ERR_UNEXPECTED, "Unexpected method call %1%", expr);
    }
}

void EBPFPsaInternetChecksum::processMethod(CodeBuilder* builder, cstring method,
                                            const IR::MethodCallExpression * expr) {
    if (method == "add") {
        engine->emitAddData(builder, expr);
    } else if (method == "subtract") {
        engine->emitSubtractData(builder, expr);
    } else if (method == "get_state") {
        engine->emitGetInternalState(builder);
    } else if (method == "set_state") {
        engine->emitSetInternalState(builder, expr);
    } else {
        EBPFPsaChecksum::processMethod(builder, method, expr);
    }
}

}  // namespace EBPF
