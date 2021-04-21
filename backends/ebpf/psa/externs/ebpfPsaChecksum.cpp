#include "ebpfPsaChecksum.h"
#include "ebpfPsaHashAlgorithm.h"

namespace EBPF {

void EBPFChecksumPSA::init(const EBPFProgram* program, cstring name, int type) {
    engine = EBPFHashAlgorithmTypeFactoryPSA::instance()->create(type, program, name, visitor);

    if (engine == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Hash algorithm not yet implemented: %1%",
                declaration->arguments->at(0));
        engine = new EBPFHashAlgorithmPSA(program, name, visitor);
    }
}

EBPFChecksumPSA::EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                                 cstring name, Visitor * visitor) :
         engine(nullptr), visitor(visitor), declaration(block) {
    auto di = block->to<IR::Declaration_Instance>();
    if (di->arguments->size() != 1) {
        ::error(ErrorType::ERR_UNEXPECTED, "Expected exactly 1 argument %1%", block);
        return;
    }
    int type = di->arguments->at(0)->expression->to<IR::Constant>()->asInt();
    init(program, name, type);
}

EBPFChecksumPSA::EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                cstring name, Visitor * visitor, int type) :
        engine(nullptr), visitor(visitor), declaration(block) {
    init(program, name, type);
}

void EBPFChecksumPSA::processMethod(CodeBuilder* builder, cstring method,
                                    const IR::MethodCallExpression * expr) {
    if (method == "clear") {
        engine->emitClear(builder);
    } else if (method == "update") {
        engine->emitAddData(builder, 0, expr);
    } else if (method == "get") {
        engine->emitGet(builder);
    } else {
        ::error(ErrorType::ERR_UNEXPECTED, "Unexpected method call %1%", expr);
    }
}

void EBPFInternetChecksumPSA::processMethod(CodeBuilder* builder, cstring method,
                                            const IR::MethodCallExpression * expr) {
    if (method == "add") {
        engine->emitAddData(builder, 0, expr);
    } else if (method == "subtract") {
        engine->emitSubtractData(builder, 0, expr);
    } else if (method == "get_state") {
        engine->emitGetInternalState(builder);
    } else if (method == "set_state") {
        engine->emitSetInternalState(builder, expr);
    } else {
        EBPFChecksumPSA::processMethod(builder, method, expr);
    }
}


void EBPFHashPSA::processMethod(CodeBuilder* builder, cstring method,
                                const IR::MethodCallExpression * expr) {
    if (method == "update") {
        // TODO: we probably should call the "clear" method in order to separate
        //  each call to "get_hash" on this object
        engine->emitAddData(builder, expr->arguments->size() == 3 ? 1 : 0, expr);
    } else if (method == "get_hash") {
        emitGetMethod(builder, expr);
    } else {
        ::error(ErrorType::ERR_UNEXPECTED, "Unexpected method call %1%", expr);
    }
}

void EBPFHashPSA::emitGetMethod(CodeBuilder* builder, const IR::MethodCallExpression * expr) {
    BUG_CHECK(expr->arguments->size() == 1 || expr->arguments->size() == 3,
              "Expected 1 or 3 arguments: %1%", expr);

    // Two forms of get method:
    // 1: (state)
    // 2: (( (state) % (max)) + (base))

    if (expr->arguments->size() == 3) {
        builder->append("((");
    }

    engine->emitGet(builder);

    if (expr->arguments->size() == 3) {
        builder->append(" % (");
        visitor->visit(expr->arguments->at(2));
        builder->append(")) + (");
        visitor->visit(expr->arguments->at(0));
        builder->append("))");
    }
}

}  // namespace EBPF
