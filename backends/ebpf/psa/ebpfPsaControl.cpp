#include "ebpfPsaControl.h"

namespace EBPF {

    bool EBPFPsaControl::build() {
        auto params = control->type->applyParams;
        if (params->size() != 4) {
            ::error(ErrorType::ERR_EXPECTED,
                    "Expected control block to have exactly 4 parameters");
            return false;
        }

        auto it = params->parameters.begin();
        headers = *it;

        codeGen = new ControlBodyTranslator(this);
        codeGen->substitute(headers, parserHeaders);

        return ::errorCount() == 0;
    }

    void EBPFPsaControl::emit(CodeBuilder *builder) {
        hitVariable = program->refMap->newName("hit");
        auto hitType = EBPFTypeFactory::instance->create(IR::Type_Boolean::get());
        builder->emitIndent();
        hitType->declare(builder, hitVariable, false);
        builder->endOfStatement(true);
        for (auto a : control->controlLocals)
            emitDeclaration(builder, a);
        builder->emitIndent();
        codeGen->setBuilder(builder);
        control->body->apply(*codeGen);
        builder->newline();
    }
}