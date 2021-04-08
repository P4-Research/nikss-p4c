#include "ebpfPsaControl.h"

namespace EBPF {

bool ControlBodyTranslatorPSA::preorder(const IR::Member* expression) {
    if (expression->expr->is<IR::TypeNameExpression>()) {
        auto tne = expression->expr->to<IR::TypeNameExpression>();
        if (tne->typeName->path->name.name == "error") {
            builder->append(expression->member);
            return false;
        }
    }

    return CodeGenInspector::preorder(expression);
}

void ControlBodyTranslatorPSA::processMethod(const P4::ExternMethod* method) {
    auto decl = method->object;
    auto declType = method->originalExternType;
    cstring name = EBPFObject::externalName(decl);

    // TODO: make something similar to EBPFModel instead of hardcoded extern name
    if (declType->name.name == "Counter") {
        auto counterMap = control->getCounter(name);
        counterMap->emitMethodInvocation(builder, method);
        return;
    }

    ControlBodyTranslator::processMethod(method);
}

bool EBPFControlPSA::build() {
    auto params = p4Control->type->applyParams;
    if (params->size() != 4) {
        ::error(ErrorType::ERR_EXPECTED,
                "Expected control block to have exactly 4 parameters");
        return false;
    }

    auto it = params->parameters.begin();
    headers = *it;

    codeGen = new ControlBodyTranslatorPSA(this);
    codeGen->substitute(headers, parserHeaders);

    return ::errorCount() == 0;
}

void EBPFControlPSA::emit(CodeBuilder *builder) {
    hitVariable = program->refMap->newName("hit");
    auto hitType = EBPFTypeFactory::instance->create(IR::Type_Boolean::get());
    builder->emitIndent();
    hitType->declare(builder, hitVariable, false);
    builder->endOfStatement(true);
    for (auto a : p4Control->controlLocals)
        emitDeclaration(builder, a);
    builder->emitIndent();
    codeGen->setBuilder(builder);
    p4Control->body->apply(*codeGen);
    builder->newline();
}

void EBPFControlPSA::emitTableInstances(CodeBuilder* builder) {
    for (auto it : tables)
        it.second->emitInstance(builder);
    for (auto it : counters)
        it.second->emitInstance(builder);
}

void EBPFControlPSA::emitTableInitializers(CodeBuilder* builder) {
    for (auto it : tables) {
        it.second->emitInitializer(builder);
    }
}
}  // namespace EBPF
