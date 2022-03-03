#include "ebpfPsaControl.h"
#include "frontends/p4/methodInstance.h"

namespace EBPF {

ControlBodyTranslatorPSA::ControlBodyTranslatorPSA(const EBPFControlPSA* control) :
        CodeGenInspector(control->program->refMap, control->program->typeMap),
        ControlBodyTranslator(control) {}

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

bool ControlBodyTranslatorPSA::preorder(const IR::AssignmentStatement* a) {
    // TODO: placeholder for handling PSA externs
    return CodeGenInspector::preorder(a);
}

void ControlBodyTranslatorPSA::processMethod(const P4::ExternMethod* method) {
    // TODO: placeholder for handling PSA externs
    ControlBodyTranslator::processMethod(method);
}

cstring ControlBodyTranslatorPSA::getValueActionParam(const IR::PathExpression *valueExpr) {
    return valueExpr->path->name.name;
}
cstring ControlBodyTranslatorPSA::getIndexActionParam(const IR::PathExpression *indexExpr) {
    return indexExpr->path->name.name;
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

void EBPFControlPSA::emitTableTypes(CodeBuilder *builder) {
    EBPFControl::emitTableTypes(builder);

    // TODO: placeholder for handling PSA externs
}

void EBPFControlPSA::emitTableInstances(CodeBuilder* builder) {
    for (auto it : tables)
        it.second->emitInstance(builder);
}

void EBPFControlPSA::emitTableInitializers(CodeBuilder* builder) {
    for (auto it : tables) {
        it.second->emitInitializer(builder);
    }
}

}  // namespace EBPF
