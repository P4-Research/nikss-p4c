#include "ebpfPsaTableImplementation.h"

namespace EBPF {

EBPFTableImplementationAPIPSA::EBPFTableImplementationAPIPSA(const EBPFProgram* program,
        CodeGenInspector* codeGen, const IR::Declaration_Instance* decl) :
        EBPFTablePSA(program, codeGen, externalName(decl)), declaration(decl) {
    referenceName = name + "_key";
}

void EBPFTableImplementationAPIPSA::emitTypes(CodeBuilder* builder) {
    if (table == nullptr)
        return;
    // key is u32
    emitValueType(builder);
}

void EBPFTableImplementationAPIPSA::emitInitializer(CodeBuilder *builder) {
    (void) builder;
}

void EBPFTableImplementationAPIPSA::emitReferenceEntry(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("u32 %s", referenceName.c_str());
    builder->endOfStatement(true);
}

void EBPFTableImplementationAPIPSA::registerTable(const EBPFTablePSA * instance) {
    // verify table instance
    verifyTableNoEntries(instance);
    verifyTableNoDefaultAction(instance);
    verifyTableNoDirectObjects(instance);

    if (table == nullptr) {
        // no other tables at the moment, take it as a reference
        table = instance->table;
        actionList = instance->actionList;
    } else {
        // another table, check that new instance has the same actions
        verifyTableActionList(instance);
        // TODO: verify direct externs
    }
}

void EBPFTableImplementationAPIPSA::verifyTableActionList(const EBPFTablePSA * instance) {
    bool printError = false;
    if (actionList == nullptr)
        return;

    if (instance->actionList->size() != actionList->size())
        printError = true;

    auto getActionName = [](const IR::ActionList * al, size_t id)->cstring {
        auto mce = al->actionList.at(id)->expression->to<IR::MethodCallExpression>();
        BUG_CHECK(mce != nullptr, "%1%: expected an action call", mce);
        auto pe = mce->method->to<IR::PathExpression>();
        BUG_CHECK(pe != nullptr, "%1%: expected an action name", pe);
        return pe->path->name.originalName;
    };

    for (size_t i = 0; i < actionList->size(); ++i) {
        auto left = getActionName(instance->actionList, i);
        auto right = getActionName(actionList, i);
        if (left != right)
            printError = true;
    }

    if (printError) {
        ::error(ErrorType::ERR_EXPECTED,
                "%1%: Action list differs from previous %2% "
                "(tables use the same implementation %3%)",
                instance->table->container->getActionList(), table->container->getActionList(),
                declaration);
    }
}

void EBPFTableImplementationAPIPSA::verifyTableNoDefaultAction(const EBPFTablePSA * instance) {
    auto defaultAction = instance->table->container->getDefaultAction();
    BUG_CHECK(defaultAction->is<IR::MethodCallExpression>(),
              "%1%: expected an action call", defaultAction);

    auto mi = P4::MethodInstance::resolve(defaultAction->to<IR::MethodCallExpression>(),
                                          program->refMap, program->typeMap);
    auto ac = mi->to<P4::ActionCall>();
    BUG_CHECK(ac != nullptr, "%1%: expected an action call", mi);

    if (ac->action->name.originalName != P4::P4CoreLibrary::instance.noAction.name) {
        ::error(ErrorType::ERR_UNSUPPORTED,
                "%1%: Default action cannot be defined for table %2% with implementation %3%",
                defaultAction, instance->table->container->name, declaration);
    }
}

void EBPFTableImplementationAPIPSA::verifyTableNoDirectObjects(const EBPFTablePSA * instance) {
    if (!instance->counters.empty() || !instance->meters.empty()) {
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "%1%: DirectCounter and DirectMeter externs are not supported "
                "with table implementation %2%",
                instance->table->container->name, declaration->type->toString());
    }
}

void EBPFTableImplementationAPIPSA::verifyTableNoEntries(const EBPFTablePSA * instance) {
    // PSA documentation v1.1 says: "Directly specifying the action as part of the table
    //    entry is not allowed for tables with an action profile implementation."
    // I believe that this sentence forbids (const) entries in a table in P4 code at all.
    auto entries = instance->table->container->getEntries();
    if (entries != nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED,
                "%1%: entries directly specified in a table %2% "
                "with implementation %3% are not supported",
                entries, instance->table->container->name, declaration);
    }
}

// ===============================ActionProfile===============================

EBPFActionProfilePSA::EBPFActionProfilePSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                                           const IR::Declaration_Instance* decl) :
        EBPFTableImplementationAPIPSA(program, codeGen, decl) {
    auto sizeType = decl->arguments->at(0)->expression;
    if (!sizeType->is<IR::Constant>()) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Must be constant value: %1%", sizeType);
        return;
    }
    auto declaredSize = sizeType->to<IR::Constant>();
    if (!declaredSize->fitsUint()) {
        ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", declaredSize);
        return;
    }
    size = declaredSize->asUnsigned();
}

void EBPFActionProfilePSA::emitInstance(CodeBuilder *builder) {
    if (table == nullptr)  // no table(s)
        return;

    auto tableKind = TableArray;  // or might be TableHash?
    builder->target->emitTableDecl(builder, name, tableKind,
                                   "u32",
                                   cstring("struct ") + valueTypeName, size);
}

void EBPFActionProfilePSA::applyImplementation(CodeBuilder* builder, cstring tableValueName,
                                               cstring actionRunVariable) {
    cstring msg = Util::printf_format("ActionProfile: applying %s", name.c_str());
    builder->target->emitTraceMessage(builder, msg.c_str());

    cstring apValueName = program->refMap->newName("ap_value");
    cstring apKeyName = Util::printf_format("%s->%s",
        tableValueName.c_str(), referenceName.c_str());

    builder->target->emitTraceMessage(builder, "ActionProfile: entry id %u",
                                      1, apKeyName.c_str());

    builder->emitIndent();
    builder->appendFormat("struct %s *%s = NULL", valueTypeName.c_str(), apValueName.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    emitLookup(builder, apKeyName, apValueName);

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", apValueName.c_str());
    builder->blockStart();

    emitAction(builder, apValueName, cstring::empty);

    builder->blockEnd(false);
    builder->append(" else ");

    builder->blockStart();
    builder->target->emitTraceMessage(builder,
        "ActionProfile: entry not found, executing implicit NoAction");
    builder->emitIndent();
    builder->appendFormat("%s = 0", program->control->hitVariable.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    msg = Util::printf_format("ActionProfile: %s applied", name.c_str());
    builder->target->emitTraceMessage(builder, msg.c_str());

    if (!actionRunVariable.isNullOrEmpty()) {
        builder->emitIndent();
        builder->appendFormat("%s = %s->action",
                              actionRunVariable.c_str(), apValueName.c_str());
        builder->endOfStatement(true);
    }
}

}  // namespace EBPF
