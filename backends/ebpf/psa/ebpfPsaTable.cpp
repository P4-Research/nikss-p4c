#include <algorithm>

#include "backends/ebpf/ebpfType.h"
#include "ebpfPsaTable.h"
#include "ebpfPipeline.h"

namespace EBPF {

// =====================ActionTranslationVisitorPSA=============================
ActionTranslationVisitorPSA::ActionTranslationVisitorPSA(cstring valueName,
                                                         const EBPFProgram *program,
                                                         const EBPFTablePSA *table) :
        CodeGenInspector(program->refMap, program->typeMap),
        ActionTranslationVisitor(valueName, program),
        ControlBodyTranslatorPSA(program->to<EBPFPipeline>()->control),
        table(table) {}

bool ActionTranslationVisitorPSA::preorder(const IR::PathExpression* pe) {
    if (isActionParameter(pe)) {
        return ActionTranslationVisitor::preorder(pe);
    }
    return ControlBodyTranslator::preorder(pe);
}

bool ActionTranslationVisitorPSA::isActionParameter(const IR::Expression *expression) const {
    if (auto path = expression->to<IR::PathExpression>())
        return ActionTranslationVisitor::isActionParameter(path);
    else if (auto cast = expression->to<IR::Cast>())
        return isActionParameter(cast->expr);
    else
        return false;
}

cstring ActionTranslationVisitorPSA::getActionParamStr(const IR::Expression *expression) const {
    if (auto cast = expression->to<IR::Cast>())
        return ActionTranslationVisitor::getActionParamStr(cast->expr);
    else
        return ActionTranslationVisitor::getActionParamStr(expression);
}

void ActionTranslationVisitorPSA::processMethod(const P4::ExternMethod* method) {
    // TODO: placeholder for handling PSA externs
    ControlBodyTranslatorPSA::processMethod(method);
}

cstring ActionTranslationVisitorPSA::getValueActionParam(const IR::PathExpression *valueExpr) {
    if (isActionParameter(valueExpr)) {
        return getActionParamStr(valueExpr);
    }

    return ControlBodyTranslatorPSA::getValueActionParam(valueExpr);
}
cstring ActionTranslationVisitorPSA::getIndexActionParam(const IR::PathExpression *indexExpr) {
    if (isActionParameter(indexExpr)) {
        return getActionParamStr(indexExpr);
    }

    return ControlBodyTranslatorPSA::getIndexActionParam(indexExpr);
}

void ActionTranslationVisitorPSA::processApply(const P4::ApplyMethod* method) {
    ::error(ErrorType::ERR_UNSUPPORTED, "%1%: not supported in action", method->expr);
}

// =====================EBPFTablePSA=============================
EBPFTablePSA::EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                           CodeGenInspector* codeGen, cstring name, size_t size) :
                           EBPFTable(program, table, codeGen), name(name), size(size) {

    auto sizeProperty = table->container->properties->getProperty("size");
    if (keyGenerator == nullptr && sizeProperty != nullptr) {
        ::warning(ErrorType::WARN_IGNORE_PROPERTY,
                  "%1%: property ignored due to not defined table key", sizeProperty);
    }
    if (keyFieldNames.empty() && size != 1) {
        if (sizeProperty != nullptr) {
            ::warning(ErrorType::WARN_IGNORE,
                      "%1%: only one entry allowed with empty key or selector-only key",
                      sizeProperty);
        }
        this->size = 1;
    }
}

ActionTranslationVisitor* EBPFTablePSA::createActionTranslationVisitor(
        cstring valueName, const EBPFProgram* program) const {
    return new ActionTranslationVisitorPSA(valueName, program->to<EBPFPipeline>(), this);
}

void EBPFTablePSA::emitValueActionIDNames(CodeBuilder* builder) {
    // For action_run method we preserve these ID names for actions.
    // Values are the same as for implementation, because the same action
    // set is enforced.
    if (singleActionRun()) {
        EBPFTable::emitValueActionIDNames(builder);
    }
}

void EBPFTablePSA::emitValueStructStructure(CodeBuilder* builder) {
    // TODO: placeholder for handling psa_implementation
    EBPFTable::emitValueStructStructure(builder);
}

void EBPFTablePSA::emitInstance(CodeBuilder *builder) {
    if (keyGenerator != nullptr) {
        TableKind kind = isLPMTable() ? TableLPMTrie : TableHash;
        emitTableDecl(builder, name, kind,
                      cstring("struct ") + keyTypeName,
                      cstring("struct ") + valueTypeName, size);
    }

    emitTableDecl(builder, defaultActionMapName, TableArray,
                  program->arrayIndexType,
                  cstring("struct ") + valueTypeName, 1);
}

void EBPFTablePSA::emitTableDecl(CodeBuilder *builder,
                                 cstring tblName,
                                 TableKind kind,
                                 cstring keyTypeName,
                                 cstring valueTypeName,
                                 size_t size) const {
    builder->target->emitTableDecl(builder,
                                   tblName, kind,
                                   keyTypeName,
                                   valueTypeName,
                                   size);
}

void EBPFTablePSA::emitTypes(CodeBuilder* builder) {
    EBPFTable::emitTypes(builder);
    // TODO: placeholder for handling PSA-specific types
}

void EBPFTablePSA::emitAction(CodeBuilder* builder, cstring valueName, cstring actionRunVariable) {
    // TODO: placeholder for handling psa_implementation
    EBPFTable::emitAction(builder, valueName, actionRunVariable);
}

void EBPFTablePSA::emitInitializer(CodeBuilder *builder) {
    this->emitDefaultActionInitializer(builder);
    this->emitConstEntriesInitializer(builder);
}

void EBPFTablePSA::emitConstEntriesInitializer(CodeBuilder *builder) {
    CodeGenInspector cg(program->refMap, program->typeMap);
    cg.setBuilder(builder);
    const IR::EntriesList* entries = table->container->getEntries();
    if (entries != nullptr) {
        for (auto entry : entries->entries) {
            auto keyName = program->refMap->newName("key");
            auto valueName = program->refMap->newName("value");
            // construct key
            builder->emitIndent();
            builder->appendFormat("struct %s %s = {}", this->keyTypeName.c_str(), keyName.c_str());
            builder->endOfStatement(true);
            for (size_t index = 0; index < keyGenerator->keyElements.size(); index++) {
                auto keyElement = keyGenerator->keyElements[index];
                cstring fieldName = get(keyFieldNames, keyElement);
                CHECK_NULL(fieldName);
                builder->emitIndent();
                builder->appendFormat("%s.%s = ", keyName.c_str(), fieldName.c_str());
                auto mtdecl = program->refMap->getDeclaration(keyElement->matchType->path, true);
                auto matchType = mtdecl->getNode()->to<IR::Declaration_ID>();
                if (matchType->name.name == P4::P4CoreLibrary::instance.lpmMatch.name) {
                    auto expr = entry->keys->components[index];

                    auto ebpfType = ::get(keyTypes, keyElement);
                    unsigned width = 0;
                    if (ebpfType->is<EBPFScalarType>()) {
                        auto scalar = ebpfType->to<EBPFScalarType>();
                        width = scalar->implementationWidthInBits();
                    }
                    builder->appendFormat("%s(", getByteSwapMethod(width));
                    if (auto km = expr->to<IR::Mask>()) {
                        km->left->apply(cg);
                    } else {
                        expr->apply(cg);
                    }
                    builder->append(")");
                    builder->endOfStatement(true);
                    builder->emitIndent();
                    builder->appendFormat("%s.%s = ", keyName.c_str(), prefixFieldName.c_str());
                    unsigned prefixLen = 32;
                    if (auto km = expr->to<IR::Mask>()) {
                        auto trailing_zeros = [width](const big_int& n) -> int {
                            return (n == 0) ? width : boost::multiprecision::lsb(n); };
                        auto count_ones = [](const big_int& n) -> unsigned {
                            return bitcount(n); };
                        auto mask = km->right->to<IR::Constant>()->value;
                        auto len = trailing_zeros(mask);
                        if (len + count_ones(mask) != width) {  // any remaining 0s in the prefix?
                            ::error(ErrorType::ERR_INVALID,
                                    "%1% invalid mask for LPM key", keyElement);
                            return;
                        }
                        prefixLen = width - len;
                    }
                    builder->append(prefixLen);
                    builder->endOfStatement(true);

                } else if (matchType->name.name == P4::P4CoreLibrary::instance.exactMatch.name) {
                    entry->keys->components[index]->apply(cg);
                    builder->endOfStatement(true);
                }
            }

            // construct value
            auto *mce = entry->action->to<IR::MethodCallExpression>();
            emitTableValue(builder, mce, valueName.c_str());

            // emit update
            auto ret = program->refMap->newName("ret");
            builder->emitIndent();
            builder->appendFormat("int %s = ", ret.c_str());
            builder->target->emitTableUpdate(builder, name,
                                             keyName.c_str(), valueName.c_str());
            builder->newline();

            emitMapUpdateTraceMsg(builder, name, ret);
        }
    }
}

void EBPFTablePSA::emitDefaultActionInitializer(CodeBuilder *builder) {
    const IR::P4Table* t = table->container;
    const IR::Expression* defaultAction = t->getDefaultAction();
    BUG_CHECK(defaultAction->is<IR::MethodCallExpression>(),
              "%1%: expected an action call", defaultAction);
    auto mce = defaultAction->to<IR::MethodCallExpression>();
    auto pe = mce->method->to<IR::PathExpression>();
    BUG_CHECK(pe->is<IR::PathExpression>(), "%1%: expected IR::PathExpression type", pe);
    if (pe->path->name.originalName != P4::P4CoreLibrary::instance.noAction.name) {
        auto value = program->refMap->newName("value");
        emitTableValue(builder, mce, value.c_str());
        auto ret = program->refMap->newName("ret");
        builder->emitIndent();
        builder->appendFormat("int %s = ", ret.c_str());
        builder->target->emitTableUpdate(builder, defaultActionMapName,
                                         program->zeroKey.c_str(), value.c_str());
        builder->newline();

        emitMapUpdateTraceMsg(builder, defaultActionMapName, ret);
    }
}

void EBPFTablePSA::emitMapUpdateTraceMsg(CodeBuilder *builder, cstring mapName,
                                         cstring returnCode) const {
    if (!program->options.emitTraceMessages) {
        return;
    }
    builder->emitIndent();
    builder->appendFormat("if (%s) ", returnCode.c_str());
    builder->blockStart();
    cstring msgStr = Util::printf_format("Map initializer: Error while map (%s) update, code: %s",
                                         mapName, "%d");
    builder->target->emitTraceMessage(builder,
                                      msgStr, 1, returnCode.c_str());

    builder->blockEnd(false);
    builder->append(" else ");

    builder->blockStart();
    msgStr = Util::printf_format("Map initializer: Map (%s) update succeed",
                                 mapName, returnCode.c_str());
    builder->target->emitTraceMessage(builder,
                                      msgStr);
    builder->blockEnd(true);
}

void EBPFTablePSA::emitTableValue(CodeBuilder* builder, const IR::MethodCallExpression* actionMce,
                                  cstring valueName) {
    auto mi = P4::MethodInstance::resolve(actionMce, program->refMap, program->typeMap);
    auto ac = mi->to<P4::ActionCall>();
    BUG_CHECK(ac != nullptr, "%1%: expected an action call", mi);
    auto action = ac->action;

    cstring actionName = EBPFObject::externalName(action);

    CodeGenInspector cg(program->refMap, program->typeMap);
    cg.setBuilder(builder);

    builder->emitIndent();
    builder->appendFormat("struct %s %s = ", valueTypeName.c_str(), valueName.c_str());
    builder->blockStart();
    builder->emitIndent();
    if (action->name.originalName == P4::P4CoreLibrary::instance.noAction.name) {
        builder->append(".action = 0,");
    } else {
        cstring fullActionName = actionToActionIDName(action);
        builder->appendFormat(".action = %s,", fullActionName);
    }
    builder->newline();

    builder->emitIndent();
    builder->appendFormat(".u = {.%s = {", actionName.c_str());
    for (auto p : *mi->substitution.getParametersInArgumentOrder()) {
        auto arg = mi->substitution.lookup(p);
        arg->apply(cg);
        builder->append(",");
    }
    builder->append("}},\n");
    builder->blockEnd(false);
    builder->endOfStatement(true);
}

void EBPFTablePSA::emitLookup(CodeBuilder* builder, cstring key, cstring value) {
    // TODO: placeholder for handling ternary table caching
    EBPFTable::emitLookup(builder, key, value);
}

void EBPFTablePSA::emitLookupDefault(CodeBuilder* builder, cstring key, cstring value) {
    // TODO: placeholder for handling psa_implementation
    EBPFTable::emitLookupDefault(builder, key, value);
}

bool EBPFTablePSA::dropOnNoMatchingEntryFound() const {
    // TODO: placeholder for handling psa_implementation
    return EBPFTable::dropOnNoMatchingEntryFound();
}
}  // namespace EBPF
