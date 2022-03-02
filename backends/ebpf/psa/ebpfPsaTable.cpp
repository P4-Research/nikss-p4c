#include <algorithm>
#include <boost/range/irange.hpp>

#include "backends/ebpf/ebpfType.h"
#include "ebpfPsaTable.h"
#include "ebpfPipeline.h"
#include "backends/ebpf/psa/externs/ebpfPsaTableImplementation.h"

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
    auto declType = method->originalExternType;
    auto decl = method->object;
    BUG_CHECK(decl->is<IR::Declaration_Instance>(),
            "Extern has not been declared");
    auto di = decl->to<IR::Declaration_Instance>();
    auto instanceName = EBPFObject::externalName(di);

    if (declType->name.name == "DirectCounter") {
        auto ctr = table->getCounter(instanceName);
        if (ctr != nullptr)
            ctr->emitDirectMethodInvocation(builder, method, valueName);
        else
            ::error(ErrorType::ERR_NOT_FOUND,
                    "%1%: Table %2% do not own DirectCounter named %3%",
                    method->expr, table->name, instanceName);
    } else if (declType->name.name == "DirectMeter") {
        auto met = table->getMeter(instanceName);
        if (met != nullptr) {
            met->emitDirectExecute(builder, method, valueName);
        } else {
            ::error(ErrorType::ERR_NOT_FOUND,
                    "%1%: Table %2% do not own DirectMeter named %3%",
                    method->expr, table->name, instanceName);
        }
    } else if (declType->name.name == "Counter") {
        auto ctr = control->to<EBPFControlPSA>()->getCounter(instanceName);
        // Counter count() always has one argument/index
        if (ctr != nullptr) {
            ctr->to<EBPFCounterPSA>()->emitMethodInvocation(builder, method, this);
        } else {
            ::error(ErrorType::ERR_NOT_FOUND,
                    "%1%: Counter named %2% not found",
                    method->expr, instanceName);
        }
        return;
    } else if (declType->name.name == "Meter") {
        auto met = control->to<EBPFControlPSA>()->getMeter(instanceName);
        // Meter execute() always has one argument/index
        if (met != nullptr) {
            met->emitExecute(builder, method, this);
        } else {
            ::error(ErrorType::ERR_NOT_FOUND,
                    "%1%: Meter named %2% not found",
                    method->expr, instanceName);
        }
    } else {
        ControlBodyTranslatorPSA::processMethod(method);
    }
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
    initDirectCounters();
    initDirectMeters();

    initImplementations();

    tryEnableTableCache();

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

EBPFTablePSA::EBPFTablePSA(const EBPFProgram* program, CodeGenInspector* codeGen, cstring name) :
        EBPFTable(program, codeGen, name), name(name) {}

ActionTranslationVisitor* EBPFTablePSA::createActionTranslationVisitor(
        cstring valueName, const EBPFProgram* program) const {
    return new ActionTranslationVisitorPSA(valueName, program->to<EBPFPipeline>(), this);
}

void EBPFTablePSA::initDirectCounters() {
    auto counterAdder = [this](const IR::PathExpression * pe) {
        CHECK_NULL(pe);
        auto decl = program->refMap->getDeclaration(pe->path, true);
        auto di = decl->to<IR::Declaration_Instance>();
        CHECK_NULL(di);
        auto counterName = EBPFObject::externalName(di);
        auto ctr = new EBPFCounterPSA(program, di, counterName, codeGen);
        this->counters.emplace_back(std::make_pair(counterName, ctr));
    };

    forEachPropertyEntry("psa_direct_counter", counterAdder);
}

void EBPFTablePSA::initDirectMeters() {
    auto meterAdder = [this](const IR::PathExpression * pe) {
        CHECK_NULL(pe);
        auto decl = program->refMap->getDeclaration(pe->path, true);
        auto di = decl->to<IR::Declaration_Instance>();
        CHECK_NULL(di);
        if (isLPMTable() || isTernaryTable()) {
            ::error(ErrorType::ERR_UNSUPPORTED,
                    "DirectMeter in table with ternary key or "
                    "Longest Prefix Match key is not supported: %1%", di);
            return;
        }
        auto meterName = EBPFObject::externalName(di);
        auto met = new EBPFMeterPSA(program, meterName, di, codeGen);
        this->meters.emplace_back(std::make_pair(meterName, met));
    };

    forEachPropertyEntry("psa_direct_meter", meterAdder);
}

void EBPFTablePSA::initImplementations() {
    bool hasActionSelector = false;
    auto impl = [this, &hasActionSelector](const IR::PathExpression * pe) {
        CHECK_NULL(pe);
        auto decl = program->refMap->getDeclaration(pe->path, true);
        auto di = decl->to<IR::Declaration_Instance>();
        CHECK_NULL(di);
        EBPFTableImplementationPSA * implementation = nullptr;
        cstring type = di->type->toString();
        if (type == "ActionProfile" || type == "ActionSelector") {
            auto ap = program->control->getTable(di->name.name);
            implementation = ap->to<EBPFTableImplementationPSA>();
            if (type == "ActionSelector")
                hasActionSelector = true;
        }

        if (implementation != nullptr) {
            implementation->registerTable(this);
            implementations.emplace_back(implementation);
        } else {
            ::error(ErrorType::ERR_UNKNOWN,
                    "%1%: unknown table implementation %2%", pe, decl);
        }
    };
    forEachPropertyEntry("psa_implementation", impl);

    // check if we have also selector key
    const IR::KeyElement * selectorKey = nullptr;
    if (keyGenerator != nullptr) {
        for (auto k : keyGenerator->keyElements) {
            auto mkdecl = program->refMap->getDeclaration(k->matchType->path, true);
            auto matchType = mkdecl->getNode()->to<IR::Declaration_ID>();
            if (matchType->name.name == "selector") {
                selectorKey = k;
                break;
            }
        }
    }

    if (hasActionSelector && selectorKey == nullptr) {
        ::error(ErrorType::ERR_NOT_FOUND,
                "%1%: ActionSelector provided but there is no selector key",
                table->container);
    }
    if (!hasActionSelector && selectorKey != nullptr) {
        ::error(ErrorType::ERR_NOT_FOUND,
                "%1%: implementation not found, ActionSelector is required",
                selectorKey->matchType);
    }
    auto emptyGroupAction = table->container->properties->getProperty("psa_empty_group_action");
    if (!hasActionSelector && emptyGroupAction != nullptr) {
        ::warning(ErrorType::WARN_UNUSED,
                  "%1%: unused property (ActionSelector not provided)",
                  emptyGroupAction);
    }
}

bool EBPFTablePSA::hasImplementation() const {
    return !implementations.empty();
}

void EBPFTablePSA::tryEnableTableCache() {
    if (!program->options.enableTableCache)
        return;
    if (!isLPMTable() && !isTernaryTable())
        return;
    if (!counters.empty() || !meters.empty()) {
        ::warning(ErrorType::WARN_UNSUPPORTED,
                  "%1%: table cache can't be enabled due to direct extern(s)",
                  table->container->name);
        return;
    }
    createCacheTypeNames(false, true);
}

void EBPFTablePSA::createCacheTypeNames(bool isCacheKeyType, bool isCacheValueType) {
    if (!program->options.enableTableCache)
        return;

    tableCacheEnabled = true;
    cacheTableName = name + "_cache";

    cacheKeyTypeName = keyTypeName;
    if (isCacheKeyType)
        cacheKeyTypeName = keyTypeName + "_cache";

    cacheValueTypeName = valueTypeName;
    if (isCacheValueType)
        cacheValueTypeName = valueTypeName + "_cache";
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
    if (hasImplementation()) {
        if (isTernaryTable()) {
            builder->emitIndent();
            builder->append("__u32 priority;");
            builder->newline();
        }

        for (auto impl : implementations) {
            impl->emitReferenceEntry(builder);
        }
    } else {
        EBPFTable::emitValueStructStructure(builder);
    }
}

void EBPFTablePSA::emitInstance(CodeBuilder *builder) {
    if (keyGenerator != nullptr) {
        TableKind kind = isLPMTable() ? TableLPMTrie : TableHash;
        emitTableDecl(builder, name, kind,
                      cstring("struct ") + keyTypeName,
                      cstring("struct ") + valueTypeName, size);
    }

    if (!hasImplementation()) {
        // Default action is up to implementation
        emitTableDecl(builder, defaultActionMapName, TableArray,
                      program->arrayIndexType,
                      cstring("struct ") + valueTypeName, 1);
    }

    emitCacheInstance(builder);
}

void EBPFTablePSA::emitTableDecl(CodeBuilder *builder,
                                 cstring tblName,
                                 TableKind kind,
                                 cstring keyTypeName,
                                 cstring valueTypeName,
                                 size_t size) const {
    if (meters.empty()) {
        builder->target->emitTableDecl(builder,
                                       tblName, kind,
                                       keyTypeName,
                                       valueTypeName,
                                       size);
    } else {
        builder->target->emitTableDeclSpinlock(builder,
                                               tblName, kind,
                                               keyTypeName,
                                               valueTypeName,
                                               size);
    }
}

void EBPFTablePSA::emitTypes(CodeBuilder* builder) {
    EBPFTable::emitTypes(builder);
    emitCacheTypes(builder);
}

/**
 * Remember that order of emitting counters and meters affects future access to BPF maps.
 * Do not change this order!
 */
void EBPFTablePSA::emitDirectTypes(CodeBuilder* builder) {
    for (auto ctr : counters) {
        ctr.second->emitValueType(builder);
    }
    for (auto met : meters) {
        met.second->emitValueType(builder);
    }
    if (!meters.empty()) {
        meters.begin()->second->emitSpinLockField(builder);
    }
}

void EBPFTablePSA::emitAction(CodeBuilder* builder, cstring valueName, cstring actionRunVariable) {
    if (hasImplementation()) {
        for (auto impl : implementations) {
            impl->applyImplementation(builder, valueName, actionRunVariable);
        }
    } else {
        EBPFTable::emitAction(builder, valueName, actionRunVariable);
    }
}

void EBPFTablePSA::emitInitializer(CodeBuilder *builder) {
    // Do not emit initializer when table implementation(s) is provided
    if (!hasImplementation()) {
        this->emitDefaultActionInitializer(builder);
        this->emitConstEntriesInitializer(builder);
    }
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
    if (tableCacheEnabled)
        emitCacheLookup(builder, key, value);

    EBPFTable::emitLookup(builder, key, value);
}

void EBPFTablePSA::emitLookupDefault(CodeBuilder* builder, cstring key, cstring value) {
    if (hasImplementation()) {
        builder->appendLine("/* table with implementation has no default action */");
        builder->target->emitTraceMessage(builder,
            "Control: skipping default action due to implementation");
    } else {
        EBPFTable::emitLookupDefault(builder, key, value);
    }
}

bool EBPFTablePSA::dropOnNoMatchingEntryFound() const {
    if (hasImplementation())
        return false;
    return EBPFTable::dropOnNoMatchingEntryFound();
}

bool EBPFTablePSA::singleActionRun() const {
    return implementations.size() <= 1;
}

void EBPFTablePSA::emitCacheTypes(CodeBuilder* builder) {
    if (!tableCacheEnabled)
        return;

    builder->emitIndent();
    builder->appendFormat("struct %s ", cacheValueTypeName.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("struct %s value", valueTypeName.c_str());
    builder->endOfStatement(true);

    // additional metadata fields add at the end of this structure. This allows
    // to simpler conversion cache value to value used by table

    builder->emitIndent();
    builder->append("u8 hit");
    builder->endOfStatement(true);

    builder->blockEnd(false);
    builder->endOfStatement(true);
}

void EBPFTablePSA::emitCacheInstance(CodeBuilder* builder) {
    if (!tableCacheEnabled)
        return;

    // TODO: make cache size calculation more smart
    size_t cacheSize = std::max((size_t) 1, size / 2);
    builder->target->emitTableDecl(builder, cacheTableName, TableHashLRU,
                                   "struct " + cacheKeyTypeName, "struct " + cacheValueTypeName,
                                   cacheSize);
}

void EBPFTablePSA::emitCacheLookup(CodeBuilder* builder, cstring key, cstring value) {
    cstring cacheVal = "cached_value";

    builder->appendFormat("struct %s* %s = NULL", cacheValueTypeName.c_str(), cacheVal.c_str());
    builder->endOfStatement(true);

    builder->target->emitTraceMessage(builder, "Control: trying table cache...");

    builder->emitIndent();
    builder->target->emitTableLookup(builder, cacheTableName, key, cacheVal);
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", cacheVal.c_str());
    builder->blockStart();

    builder->target->emitTraceMessage(builder,
                                      "Control: table cache hit, skipping later lookup(s)");
    builder->emitIndent();
    builder->appendFormat("%s = &(%s->value)", value.c_str(), cacheVal.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("%s = %s->hit",
                          program->control->hitVariable.c_str(), cacheVal.c_str());
    builder->endOfStatement(true);

    builder->blockEnd(false);
    builder->append(" else ");
    builder->blockStart();

    builder->target->emitTraceMessage(builder, "Control: table cache miss, nevermind");
    builder->emitIndent();

    // Do not end block here because we need lookup for (default) value
    // and set hit variable at this indent level which is done in the control block
}

void EBPFTablePSA::emitCacheUpdate(CodeBuilder* builder, cstring key, cstring value) {
    cstring cacheUpdateVarName = "cache_update";

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", value.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("struct %s %s = {0}",
                          cacheValueTypeName.c_str(), cacheUpdateVarName.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("%s.hit = %s",
                          cacheUpdateVarName.c_str(), program->control->hitVariable.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat(
        "__builtin_memcpy((void *) &(%s.value), (void *) %s, sizeof(struct %s))",
        cacheUpdateVarName.c_str(), value.c_str(), valueTypeName.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->target->emitTableUpdate(builder, cacheTableName, key, cacheUpdateVarName);
    builder->newline();

    builder->target->emitTraceMessage(builder, "Control: table cache updated");

    builder->blockEnd(true);
}

// =====================EBPFTernaryTablePSA=============================
void EBPFTernaryTablePSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, name + "_prefixes", TableHash,
                                   "struct " + keyTypeName + "_mask",
                                   "struct " + valueTypeName + "_mask", size);
    builder->target->emitMapInMapDecl(builder, name + "_tuple",
                                      TableHash, "struct " + keyTypeName,
                                      "struct " + valueTypeName, size,
                                      name + "_tuples_map", TableArray, "__u32", size);
    if (!hasImplementation()) {
        builder->target->emitTableDecl(builder, defaultActionMapName, TableArray,
                                       program->arrayIndexType,
                                       cstring("struct ") + valueTypeName, 1);
        if (hasEntries()) {
            auto entries = constEntriesGroupedByPrefix();
            // A number of tuples is equal to number of unique prefixes
            int nrOfTuples = entries.size();
            for (int i = 0; i < nrOfTuples; i++) {
                builder->target->emitTableDecl(builder, name + "_tuple_" + std::to_string(i), TableHash,
                                               "struct " + keyTypeName,
                                               "struct " + valueTypeName, size);
            }
        }
    }

    emitCacheInstance(builder);
}

void EBPFTernaryTablePSA::emitKeyType(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct %s ", keyTypeName.c_str());
    builder->blockStart();

    CodeGenInspector commentGen(program->refMap, program->typeMap);
    commentGen.setBuilder(builder);

    unsigned int structAlignment = 4;  // 4 by default
    if (keyGenerator != nullptr) {
        for (auto c : keyGenerator->keyElements) {
            if (c->matchType->path->name.name == "selector")
                continue;  // this match type is intended for ActionSelector, not table itself

            auto ebpfType = ::get(keyTypes, c);
            cstring fieldName = ::get(keyFieldNames, c);

            if (ebpfType->is<EBPFScalarType>() &&
                ebpfType->to<EBPFScalarType>()->alignment() > structAlignment) {
                structAlignment = 8;
            }

            builder->emitIndent();
            ebpfType->declare(builder, fieldName, false);

            builder->append("; /* ");
            c->expression->apply(commentGen);
            builder->append(" */");
            builder->newline();
        }
    }

    builder->blockEnd(false);
    builder->appendFormat(" __attribute__((aligned(%d)))", structAlignment);
    builder->endOfStatement(true);

    // generate mask key
    builder->emitIndent();
    // TODO: find better solution to workaround BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    builder->appendFormat("#define MAX_%s_MASKS %u", keyTypeName.toUpper(),
                          program->options.maxTernaryMasks);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("struct %s_mask ", keyTypeName.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("__u8 mask[sizeof(struct %s)];", keyTypeName.c_str());
    builder->newline();

    builder->blockEnd(false);
    builder->appendFormat(" __attribute__((aligned(%d)))", structAlignment);
    builder->endOfStatement(true);
}

void EBPFTernaryTablePSA::emitValueType(CodeBuilder* builder) {
    EBPFTablePSA::emitValueType(builder);

    if (isTernaryTable()) {
        // emit ternary mask value
        builder->emitIndent();
        builder->appendFormat("struct %s_mask ", valueTypeName.c_str());
        builder->blockStart();

        builder->emitIndent();
        builder->appendLine("__u32 tuple_id;");
        builder->emitIndent();
        builder->appendFormat("struct %s_mask next_tuple_mask;", keyTypeName.c_str());
        builder->newline();
        builder->emitIndent();
        builder->appendLine("__u8 has_next;");
        builder->blockEnd(false);
        builder->endOfStatement(true);
    }
}

void EBPFTernaryTablePSA::emitLookup(CodeBuilder *builder, cstring key, cstring value) {
    if (tableCacheEnabled)
        emitCacheLookup(builder, key, value);

    builder->appendFormat("struct %s_mask head = {0};", keyTypeName);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("struct %s_mask *", valueTypeName);
    builder->target->emitTableLookup(builder, name + "_prefixes", "head", "val");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (val && val->has_next != 0) ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("struct %s_mask next = val->next_tuple_mask;", keyTypeName);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("#pragma clang loop unroll(disable)");
    builder->emitIndent();
    builder->appendFormat("for (int i = 0; i < MAX_%s_MASKS; i++) ", keyTypeName.toUpper());
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("struct %s_mask *", valueTypeName);
    builder->target->emitTableLookup(builder, name + "_prefixes", "next", "v");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!v) ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
                                      "Control: No next element found!");
    builder->emitIndent();
    builder->appendLine("break;");
    builder->blockEnd(true);
    builder->emitIndent();
    cstring new_key = "k";
    builder->appendFormat("struct %s %s = {};", keyTypeName, new_key);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("__u32 *chunk = ((__u32 *) &%s);", new_key);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("__u32 *mask = ((__u32 *) &next);");
    builder->emitIndent();
    builder->appendLine("#pragma clang loop unroll(disable)");
    builder->emitIndent();
    builder->appendFormat("for (int i = 0; i < sizeof(struct %s_mask) / 4; i++) ", keyTypeName);
    builder->blockStart();
    cstring str = Util::printf_format("*(((__u32 *) &%s) + i)", key);
    builder->target->emitTraceMessage(builder,
                                  "Control: [Ternary] Masking next 4 bytes of %llx with mask %llx",
                                  2, str, "mask[i]");

    builder->emitIndent();
    builder->appendFormat("chunk[i] = ((__u32 *) &%s)[i] & mask[i];", key);
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendLine("__u32 tuple_id = v->tuple_id;");
    builder->emitIndent();
    builder->append("next = v->next_tuple_mask;");
    builder->newline();
    builder->emitIndent();
    builder->append("struct bpf_elf_map *");
    builder->target->emitTableLookup(builder, name + "_tuples_map",
            "tuple_id", "tuple");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!tuple) ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
      Util::printf_format("Control: Tuples map %s not found during ternary lookup. Bug?",
              name));
    builder->emitIndent();
    builder->append("break;");
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendFormat("struct %s *tuple_entry = "
                          "bpf_map_lookup_elem(%s, &%s)",
                          valueTypeName, "tuple", new_key);
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!tuple_entry) ");
    builder->blockStart();
    builder->emitIndent();
    builder->append("if (v->has_next == 0) ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("break;");
    builder->blockEnd(true);
    builder->emitIndent();
    builder->append("continue;");
    builder->newline();
    builder->blockEnd(true);
    builder->target->emitTraceMessage(builder,
            "Control: Ternary match found, priority=%d.", 1, "tuple_entry->priority");

    builder->emitIndent();
    builder->appendFormat("if (%s == NULL || tuple_entry->priority > %s->priority) ",
            value, value);
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("%s = tuple_entry;", value);
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->append("if (v->has_next == 0) ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("break;");
    builder->blockEnd(true);
    builder->blockEnd(true);
    builder->blockEnd(true);
}

void EBPFTernaryTablePSA::validateKeys() const {
    if (keyGenerator == nullptr)
        return;

    unsigned last_key_size = std::numeric_limits<unsigned>::max();
    for (auto it : keyGenerator->keyElements) {
        if (it->matchType->path->name.name == "selector")
            continue;

        auto type = program->typeMap->getType(it->expression);
        auto ebpfType = EBPFTypeFactory::instance->create(type);
        if (!ebpfType->is<IHasWidth>())
            continue;

        unsigned width = ebpfType->to<IHasWidth>()->widthInBits();
        if (width > last_key_size) {
            ::error(ErrorType::WARN_ORDERING,
                    "%1%: key field larger than previous key, move it before previous key "
                    "to avoid padding between these keys", it->expression);
            return;
        }
        last_key_size = width;
    }
}

void EBPFTernaryTablePSA::emitConstEntriesInitializer(CodeBuilder *builder) {
    CodeGenInspector cg(program->refMap, program->typeMap);
    cg.setBuilder(builder);
    std::vector<std::vector<const IR::Entry*>> entriesList = constEntriesGroupedByPrefix();
    std::vector<cstring> keyMasksNames;
    cstring uniquePrefix = name;
    int tuple_id = 0; // We have preallocated tuple maps with ids starting from 0

    // emit key head mask
    cstring headName = program->refMap->newName("key_mask");
    builder->emitIndent();
    builder->appendFormat("struct %s_mask %s = {0}", keyTypeName, headName);
    builder->endOfStatement(true);

    // emit key masks
    emitKeyMasks(builder, entriesList, keyMasksNames);

    builder->newline();

    // add head
    cstring valueMask = program->refMap->newName("value_mask");
    cstring nextMask = keyMasksNames[0];
    int noTupleId = -1;
    emitValueMask(builder, valueMask, nextMask, noTupleId);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("%s(0, 0, &%s, &%s, &%s, &%s, NULL, NULL)",
                          addPrefixFunctionName, tuplesMapName, prefixesMapName, headName, valueMask);
    builder->endOfStatement(true);
    builder->newline();

    // emit values + updates
    for (size_t i = 0; i < entriesList.size(); i++) {
        auto samePrefixEntries = entriesList[i];
        valueMask = program->refMap->newName("value_mask");
        std::vector<cstring> keyNames;
        std::vector<cstring> valueNames;
        cstring keysArray = program->refMap->newName("keys");
        cstring valuesArray = program->refMap->newName("values");
        cstring keyMaskVarName = keyMasksNames[i];

        nextMask = cstring::empty;
        if (entriesList.size() > i + 1) {
            nextMask = keyMasksNames[i + 1];
        }
        emitValueMask(builder, valueMask, nextMask, tuple_id);
        builder->newline();
        emitKeysAndValues(builder, samePrefixEntries, keyNames, valueNames);

        // construct keys array
        builder->newline();
        builder->emitIndent();
        builder->appendFormat("void *%s[] = {", keysArray);
        for (auto keyName : keyNames)
            builder->appendFormat("&%s,", keyName);
        builder->append("}");
        builder->endOfStatement(true);

        // construct values array
        builder->emitIndent();
        builder->appendFormat("void *%s[] = {", valuesArray);
        for (auto valueName : valueNames)
            builder->appendFormat("&%s,", valueName);
        builder->append("}");
        builder->endOfStatement(true);

        builder->newline();
        builder->emitIndent();
        builder->appendFormat("%s(%s, %s, &%s, &%s, &%s, &%s, %s, %s)",
                              addPrefixFunctionName,
                              cstring::to_cstring(samePrefixEntries.size()),
                              cstring::to_cstring(tuple_id),
                              tuplesMapName,
                              prefixesMapName,
                              keyMaskVarName,
                              valueMask,
                              keysArray,
                              valuesArray);
        builder->endOfStatement(true);

        tuple_id++;
    }
}

void EBPFTernaryTablePSA::emitKeysAndValues(CodeBuilder *builder,
                                            std::vector<const IR::Entry *> &samePrefixEntries,
                                            std::vector<cstring> &keyNames,
                                            std::vector<cstring> &valueNames) {
    CodeGenInspector cg(program->refMap, program->typeMap);
    cg.setBuilder(builder);

    for (auto entry : samePrefixEntries) {
        cstring keyName = program->refMap->newName("key");
        cstring valueName = program->refMap->newName("value");
        keyNames.push_back(keyName);
        valueNames.push_back(valueName);
        // construct key
        builder->emitIndent();
        builder->appendFormat("struct %s %s = {}", keyTypeName.c_str(), keyName.c_str());
        builder->endOfStatement(true);
        for (size_t k = 0; k < keyGenerator->keyElements.size(); k++) {
            auto keyElement = keyGenerator->keyElements[k];
            cstring fieldName = get(keyFieldNames, keyElement);
            CHECK_NULL(fieldName);
            builder->emitIndent();
            builder->appendFormat("%s.%s = ", keyName.c_str(), fieldName.c_str());
            auto mtdecl = program->refMap->getDeclaration(keyElement->matchType->path, true);
            auto matchType = mtdecl->getNode()->to<IR::Declaration_ID>();
            auto expr = entry->keys->components[k];
            auto ebpfType = get(keyTypes, keyElement);
            if (auto km = expr->to<IR::Mask>()) {
                km->left->apply(cg);
                builder->append(" & ");
                km->right->apply(cg);
            } else {
                expr->apply(cg);
                builder->append(" & ");
                unsigned width = 0;
                if (auto hasWidth = ebpfType->to<IHasWidth>()) {
                    width = hasWidth->widthInBits();
                } else {
                    BUG("Cannot assess field bit width");
                }
                builder->append("0x");
                for (int j = 0; j < width / 8; j++)
                    builder->append("ff");
            }
            builder->endOfStatement(true);
        }

        // construct value
        auto *mce = entry->action->to<IR::MethodCallExpression>();
        emitTableValue(builder, mce, valueName.c_str());
    }
}

void EBPFTernaryTablePSA::emitKeyMasks(CodeBuilder *builder,
                                       std::vector<std::vector<const IR::Entry *>> &entriesList,
                                       std::vector<cstring> &keyMasksNames) {
    CodeGenInspector cg(program->refMap, program->typeMap);
    cg.setBuilder(builder);

    for (auto samePrefixEntries : entriesList) {
        auto firstEntry = samePrefixEntries.front();
        cstring keyFieldName = program->refMap->newName("key_mask");
        keyMasksNames.push_back(keyFieldName);

        builder->emitIndent();
        builder->appendFormat("struct %s_mask %s = {0}", keyTypeName, keyFieldName);
        builder->endOfStatement(true);

        builder->emitIndent();
        cstring keyFieldNamePtr = program->refMap->newName(keyFieldName + "_ptr");
        builder->appendFormat("char *%s = &%s.mask", keyFieldNamePtr, keyFieldName);
        builder->endOfStatement(true);

        cstring prevField;
        for (size_t i = 0; i < keyGenerator->keyElements.size(); i++) {
            auto keyElement = keyGenerator->keyElements[i];
            auto expr = firstEntry->keys->components[i];
            cstring fieldName = program->refMap->newName("field");
            auto ebpfType = get(keyTypes, keyElement);
            builder->emitIndent();
            ebpfType->declare(builder, fieldName, false);
            builder->append(" = ");
            if (auto mask = expr->to<IR::Mask>()) {
                mask->right->apply(cg);
                builder->endOfStatement(true);
            } else {
                // MidEnd transforms 0xffff... masks into exact match
                // So we receive there a Constant same as exact match
                // So we have to create 0xffff... mask on our own
                unsigned width = 0;
                if (auto hasWidth = ebpfType->to<IHasWidth>()) {
                    width = hasWidth->widthInBits();
                } else {
                    BUG("Cannot assess field bit width");
                }
                builder->append("0x");
                for (int j = 0; j < width / 8; j++)
                    builder->append("ff");
                builder->endOfStatement(true);
            }
            builder->emitIndent();
            if (i == 0) {
                builder->appendFormat("__builtin_memcpy(%s, &%s, sizeof(%s))",
                                      keyFieldNamePtr, fieldName, fieldName);
            } else {
                builder->appendFormat("__builtin_memcpy(%s + sizeof(%s), &%s, sizeof(%s))",
                                      keyFieldNamePtr, prevField, fieldName, fieldName);
            }
            builder->endOfStatement(true);
            prevField = cstring(fieldName);
        }
    }
}

void EBPFTernaryTablePSA::emitValueMask(CodeBuilder *builder, const cstring valueMask,
                                        const cstring nextMask, int tupleId) const {
    builder->emitIndent();
    builder->appendFormat("struct %s_mask %s = {0}", valueTypeName, valueMask);
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("%s.tuple_id = %s", valueMask, cstring::to_cstring(tupleId));
    builder->endOfStatement(true);
    builder->emitIndent();
    if (nextMask.isNullOrEmpty()) {
        builder->appendFormat("%s.has_next = 0", valueMask);
        builder->endOfStatement(true);
    } else {
        builder->appendFormat("%s.next_tuple_mask = %s", valueMask, nextMask);
        builder->endOfStatement(true);
        builder->emitIndent();
        builder->appendFormat("%s.has_next = 1", valueMask);
        builder->endOfStatement(true);
    }
}

std::vector<std::vector<const IR::Entry*>> EBPFTernaryTablePSA::constEntriesGroupedByPrefix() {
    std::vector<std::vector<const IR::Entry*>> entriesGroupedByPrefix;
    std::vector<std::vector<int>> list;
    const IR::EntriesList* entries = table->container->getEntries();
    if (entries != nullptr) {
        for (int i = 0; i < (int)entries->entries.size(); i++) {
            if (!list.empty()) {
                auto last = list.back();
                auto it = std::find(last.begin(), last.end(), i);
                if (it != last.end()) {
                    // If this entry was added in a previous iteration
                    continue;
                }
            }
            auto main_entr = entries->entries[i];
            std::vector<int> indexes;
            indexes.push_back(i);
            for (int j = i; j < (int)entries->entries.size(); j++) {
                auto ref_entr = entries->entries[j];
                if (i != j) {
                    bool isTheSamePrefix = true;
                    for (size_t k = 0; k < main_entr->keys->components.size(); k++) {
                        auto k1 = main_entr->keys->components[k];
                        auto k2 = ref_entr->keys->components[k];
                        if (auto k1Mask = k1->to<IR::Mask>()) {
                            if (auto k2Mask = k2->to<IR::Mask>()) {
                                auto val1 = k1Mask->right->to<IR::Constant>();
                                auto val2 = k2Mask->right->to<IR::Constant>();
                                if (val1->value != val2->value) {
                                    isTheSamePrefix = false;
                                }
                            }
                        }
                    }
                    if (isTheSamePrefix) {
                        indexes.push_back(j);
                    }
                }
            }
            list.push_back(indexes);
        }

        for (auto samePrefixEntries : list) {
            std::vector<const IR::Entry*> samePrefEntries;
            for (int i : samePrefixEntries) {
                samePrefEntries.push_back(entries->entries[i]);
            }
            entriesGroupedByPrefix.push_back(samePrefEntries);
        }
    }

    return entriesGroupedByPrefix;
}

bool EBPFTernaryTablePSA::hasEntries() {
    const IR::EntriesList* entries = table->container->getEntries();
    return entries && entries->size() > 0;
}

cstring EBPFTernaryTablePSA::addPrefixFunc(bool trace) {
    cstring addPrefixFunc =
            "static __always_inline\n"
            "void add_prefix_and_entries(__u32 nr_entries,\n"
            "            __u32 tuple_id,\n"
            "            void *tuples_map,\n"
            "            void *prefixes_map,\n"
            "            void *key_mask,\n"
            "            void *value_mask,\n"
            "            void *keysPtrs[],\n"
            "            void *valuesPtrs[]) {\n"
            "    int ret = bpf_map_update_elem(prefixes_map, key_mask, value_mask, BPF_ANY);\n"
            "    if (ret) {\n"
            "%trace_msg_prefix_map_fail%"
            "        return;\n"
            "    }\n"
            "    if (nr_entries == 0) {\n"
            "        return;\n"
            "    }\n"
            "    struct bpf_elf_map *tuple = bpf_map_lookup_elem(tuples_map, &tuple_id);\n"
            "    if (tuple) {\n"
            "        for (__u32 i = 0; i < nr_entries; i++) {\n"
            "            int ret = bpf_map_update_elem(tuple, keysPtrs[i], valuesPtrs[i], "
            "BPF_ANY);\n"
            "            if (ret) {\n"
            "%trace_msg_tuple_update_fail%"
            "                return;\n"
            "            } else {\n"
            "%trace_msg_tuple_update_success%"
            "            }\n"
            "        }\n"
            "    } else {\n"
            "%trace_msg_tuple_not_found%"
            "        return;\n"
            "    }\n"
            "}";

    if (trace) {
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_prefix_map_fail%",
                "        bpf_trace_message(\"Prefixes map update failed\\n\");\n");
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_tuple_update_fail%",
                "                bpf_trace_message(\"Tuple map update failed\\n\");\n");
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_tuple_update_success%",
                "                bpf_trace_message(\"Tuple map update succeed\\n\");\n");
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_tuple_not_found%",
                "        bpf_trace_message(\"Tuple not found\\n\");\n");
    } else {
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_prefix_map_fail%",
                "");
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_tuple_update_fail%",
                "");
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_tuple_update_success%",
                "");
        addPrefixFunc = addPrefixFunc.replace(
                "%trace_msg_tuple_not_found%",
                "");
    }

    return addPrefixFunc;
}

}  // namespace EBPF
