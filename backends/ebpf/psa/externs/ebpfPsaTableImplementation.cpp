#include "ebpfPsaTableImplementation.h"
#include "backends/ebpf/psa/ebpfPsaControl.h"

namespace EBPF {

EBPFTableImplementationPSA::EBPFTableImplementationPSA(const EBPFProgram* program,
        CodeGenInspector* codeGen, const IR::Declaration_Instance* decl) :
        EBPFTablePSA(program, codeGen, externalName(decl)), declaration(decl) {
    referenceName = name + "_key";
}

void EBPFTableImplementationPSA::emitTypes(CodeBuilder* builder) {
    if (table == nullptr)
        return;
    // key is u32
    emitValueType(builder);
}

void EBPFTableImplementationPSA::emitInitializer(CodeBuilder *builder) {
    (void) builder;
}

void EBPFTableImplementationPSA::emitReferenceEntry(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("u32 %s", referenceName.c_str());
    builder->endOfStatement(true);
}

void EBPFTableImplementationPSA::registerTable(const EBPFTablePSA * instance) {
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

void EBPFTableImplementationPSA::verifyTableActionList(const EBPFTablePSA * instance) {
    bool printError = false;
    if (actionList == nullptr)
        return;

    auto getActionName = [](const IR::ActionList * al, size_t id)->cstring {
        auto mce = al->actionList.at(id)->expression->to<IR::MethodCallExpression>();
        BUG_CHECK(mce != nullptr, "%1%: expected an action call", mce);
        auto pe = mce->method->to<IR::PathExpression>();
        BUG_CHECK(pe != nullptr, "%1%: expected an action name", pe);
        return pe->path->name.originalName;
    };

    if (instance->actionList->size() == actionList->size()) {
        for (size_t i = 0; i < actionList->size(); ++i) {
            auto left = getActionName(instance->actionList, i);
            auto right = getActionName(actionList, i);
            if (left != right)
                printError = true;
        }
    } else {
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

void EBPFTableImplementationPSA::verifyTableNoDefaultAction(const EBPFTablePSA * instance) {
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

void EBPFTableImplementationPSA::verifyTableNoDirectObjects(const EBPFTablePSA * instance) {
    if (!instance->counters.empty() || !instance->meters.empty()) {
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "%1%: DirectCounter and DirectMeter externs are not supported "
                "with table implementation %2%",
                instance->table->container->name, declaration->type->toString());
    }
}

void EBPFTableImplementationPSA::verifyTableNoEntries(const EBPFTablePSA * instance) {
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

unsigned EBPFTableImplementationPSA::getUintFromExpression(const IR::Expression * expr,
                                                           unsigned defaultValue) {
    if (!expr->is<IR::Constant>()) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Must be constant value: %1%", expr);
        return defaultValue;
    }
    auto c = expr->to<IR::Constant>();
    if (!c->fitsUint()) {
        ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", c);
        return defaultValue;
    }
    return c->asUnsigned();
}

// ===============================ActionProfile===============================

EBPFActionProfilePSA::EBPFActionProfilePSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                                           const IR::Declaration_Instance* decl) :
        EBPFTableImplementationPSA(program, codeGen, decl) {
    size = getUintFromExpression(decl->arguments->at(0)->expression, 1);
}

void EBPFActionProfilePSA::emitInstance(CodeBuilder *builder) {
    if (table == nullptr)  // no table(s)
        return;

    // Control plane must have ability to know if given reference exists or is used.
    // Problem with TableArray: id of NoAction is 0 and default value of entry is also 0.
    //   If user change action for given reference to NoAction, it will be hard to
    //   distinguish it from non-existing entry using only key value.
    auto tableKind = TableHash;
    builder->target->emitTableDecl(builder, name, tableKind, "u32",
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

    // Do not set hit variable here, because other instance before
    // may it already set to 0 (no match).

    emitAction(builder, apValueName, actionRunVariable);

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
}

// ===============================ActionSelector===============================

EBPFActionSelectorPSA::EBPFActionSelectorPSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                                             const IR::Declaration_Instance* decl) :
        EBPFTableImplementationPSA(program, codeGen, decl), emptyGroupAction(nullptr) {
    hashEngine = EBPFHashAlgorithmTypeFactoryPSA::instance()->create(
            getUintFromExpression(decl->arguments->at(0)->expression, 0),
            program, name + "_hash");
    if (hashEngine != nullptr) {
        hashEngine->setVisitor(codeGen);
    } else {
        ::error(ErrorType::ERR_UNSUPPORTED,
                "Algorithm not yet implemented: %1%", decl->arguments->at(0));
        hashEngine = new EBPFHashAlgorithmPSA(program, name + "_hash");
    }

    size = getUintFromExpression(decl->arguments->at(1)->expression, 1);

    unsigned outputHashWidth = getUintFromExpression(decl->arguments->at(2)->expression, 0);
    if (outputHashWidth > hashEngine->getOutputWidth()) {
        ::error(ErrorType::ERR_INVALID, "%1%: more bits requested than hash provides (%2%)",
                decl->arguments->at(2)->expression, hashEngine->getOutputWidth());
    }
    if (outputHashWidth > 64) {
        ::error(ErrorType::ERR_UNSUPPORTED, "%1%: supported up to 64 bits",
                decl->arguments->at(2)->expression);
    }
    outputHashMask = Util::printf_format("0x%llx", (1ull << outputHashWidth) - 1);

    // map names
    actionsMapName = name + "_actions";
    groupsMapName = name + "_groups";
    emptyGroupActionMapName = name + "_defaultActionGroup";

    groupsMapSize = 0;
}

void EBPFActionSelectorPSA::emitInitializer(CodeBuilder *builder) {
    if (emptyGroupAction == nullptr)
        return;  // no entry to initialize

    auto ev = emptyGroupAction->value->to<IR::ExpressionValue>()->expression;
    cstring value = program->refMap->newName("value");

    if (auto pe = ev->to<IR::PathExpression>()) {
        auto decl = program->refMap->getDeclaration(pe->path, true);
        auto action = decl->to<IR::P4Action>();
        BUG_CHECK(action != nullptr, "%1%: not an action", ev);

        if (!action->getParameters()->empty()) {
            ::error(ErrorType::ERR_UNINITIALIZED,
                    "%1%: missing value for action parameters: %2%",
                    ev, action->getParameters());
            return;
        }

        builder->emitIndent();
        builder->appendFormat("struct %s %s = ", valueTypeName.c_str(), value.c_str());
        builder->blockStart();
        builder->emitIndent();
        if (action->name.originalName == P4::P4CoreLibrary::instance.noAction.name) {
            builder->append(".action = 0,");
        } else {
            builder->appendFormat(".action = %s,", actionToActionIDName(action));
        }
        builder->newline();
        builder->blockEnd(false);
        builder->endOfStatement(true);
    } else if (auto mce = ev->to<IR::MethodCallExpression>()) {
        emitTableValue(builder, mce, value);
    }

    cstring ret = program->refMap->newName("ret");
    builder->emitIndent();
    builder->appendFormat("int %s = ", ret.c_str());
    builder->target->emitTableUpdate(builder, emptyGroupActionMapName,
                                     program->zeroKey, value);
    builder->newline();

    emitMapUpdateTraceMsg(builder, emptyGroupActionMapName, ret);
}

void EBPFActionSelectorPSA::emitInstance(CodeBuilder *builder) {
    if (table == nullptr)  // no table(s)
        return;

    // group map (group ref -> {action refs})
    // TODO: group size (inner size) is assumed to be 128. Make more logic for this.
    builder->target->emitMapInMapDecl(builder, groupsMapName + "_inner", TableArray,
                                      "u32", "u32", 128,
                                      groupsMapName, TableHash,
                                      "u32", groupsMapSize);

    // default empty group action (0 -> action)
    builder->target->emitTableDecl(builder, emptyGroupActionMapName, TableArray,
                                   program->arrayIndexType,
                                   cstring("struct ") + valueTypeName, 1);

    // action map (ref -> action)
    builder->target->emitTableDecl(builder, actionsMapName, TableHash, "u32",
                                   cstring("struct ") + valueTypeName, size);
}

void EBPFActionSelectorPSA::applyImplementation(CodeBuilder* builder, cstring tableValueName,
                                                cstring actionRunVariable) {
    cstring msg = Util::printf_format("ActionSelector: applying %s", name.c_str());
    builder->target->emitTraceMessage(builder, msg.c_str());

    // 1. Declare variables.

    cstring asValueName = program->refMap->newName("as_value");
    cstring effectiveActionRefName = program->refMap->newName("as_action_ref");
    cstring groupStateName = program->refMap->newName("as_group_state");
    cstring innerGroupName = program->refMap->newName("as_group_map");
    // these can be hardcoded because they are declared inside of a block
    cstring checksumValName = "as_checksum_val";
    cstring mapEntryName = "as_map_entry";

    builder->emitIndent();
    builder->appendFormat("struct %s * %s = NULL", valueTypeName.c_str(), asValueName.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("u32 %s = %s->%s", effectiveActionRefName.c_str(),
                          tableValueName.c_str(), referenceName.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("u8 %s = 0", groupStateName.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("void * ");
    builder->target->emitTableLookup(builder, groupsMapName, effectiveActionRefName,
                                     innerGroupName);
    builder->endOfStatement(true);

    // 2. Check if we have got group reference.

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", innerGroupName.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "ActionSelector: group reference %u",
                                      1, effectiveActionRefName.c_str());

    // 3. Calculate hash of selector keys and use some least significant bits.

    hashEngine->emitVariables(builder, nullptr);
    hashEngine->emitAddData(builder, unpackSelectors());

    builder->emitIndent();
    builder->appendFormat("u64 %s = ", checksumValName.c_str());
    hashEngine->emitGet(builder);
    builder->appendFormat(" & %s", outputHashMask.c_str());
    builder->endOfStatement(true);

    // 4. Find member reference.
    // First entry in inner map contains number of valid elements in the map

    builder->emitIndent();
    builder->append("u32 * ");
    builder->target->emitTableLookup(builder, innerGroupName, program->zeroKey, mapEntryName);
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", mapEntryName.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("if (*%s != 0) ", mapEntryName.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("%s = 1 + (%s %% (*%s))", effectiveActionRefName.c_str(),
                          checksumValName.c_str(), mapEntryName.c_str());
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->target->emitTableLookup(builder, innerGroupName, effectiveActionRefName,
                                     mapEntryName);
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", mapEntryName.c_str());
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("%s = *%s", effectiveActionRefName.c_str(), mapEntryName.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(false);
    builder->append(" else ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("/* Entry with action reference was not found, going to NoAction */");
    builder->emitIndent();
    builder->appendFormat("%s = 2", groupStateName.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->blockEnd(false);  // elements != 0
    builder->append(" else ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
        "ActionSelector: empty group, going to default action");
    builder->emitIndent();
    builder->appendFormat("%s = 1", groupStateName.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->blockEnd(false);  // found number of elements
    builder->append(" else ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
        "ActionSelector: entry with number of elements not found, going to default action");
    builder->emitIndent();
    builder->appendFormat("%s = 1", groupStateName.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->blockEnd(true);  // is group reference

    // 5. Use group state and action ref to get an action data.

    builder->emitIndent();
    builder->appendFormat("if (%s == 0) ", groupStateName.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "ActionSelector: member reference %u",
                                      1, effectiveActionRefName.c_str());
    builder->emitIndent();
    builder->target->emitTableLookup(builder, actionsMapName, effectiveActionRefName, asValueName);
    builder->endOfStatement(true);
    builder->blockEnd(false);
    builder->appendFormat(" else if (%s == 1) ", groupStateName.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
        "ActionSelector: empty group, executing default group action");
    builder->emitIndent();
    builder->target->emitTableLookup(builder, emptyGroupActionMapName,
                                     program->zeroKey, asValueName);
    builder->endOfStatement(true);
    builder->blockEnd(true);

    // 6. Execute action.

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", asValueName.c_str());
    builder->blockStart();

    emitAction(builder, asValueName, actionRunVariable);

    builder->blockEnd(false);
    builder->append(" else ");

    builder->blockStart();
    builder->target->emitTraceMessage(builder,
        "ActionSelector: member not found, executing implicit NoAction");
    builder->emitIndent();
    builder->appendFormat("%s = 0", program->control->hitVariable.c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    msg = Util::printf_format("ActionSelector: %s applied", name.c_str());
    builder->target->emitTraceMessage(builder, msg.c_str());
}

EBPFHashAlgorithmPSA::argumentsList EBPFActionSelectorPSA::unpackSelectors() {
    EBPFHashAlgorithmPSA::argumentsList result;
    for (auto s : selectors) {
        result.emplace_back(s->expression);
    }
    return result;
}

EBPFActionSelectorPSA::selectorsListType
EBPFActionSelectorPSA::getSelectorsFromTable(const EBPFTablePSA * instance) {
    selectorsListType ret;

    for (auto k : instance->keyGenerator->keyElements) {
        auto mkdecl = program->refMap->getDeclaration(k->matchType->path, true);
        auto matchType = mkdecl->getNode()->to<IR::Declaration_ID>();

        if (matchType->name.name == "selector")
            ret.emplace_back(k);
    }

    return ret;
}

void EBPFActionSelectorPSA::registerTable(const EBPFTablePSA * instance) {
    if (table == nullptr) {
        selectors = getSelectorsFromTable(instance);
        emptyGroupAction =
            instance->table->container->properties->getProperty("psa_empty_group_action");
        groupsMapSize = instance->size;
    } else {
        verifyTableSelectorKeySet(instance);
        verifyTableEmptyGroupAction(instance);

        // Documentation says: The number of groups may be at most the size of the table
        //     that is implemented by the selector.
        // So, when we take the max from both tables, this value will not be conformant
        // with specification because for one table there will be available more groups
        // than possible entries. We have to use min.
        groupsMapSize = std::min(groupsMapSize, instance->size);
    }

    EBPFTableImplementationPSA::registerTable(instance);
}

void EBPFActionSelectorPSA::verifyTableSelectorKeySet(const EBPFTablePSA * instance) {
    bool printError = false;
    auto is = getSelectorsFromTable(instance);

    if (selectors.size() == is.size()) {
        for (size_t i = 0; i < selectors.size(); ++i) {
            auto left = is.at(i)->expression->toString();
            auto right = selectors.at(i)->expression->toString();
            if (left != right)
                printError = true;
        }
    } else {
        printError = true;
    }

    if (printError) {
        ::error(ErrorType::ERR_EXPECTED,
                "%1%: selector type keys list differs from previous %2% "
                "(tables use the same implementation %3%)",
                instance->table->container, table->container, declaration);
    }
}

void EBPFActionSelectorPSA::verifyTableEmptyGroupAction(const EBPFTablePSA * instance) {
    auto iega = instance->table->container->properties->getProperty("psa_empty_group_action");

    if (emptyGroupAction == nullptr && iega == nullptr)
        return;  // nothing to do here
    if (emptyGroupAction == nullptr && iega != nullptr) {
        ::error(ErrorType::ERR_UNEXPECTED,
                "%1%: property not specified in previous table %2% "
                "(tables use the same implementation %3%)",
                iega, table->container, declaration);
        return;
    }
    if (emptyGroupAction != nullptr && iega == nullptr) {
        ::error(ErrorType::ERR_EXPECTED,
                "%1%: missing property %2%, defined in previous table %3% "
                "(tables use the same implementation %4%)", instance->table->container,
                emptyGroupAction, table->container->toString(), declaration);
        return;
    }

    bool same = true;
    cstring additionalNote;

    if (emptyGroupAction->isConstant != iega->isConstant) {
        same = false;
        additionalNote = "; note: const qualifiers also must be the same";
    }

    // compare action and arguments
    auto rev = iega->value->to<IR::ExpressionValue>()->expression;
    auto lev = emptyGroupAction->value->to<IR::ExpressionValue>()->expression;
    auto rpe = rev->to<IR::PathExpression>();
    auto lpe = lev->to<IR::PathExpression>();
    auto rmce = rev->to<IR::MethodCallExpression>();
    auto lmce = lev->to<IR::MethodCallExpression>();

    if (lpe != nullptr && rpe != nullptr) {
        if (lpe->toString() != rpe->toString())
            same = false;
    } else if (lmce != nullptr && rmce != nullptr) {
        if (lmce->method->to<IR::PathExpression>()->path->name.originalName !=
            rmce->method->to<IR::PathExpression>()->path->name.originalName) {
            same = false;
        } else if (lmce->arguments->size() == rmce->arguments->size()) {
            for (size_t i = 0; i < lmce->arguments->size(); ++i) {
                if (lmce->arguments->at(i)->expression->toString() !=
                    rmce->arguments->at(i)->expression->toString()) {
                    same = false;
                    additionalNote = "; note: action arguments must be the same for both tables";
                }
            }
        } else {
            same = false;
        }
    } else {
        same = false;
        additionalNote = "; note: action name can\'t be mixed with "
                         "action call expression (compiler backend limitation)";
    }

    if (!same) {
        ::error(ErrorType::ERR_EXPECTED,
                "%1%: defined property value is different from %2%, defined in "
                "previous table %3% (tables use the same implementation %4%)%5%",
                rev, lev, table->container->toString(), declaration, additionalNote);
    }
}

}  // namespace EBPF
