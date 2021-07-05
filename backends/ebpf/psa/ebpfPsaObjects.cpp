#include "backends/ebpf/ebpfType.h"
#include "ebpfPsaObjects.h"
#include "ebpfPipeline.h"
#include "ebpfPsaControlTranslators.h"
#include "backends/ebpf/psa/externs/ebpfPsaTableImplementation.h"

namespace EBPF {

// =====================ActionTranslationVisitorPSA=============================
ActionTranslationVisitorPSA::ActionTranslationVisitorPSA(cstring valueName,
                                                         const EBPFPipeline *program,
                                                         const EBPFTablePSA *table) :
        CodeGenInspector(program->refMap, program->typeMap),
        ActionTranslationVisitor(valueName, program),
        ControlBodyTranslatorPSA(program->control),
        table(table) {}

bool ActionTranslationVisitorPSA::preorder(const IR::PathExpression* pe) {
    if (isActionParameter(pe)) {
        return ActionTranslationVisitor::preorder(pe);
    }
    return ControlBodyTranslator::preorder(pe);
}

void ActionTranslationVisitorPSA::processMethod(const P4::ExternMethod* method) {
    auto declType = method->originalExternType;
    auto name = method->object->getName();

    if (declType->name.name == "DirectCounter") {
        auto ctr = table->getCounter(name);
        if (ctr != nullptr)
            ctr->emitDirectMethodInvocation(builder, method, valueName);
        else
            ::error(ErrorType::ERR_NOT_FOUND,
                    "%1%: Table %2% do not own DirectCounter named %3%",
                    method->expr, table->name, name);
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
        auto ctr = new EBPFCounterPSA(program, di, EBPFObject::externalName(di), codeGen);
        this->counters.emplace_back(std::make_pair(pe->path->name.name, ctr));
    };

    forEachPropertyEntry("psa_direct_counter", counterAdder);
}

void EBPFTablePSA::initDirectMeters() {
    auto meterAdder = [this](const IR::PathExpression * pe) {
        CHECK_NULL(pe);
        auto decl = program->refMap->getDeclaration(pe->path, true);
        this->meters.emplace_back(EBPFObject::externalName(decl));
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
    TableKind kind = isLPMTable() ? TableLPMTrie : TableHash;
    builder->target->emitTableDecl(builder, name, kind,
                                   cstring("struct ") + keyTypeName,
                                   cstring("struct ") + valueTypeName, size);

    if (!hasImplementation()) {
        // Default action is up to implementation
        builder->target->emitTableDecl(builder, defaultActionMapName, TableArray,
                                       program->arrayIndexType,
                                       cstring("struct ") + valueTypeName, 1);
    }
}

void EBPFTablePSA::emitDirectTypes(CodeBuilder* builder) {
    for (auto ctr : counters) {
        ctr.second->emitValueType(builder);
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
                    if (expr->is<IR::Mask>()) {
                        auto km = expr->to<IR::Mask>();
                        auto ebpfType = ::get(keyTypes, keyElement);
                        unsigned width = 0;
                        if (ebpfType->is<EBPFScalarType>()) {
                            auto scalar = ebpfType->to<EBPFScalarType>();
                            width = scalar->implementationWidthInBits();
                        }
                        builder->appendFormat("%s(", getByteSwapMethod(width));
                        km->left->apply(cg);
                        builder->append(")");
                        builder->endOfStatement(true);
                        builder->emitIndent();
                        builder->appendFormat("%s.%s = ", keyName.c_str(), prefixFieldName.c_str());
                        auto trailing_zeros = [width](const big_int& n) -> int {
                            return (n == 0) ? width : boost::multiprecision::lsb(n); };
                        auto count_ones = [](const big_int& n) -> int {
                            return bitcount(n); };
                        auto mask = km->right->to<IR::Constant>()->value;
                        auto len = trailing_zeros(mask);
                        if (len + count_ones(mask) != width) {  // any remaining 0s in the prefix?
                            ::error(ErrorType::ERR_INVALID,
                                    "%1% invalid mask for LPM key", keyElement);
                            return;
                        }
                        unsigned prefixLen = width - len;
                        builder->append(prefixLen);
                        builder->endOfStatement(true);
                    }
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
    }
}

void EBPFTernaryTablePSA::emitKeyType(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct %s ", keyTypeName.c_str());
    builder->blockStart();

    CodeGenInspector commentGen(program->refMap, program->typeMap);
    commentGen.setBuilder(builder);

    unsigned int structAlignment = 4;  // 4 by default
    if (keyGenerator != nullptr) {
        unsigned fieldNumber = 0;
        for (auto c : keyGenerator->keyElements) {
            if (c->matchType->path->name.name == "selector")
                continue;  // this match type is intended for ActionSelector, not table itself

            auto type = program->typeMap->getType(c->expression);
            auto ebpfType = EBPFTypeFactory::instance->create(type);
            cstring fieldName = cstring("field") + Util::toString(fieldNumber);
            if (!ebpfType->is<IHasWidth>()) {
                ::error(ErrorType::ERR_TYPE_ERROR,
                        "%1%: illegal type %2% for key field", c->expression, type);
                return;
            }
            if (ebpfType->to<EBPFScalarType>()->alignment() > structAlignment) {
                structAlignment = 8;
            }

            keyTypes.emplace(c, ebpfType);
            keyFieldNames.emplace(c, fieldName);
            fieldNumber++;

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
    // we set 256 as maximum number of ternary masks due to BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    // TODO: find better solution to workaround BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    builder->appendFormat("#define MAX_%s_MASKS %d", keyTypeName.toUpper(), 256);
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
    EBPFTable::emitValueType(builder);

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

// =====================EBPFValueSetPSA=============================
EBPFValueSetPSA::EBPFValueSetPSA(const EBPFProgram* program, const IR::P4ValueSet* p4vs,
                                 cstring instanceName, CodeGenInspector* codeGen)
     : EBPFTableBase(program, instanceName, codeGen), size(0), pvs(p4vs) {
    CHECK_NULL(pvs);
    valueTypeName = "u32";  // value is not used, we will check only if entry exists

    // validate size
    if (pvs->size->is<IR::Constant>()) {
        auto sc = pvs->size->to<IR::Constant>();
        if (sc->value.sign() <= 0) {
            ::error(ErrorType::ERR_INVALID,
                    "Invalid number of items in value_set (must be 1 or more): %1%", pvs->size);
        } else if (sc->fitsUint()) {
            size = sc->asUnsigned();
        } else {
            ::error(ErrorType::ERR_OVERLIMIT,
                    "Too many items in value_set (must be less than 2^32): %1%", pvs->size);
        }
    } else {
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "Size of value_set must be know at compilation time: %1%", pvs->size);
    }

    // validate type
    if (pvs->elementType->is<IR::Type_Bits>()) {
        // no restrictions
    } else if (pvs->elementType->is<IR::Type_Name>()) {
        auto type = pvs->elementType->to<IR::Type_Name>();
        keyTypeName = type->path->name.name;

        auto decl = program->refMap->getDeclaration(type->path, true);
        if (decl->is<IR::Type_Header>()) {
            ::warning("Header type may contain additional shadow data: %1%", pvs->elementType);
            ::warning("Header defined here: %1%", decl);
        }
        if (!decl->is<IR::Type_StructLike>()) {
            ::error(ErrorType::ERR_UNSUPPORTED,
                    "Unsupported type for value_set (hint: it might be a struct): %1%",
                    pvs->elementType);
        }
    } else if (pvs->elementType->is<IR::Type_Tuple>()) {
        // no restrictions
    } else {
        ::error(ErrorType::ERR_UNSUPPORTED,
                "Unsupported type with value_set: %1%", pvs->elementType);
    }

    keyTypeName = "struct " + keyTypeName;
}

void EBPFValueSetPSA::emitTypes(CodeBuilder* builder) {
    if (pvs->elementType->is<IR::Type_Name>()) {
        auto type = pvs->elementType->to<IR::Type_Name>();
        auto decl = program->refMap->getDeclaration(type->path, true);
        auto tsl = decl->to<IR::Type_StructLike>();
        CHECK_NULL(tsl);
        for (auto field : tsl->fields) {
            fieldNames.emplace_back(std::make_pair(field->name.name, field->type));
        }
        // Do not re-declare this type
        return;
    }

    builder->emitIndent();
    builder->appendFormat("%s ", keyTypeName.c_str());
    builder->blockStart();

    auto fieldEmitter = [builder](const IR::Type* type, cstring name){
        auto etype = EBPFTypeFactory::instance->create(type);
        builder->emitIndent();
        etype->declare(builder, name, false);
        builder->endOfStatement(true);
    };

    if (pvs->elementType->is<IR::Type_Bits>()) {
        auto type = pvs->elementType->to<IR::Type_Bits>();
        cstring name = "field0";
        fieldEmitter(type, name);
        fieldNames.emplace_back(std::make_pair(name, type));
    } else if (pvs->elementType->is<IR::Type_Tuple>()) {
        auto tuple = pvs->elementType->to<IR::Type_Tuple>();
        int i = 0;
        for (auto field : tuple->components) {
            cstring name = Util::printf_format("field%d", i++);
            fieldEmitter(field, name);
            fieldNames.emplace_back(std::make_pair(name, field));
        }
    } else {
        BUG("Type for value_set not implemented %1%", pvs->elementType);
    }

    builder->blockEnd(false);
    builder->endOfStatement(true);
}

void EBPFValueSetPSA::emitInstance(CodeBuilder* builder) {
    builder->target->emitTableDecl(builder, instanceName, TableKind::TableHash,
                                   keyTypeName, valueTypeName, size);
}

void EBPFValueSetPSA::emitKeyInitializer(CodeBuilder* builder,
                                         const IR::SelectExpression* expression,
                                         cstring varName) {
    if (fieldNames.size() != expression->select->components.size()) {
        ::error(ErrorType::ERR_EXPECTED,
                "Fields number of value_set do not match number of arguments: %1%", expression);
        return;
    }
    keyVarName = varName;
    builder->emitIndent();
    builder->appendFormat("%s %s = ", keyTypeName.c_str(), keyVarName.c_str());
    builder->blockStart();

    // initialize small fields up to 64 bits
    for (unsigned int i = 0; i < fieldNames.size(); i++) {
        if (fieldNames.at(i).second->is<IR::Type_Bits>()) {
            int width = fieldNames.at(i).second->to<IR::Type_Bits>()->width_bits();
            if (width > 64)
                continue;

            builder->emitIndent();
            builder->appendFormat(".%s = ", fieldNames.at(i).first);
            codeGen->visit(expression->select->components.at(i));
            builder->appendLine(",");
        }
    }

    builder->blockEnd(false);
    builder->endOfStatement(true);

    // init other bigger fields
    for (unsigned int i = 0; i < fieldNames.size(); i++) {
        if (fieldNames.at(i).second->is<IR::Type_Bits>()) {
            int width = fieldNames.at(i).second->to<IR::Type_Bits>()->width_bits();
            if (width <= 64)
                continue;
        }

        builder->emitIndent();
        cstring dst = Util::printf_format("%s.%s", keyVarName.c_str(),
                                          fieldNames.at(i).first.c_str());
        builder->appendFormat("__builtin_memcpy(&%s, &(", dst.c_str());
        codeGen->visit(expression->select->components.at(i));
        builder->appendFormat("), sizeof(%s))", dst.c_str());
        builder->endOfStatement(true);
    }
}

void EBPFValueSetPSA::emitLookup(CodeBuilder* builder) {
    builder->target->emitTableLookup(builder, instanceName, keyVarName, "");
}

}  // namespace EBPF
