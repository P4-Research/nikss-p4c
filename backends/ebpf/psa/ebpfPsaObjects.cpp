#include "backends/ebpf/ebpfType.h"
#include "ebpfPsaObjects.h"
#include "ebpfPipeline.h"

namespace EBPF {

// =====================ActionTranslationVisitorPSA=============================
bool ActionTranslationVisitorPSA::preorder(const IR::MethodCallExpression* expression) {
    auto mi = P4::MethodInstance::resolve(expression,
                                          program->refMap,
                                          program->typeMap);
    auto ext = mi->to<P4::ExternMethod>();
    if (ext != nullptr) {
        processMethod(ext);
        return false;
    }

    return CodeGenInspector::preorder(expression);
}

void ActionTranslationVisitorPSA::processMethod(const P4::ExternMethod* method) {
    auto declType = method->originalExternType;
    auto name = method->object->getName();

    if (declType->name.name == "Counter") {
        program->control->getCounter(name)->emitMethodInvocation(builder, method);
    } else if (declType->name.name == "DirectCounter") {
        auto ctr = table->getCounter(name);
        if (ctr != nullptr)
            ctr->emitDirectMethodInvocation(builder, method, valueName);
        else
            ::error(ErrorType::ERR_NOT_FOUND,
                    "%1%: Table %2% do not own DirectCounter named %3%",
                    method->expr, table->name, name);
    } else {
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "%1%: Unexpected method call in action", method->expr);
    }
}

// =====================EBPFTablePSA=============================
EBPFTablePSA::EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                           CodeGenInspector* codeGen, cstring name, size_t size) :
                           EBPFTable(program, table, codeGen), name(name), size(size) {
    initDirectCounters();
}

void EBPFTablePSA::initDirectCounters() {
    auto counterProperty = table->container->properties->getProperty("psa_direct_counter");
    if (counterProperty == nullptr)
        return;

    auto counterAdder = [this](const IR::PathExpression * pe){
        CHECK_NULL(pe);
        auto decl = program->refMap->getDeclaration(pe->path, true);
        auto di = decl->to<IR::Declaration_Instance>();
        CHECK_NULL(di);
        auto ctr = new EBPFCounterPSA(program, di, EBPFObject::externalName(di), codeGen);
        this->counters.emplace_back(std::make_pair(pe->path->name.name, ctr));
    };

    if (counterProperty->value->is<IR::ExpressionValue>()) {
        auto ev = counterProperty->value->to<IR::ExpressionValue>();

        if (ev->expression->is<IR::PathExpression>()) {
            counterAdder(ev->expression->to<IR::PathExpression>());
        } else if (ev->expression->is<IR::ListExpression>()) {
            auto le = ev->expression->to<IR::ListExpression>();
            for (auto c : le->components) {
                counterAdder(c->to<IR::PathExpression>());
            }
        } else {
            ::error(ErrorType::ERR_UNSUPPORTED,
                    "Unsupported list type: %1%", counterProperty->value);
        }
    } else {
        ::error(ErrorType::ERR_UNKNOWN,
                "Unknown property expression type: %1%", counterProperty->value);
    }
}

void EBPFTablePSA::emitInstance(CodeBuilder *builder) {
    TableKind kind = isLPMTable() ? TableLPMTrie : TableHash;
    builder->target->emitTableDecl(builder, name, kind,
                                   cstring("struct ") + keyTypeName,
                                   cstring("struct ") + valueTypeName, size);
    builder->target->emitTableDecl(builder, defaultActionMapName, TableArray,
                                   program->arrayIndexType,
                                   cstring("struct ") + valueTypeName, 1);
}

void EBPFTablePSA::emitDirectTypes(CodeBuilder* builder) {
    for (auto ctr : counters) {
        ctr.second->emitValueType(builder);
    }
}

void EBPFTablePSA::emitInitializer(CodeBuilder *builder) {
    this->emitDefaultActionInitializer(builder);
    this->emitConstEntriesInitializer(builder);
}

void EBPFTablePSA::emitConstEntriesInitializer(CodeBuilder *builder) {
    CodeGenInspector cg(program->refMap, program->typeMap);
    cg.setBuilder(builder);
    auto keyName = program->refMap->newName("key");
    auto valueName = program->refMap->newName("value");
    const IR::EntriesList* entries = table->container->getEntries();
    if (entries != nullptr) {
        for (auto entry : entries->entries) {
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
                entry->keys->components[index]->apply(cg);
                builder->endOfStatement(true);
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

// =====================EBPFTernaryTablePSA=============================
void EBPFTernaryTablePSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, name + "_prefixes", TableHash,
                                   "struct " + keyTypeName + "_mask",
                                   "struct " + valueTypeName + "_mask", size);
    builder->target->emitMapInMapDecl(builder, name + "_tuple",
                                      TableHash, "struct " + keyTypeName,
                                      "struct " + valueTypeName, size,
                                      name + "_tuples_map", TableArray, "__u32", size);
    builder->target->emitTableDecl(builder, defaultActionMapName, TableArray,
                                   program->arrayIndexType,
                                   cstring("struct ") + valueTypeName, 1);
}

void EBPFTernaryTablePSA::emitKeyType(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct %s ", keyTypeName.c_str());
    builder->blockStart();

    CodeGenInspector commentGen(program->refMap, program->typeMap);
    commentGen.setBuilder(builder);

    unsigned int structAlignment = 4;  // 4 by default
    unsigned int totalSizeOfKeys = 0;
    unsigned int lengthOfTernaryFields = 0;
    unsigned int lengthOfLPMFields = 0;
    if (keyGenerator != nullptr) {
        std::vector<std::pair<size_t, const IR::KeyElement*>> ordered;
        unsigned fieldNumber = 0;
        for (auto c : keyGenerator->keyElements) {
            auto type = program->typeMap->getType(c->expression);
            auto ebpfType = EBPFTypeFactory::instance->create(type);
            cstring fieldName = cstring("field") + Util::toString(fieldNumber);
            if (!ebpfType->is<IHasWidth>()) {
                ::error(ErrorType::ERR_TYPE_ERROR,
                        "%1%: illegal type %2% for key field", c, type);
                return;
            }
            unsigned width = ebpfType->to<IHasWidth>()->widthInBits();
            if (ebpfType->to<EBPFScalarType>()->alignment() > structAlignment) {
                structAlignment = 8;
            }

            auto mtdecl = program->refMap->getDeclaration(c->matchType->path, true);
            auto matchType = mtdecl->getNode()->to<IR::Declaration_ID>();
            if (matchType->name.name == P4::P4CoreLibrary::instance.ternaryMatch.name) {
                lengthOfTernaryFields += width;
            } else if (matchType->name.name == P4::P4CoreLibrary::instance.lpmMatch.name) {
                lengthOfLPMFields += width;
            }

            totalSizeOfKeys += ebpfType->to<EBPFScalarType>()->bytesRequired();
            ordered.emplace_back(width, c);
            keyTypes.emplace(c, ebpfType);
            keyFieldNames.emplace(c, fieldName);
            fieldNumber++;
        }

        // Use this to order elements by size
        std::stable_sort(ordered.begin(), ordered.end(),
                [] (std::pair<size_t, const IR::KeyElement*> p1,
                    std::pair<size_t, const IR::KeyElement*> p2) {
            return p1.first <= p2.first;
        });

        // Emit key in decreasing order size - this way there will be no gaps
        for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
            auto c = it->second;

            auto ebpfType = ::get(keyTypes, c);
            builder->emitIndent();
            cstring fieldName = ::get(keyFieldNames, c);
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
    builder->appendFormat("__u8 mask[%d];", totalSizeOfKeys);
    builder->newline();

    builder->blockEnd(false);
    builder->appendFormat(" __attribute__((aligned(%d)))", structAlignment);
    builder->endOfStatement(true);
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
