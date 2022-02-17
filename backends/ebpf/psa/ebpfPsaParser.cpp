#include "ebpfPsaParser.h"
#include "backends/ebpf/ebpfType.h"

namespace EBPF {

bool PsaStateTranslationVisitor::preorder(const IR::Expression* expression) {
    // Allow for friendly error name in comment before verify() call, e.g. error.NoMatch
    if (expression->is<IR::TypeNameExpression>()) {
        auto tne = expression->to<IR::TypeNameExpression>();
        builder->append(tne->typeName->path->name.name);
        return false;
    }

    return CodeGenInspector::preorder(expression);
}

bool PsaStateTranslationVisitor::preorder(const IR::Mask *mask) {
    CHECK_NULL(currentSelectExpression);
    builder->append("(");
    visit(currentSelectExpression->select->components.at(0));
    builder->append(" & ");
    visit(mask->right);
    builder->append(") == (");
    visit(mask->left);
    builder->append(" & ");
    visit(mask->right);
    builder->append(")");
    return false;
}

bool PsaStateTranslationVisitor::preorder(const IR::SelectCase* selectCase) {
    if (!selectHasValueSet)
        return StateTranslationVisitor::preorder(selectCase);

    CHECK_NULL(currentSelectExpression);

    builder->emitIndent();
    if (!selectFirstIfStatement)
        builder->append("else ");
    else
        selectFirstIfStatement = false;

    builder->append("if (");

    if (selectCase->keyset->is<IR::PathExpression>()) {
        cstring pvsName = selectCase->keyset->to<IR::PathExpression>()->path->name.name;
        auto pvs = parser->getValueSet(pvsName);
        pvs->emitLookup(builder);
        builder->append(" != NULL");
    } else if (selectCase->keyset->is<IR::Mask>()) {
        visit(selectCase->keyset);
    } else {
        visit(selectCase->keyset);
        builder->append(" == ");
        visit(currentSelectExpression->select->components.at(0));
    }

    builder->append(") ");


    builder->append("goto ");
    visit(selectCase->state);
    builder->endOfStatement(true);

    return false;
}

bool PsaStateTranslationVisitor::preorder(const IR::SelectExpression* expression) {
    selectHasValueSet = false;
    selectFirstIfStatement = true;
    selectHasDefault = false;
    currentSelectExpression = expression;

    for (auto e : expression->selectCases) {
        if (e->keyset->is<IR::PathExpression>()) {
            selectHasValueSet = true;

            cstring pvsName = e->keyset->to<IR::PathExpression>()->path->name.name;
            cstring pvsKeyVarName = parser->program->refMap->newName(pvsName + "_key");
            auto pvs = parser->getValueSet(pvsName);
            pvs->emitKeyInitializer(builder, expression, pvsKeyVarName);
        }
    }

    if (!selectHasValueSet)
        return StateTranslationVisitor::preorder(expression);

    if (expression->select->components.size() != 1) {
        // TODO: add support for tuples
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "%1%: only supporting a single argument for select", expression->select);
        return false;
    }

    for (auto e : expression->selectCases) {
        visit(e);
    }

    if (!selectHasDefault) {
        builder->emitIndent();
        builder->appendFormat("goto %s", IR::ParserState::reject.c_str());
        builder->endOfStatement(true);
    }

    return false;
}

void PsaStateTranslationVisitor::processFunction(const P4::ExternFunction* function) {
    if (function->method->name.name == "verify") {
        compileVerify(function->expr);
        return;
    }

    StateTranslationVisitor::processFunction(function);
}

void PsaStateTranslationVisitor::processMethod(const P4::ExternMethod* ext) {
    auto externName = ext->originalExternType->name.name;

    if (externName == "InternetChecksum" || externName == "Checksum") {
        auto instance = ext->object->getName().name;
        auto method = ext->method->getName().name;
        parser->getChecksum(instance)->processMethod(builder, method, ext->expr, this);
        return;
    }

    StateTranslationVisitor::processMethod(ext);
}

void PsaStateTranslationVisitor::compileVerify(const IR::MethodCallExpression * expression) {
    BUG_CHECK(expression->arguments->size() == 2, "Expected 2 arguments: %1%", expression);

    builder->emitIndent();
    builder->append("if (!(");
    visit(expression->arguments->at(0));
    builder->append(")) ");

    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("%s = ", parser->program->errorVar.c_str());

    auto mt = expression->arguments->at(1)->expression->to<IR::Member>();
    if (mt == nullptr) {
        ::error(ErrorType::ERR_UNEXPECTED, "%1%: not accessing a member error type",
                expression->arguments->at(1));
        return;
    }
    auto tne = mt->expr->to<IR::TypeNameExpression>();
    if (tne == nullptr) {
        ::error(ErrorType::ERR_UNEXPECTED, "%1%: not accessing a member error type",
                expression->arguments->at(1));
        return;
    }
    if (tne->typeName->path->name.name != "error") {
        ::error(ErrorType::ERR_UNEXPECTED, "%1%: must be an error type",
                expression->arguments->at(1));
        return;
    }
    builder->append(mt->member.name);

    builder->endOfStatement(true);

    cstring msg = Util::printf_format("Verify: condition failed, parser_error=%%u (%s)",
                                      mt->member.name);
    builder->target->emitTraceMessage(builder, msg.c_str(), 1, parser->program->errorVar.c_str());

    builder->emitIndent();
    builder->appendFormat("goto %s", IR::ParserState::reject.c_str());
    builder->endOfStatement(true);
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

EBPFPsaParser::EBPFPsaParser(const EBPFProgram* program, const IR::ParserBlock* block,
                             const P4::TypeMap* typeMap) : EBPFParser(program, block, typeMap) {
    visitor = new PsaStateTranslationVisitor(program->refMap, program->typeMap, this);
}

void EBPFPsaParser::emitDeclaration(CodeBuilder* builder, const IR::Declaration* decl) {
    if (decl->is<IR::Declaration_Instance>()) {
        auto di = decl->to<IR::Declaration_Instance>();
        auto type = di->type->to<IR::Type_Name>();
        auto typeSpec = di->type->to<IR::Type_Specialized>();
        cstring name = di->name.name;

        if (type != nullptr && type->path->name.name == "InternetChecksum") {
            auto instance = new EBPFInternetChecksumPSA(program, di, name);
            checksums.emplace(name, instance);
            instance->emitVariables(builder);
            return;
        }

        if (typeSpec != nullptr &&
                typeSpec->baseType->to<IR::Type_Name>()->path->name.name == "Checksum") {
            auto instance = new EBPFChecksumPSA(program, di, name);
            checksums.emplace(name, instance);
            instance->emitVariables(builder);
            return;
        }
    }

    if (decl->is<IR::P4ValueSet>()) {
        return;
    }

    EBPFParser::emitDeclaration(builder, decl);
}

void EBPFPsaParser::emitTypes(CodeBuilder* builder) {
    for (auto pvs : valueSets) {
        pvs.second->emitTypes(builder);
    }
}

void EBPFPsaParser::emitValueSetInstances(CodeBuilder* builder) {
    for (auto pvs : valueSets) {
        pvs.second->emitInstance(builder);
    }
}

void EBPFPsaParser::emitRejectState(CodeBuilder* builder) {
    builder->emitIndent();
    builder->appendFormat("if (%s == 0) ", program->errorVar.c_str());
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
        "Parser: Explicit transition to reject state, dropping packet..");
    builder->emitIndent();
    builder->appendFormat("return %s", builder->target->abortReturnCode().c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendFormat("goto %s", IR::ParserState::accept.c_str());
    builder->endOfStatement(true);
}

bool EBPFPsaParser::isHeaderExtractedByParser(cstring hdrName) {
    for (auto state : parserBlock->container->states) {
        for (auto c : state->components) {
            if (c->is<IR::MethodCallStatement>()) {
                auto mce = c->to<IR::MethodCallStatement>()->methodCall;
                auto mi = P4::MethodInstance::resolve(mce,
                                                      program->refMap,
                                                      program->typeMap);
                auto extMethod = mi->to<P4::ExternMethod>();
                if (extMethod != nullptr) {
                    if (extMethod->originalExternType->getName().name != P4::P4CoreLibrary::instance.packetIn.name)
                        continue;
                    if (extMethod->method->getName().name != P4::P4CoreLibrary::instance.packetIn.extract.name)
                        continue;
                    auto extractedHdr = extMethod->expr->arguments->at(0)->expression;
                    if (extractedHdr->is<IR::Member>() &&
                        extractedHdr->to<IR::Member>()->expr->is<IR::PathExpression>()) {
                        auto name = extractedHdr->to<IR::Member>()->member.name;
                        auto headers = extractedHdr->to<IR::Member>()->expr->
                                to<IR::PathExpression>()->path->name.name;
                        // this kind of expression is independent of whether hdr is pointer or not.
                        if (hdrName.find(headers) && hdrName.find(name)) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool EBPFPsaParser::isHeaderExtractedByParserWithNoLookaheadBefore(cstring hdrName) {
    for (auto state : parserBlock->container->states) {
        for (auto c : state->components) {
            if (c->is<IR::MethodCallStatement>()) {
                auto mce = c->to<IR::MethodCallStatement>()->methodCall;
                auto mi = P4::MethodInstance::resolve(mce,
                                                      program->refMap,
                                                      program->typeMap);
                auto extMethod = mi->to<P4::ExternMethod>();
                if (extMethod != nullptr) {
                    if (extMethod->originalExternType->getName().name != P4::P4CoreLibrary::instance.packetIn.name)
                        continue;
                    if (extMethod->method->getName().name != P4::P4CoreLibrary::instance.packetIn.extract.name)
                        continue;
                    auto extractedHdr = extMethod->expr->arguments->at(0)->expression;
                    if (extractedHdr->is<IR::Member>() &&
                        extractedHdr->to<IR::Member>()->expr->is<IR::PathExpression>()) {
                        auto name = extractedHdr->to<IR::Member>()->member.name;
                        auto headers = extractedHdr->to<IR::Member>()->expr->
                                to<IR::PathExpression>()->path->name.name;
                        // this kind of expression is independent of whether hdr is pointer or not.
                        if (hdrName.find(headers) && hdrName.find(name)) {
                            return true;
                        }
                    }
                }
            } else if (c->is<IR::AssignmentStatement>()) {
                // if we met lookahead before the header being checked is extracted,
                // we return false because header is conditionally extracted.
                auto as = c->to<IR::AssignmentStatement>();
                if (auto mce = as->right->to<IR::MethodCallExpression>()) {
                    auto mi = P4::MethodInstance::resolve(mce,
                                                          this->program->refMap,
                                                          this->program->typeMap);
                    auto extMethod = mi->to<P4::ExternMethod>();
                    if (extMethod == nullptr)
                        BUG("Unhandled method %1%", mce);

                    auto decl = extMethod->object;
                    if (decl == this->packet) {
                        if (extMethod->method->name.name ==
                            P4::P4CoreLibrary::instance.packetIn.lookahead.name) {
                            return false;
                        }
                    }
                }
            }
        }
    }
    return false;
}

// =====================EBPFOptimizedEgressParserPSA=============================
bool OptimizedEgressParserStateVisitor::shouldMoveOffset(cstring hdr) {
    for (auto h : parser->headersToSkipMovingOffset) {
        if (h.first.endsWith(hdr)) {
            return false;
        }
    }

    return true;
}

void OptimizedEgressParserStateVisitor::compileExtract(const IR::Expression *destination) {
    auto type = state->parser->typeMap->getType(destination);
    auto ht = type->to<IR::Type_StructLike>();
    if (ht == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                "Cannot extract to a non-struct type %1%", destination);
        return;
    }

    unsigned width = ht->width_bits();

    if (destination->is<IR::PathExpression>()) {
        PsaStateTranslationVisitor::compileExtract(destination);
        return;
    }

    builder->emitIndent();
    builder->append("if (!");
    cstring hdrName = destination->toString().replace(".", "_");
    builder->append(hdrName);
    builder->append("_ingress_ebpf_valid) ");
    builder->blockStart();
    PsaStateTranslationVisitor::compileExtract(destination);
    builder->blockEnd(false);
    builder->append(" else ");
    builder->blockStart();
    builder->emitIndent();
    visit(destination);
    builder->append(".ebpf_valid = 1");
    builder->endOfStatement(true);
    if (destination->is<IR::Member>()) {
        auto hdr = destination->to<IR::Member>()->member.name;
        if (shouldMoveOffset(hdr)) {
            builder->emitIndent();
            builder->appendFormat("%s += %d", parser->program->offsetVar.c_str(), width);
            builder->endOfStatement(true);
        }
    }
    builder->blockEnd(true);

    if (destination->is<IR::Member>() &&
        parser->headersToInvalidate.find(destination->to<IR::Member>()->member.name) !=
        parser->headersToInvalidate.end()) {
        parser->headersToInvalidate.erase(destination->to<IR::Member>()->member.name);
    }
}

bool OptimizedEgressParserStateVisitor::preorder(const IR::ParserState *parserState) {
    if (parserState->isBuiltin()) return false;

    builder->emitIndent();
    builder->append(parserState->name.name);
    builder->append(":");
    builder->spc();
    builder->blockStart();

    cstring msgStr = Util::printf_format("Parser: state %s (curr_offset=%%u)",
                                         parserState->name.name);
    builder->target->emitTraceMessage(builder, msgStr.c_str(), 1,
                                      state->parser->program->offsetVar);

    visit(parserState->components, "components");
    if (parserState->selectExpression == nullptr) {
        builder->emitIndent();
        builder->append("goto ");
        builder->append(IR::ParserState::reject);
        builder->endOfStatement(true);
    } else if (parserState->selectExpression->is<IR::SelectExpression>()) {
        visit(parserState->selectExpression);
    } else {
        // must be a PathExpression which is a state name
        if (!parserState->selectExpression->is<IR::PathExpression>())
            BUG("Expected a PathExpression, got a %1%", parserState->selectExpression);
        builder->emitIndent();
        builder->append("goto ");
        visit(parserState->selectExpression);
        builder->endOfStatement(true);
    }

    builder->blockEnd(true);
    return false;
}

}  // namespace EBPF
