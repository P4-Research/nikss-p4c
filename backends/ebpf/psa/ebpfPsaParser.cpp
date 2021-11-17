#include "ebpfPsaParser.h"
#include "backends/ebpf/ebpfType.h"
#include "ebpfPsaTypes.h"

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

bool PsaStateTranslationVisitor::preorder(const IR::SelectCase* selectCase) {
    if (!selectHasValueSet)
        return StateTranslationVisitor::preorder(selectCase);

    CHECK_NULL(currentSelectExpression);

    builder->emitIndent();
    if (!selectFirstIfStatement)
        builder->append("else ");
    else
        selectFirstIfStatement = false;

    if (selectCase->keyset->is<IR::DefaultExpression>()) {
        selectHasDefault = true;
    } else {
        builder->append("if (");

        if (selectCase->keyset->is<IR::PathExpression>()) {
            cstring pvsName = selectCase->keyset->to<IR::PathExpression>()->path->name.name;
            auto pvs = parser->getValueSet(pvsName);
            pvs->emitLookup(builder);
            builder->append(" != NULL");
        } else {
            visit(selectCase->keyset);
            builder->append(" == ");
            visit(currentSelectExpression->select->components.at(0));
        }

        builder->append(") ");
    }

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

void PsaStateTranslationVisitor::compileExtract(const IR::Expression* destination) {
    auto type = state->parser->typeMap->getType(destination);
    auto ht = type->to<IR::Type_Header>();
    if (ht == nullptr) {
        StateTranslationVisitor::compileExtract(destination);
        return;
    }
    auto etype = new EBPFHeaderTypePSA(ht);

    unsigned width = ht->width_bits();
    auto program = state->parser->program;

    cstring offsetStr = Util::printf_format("BYTES(%s + %u)", program->offsetVar, width);
    // FIXME: program->lengthVariable should be used instead of difference of end and start
    builder->target->emitTraceMessage(builder, "Parser: check pkt_len=%%d < last_read_byte=%%d", 2,
        (program->packetEndVar + " - " + program->packetStartVar).c_str(), offsetStr.c_str());

    builder->emitIndent();
    builder->appendFormat("if (%s < %s + BYTES(%s + %u)) ",
                          program->packetEndVar.c_str(),
                          program->packetStartVar.c_str(),
                          program->offsetVar.c_str(), width);
    builder->blockStart();

    builder->target->emitTraceMessage(builder, "Parser: invalid packet (packet too short)");

    builder->emitIndent();
    builder->appendFormat("%s = %s;", program->errorVar.c_str(),
                          p4lib.packetTooShort.str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::reject.c_str());
    builder->newline();
    builder->blockEnd(true);

    cstring msgStr = Util::printf_format("Parser: extracting header %s", destination->toString());
    builder->target->emitTraceMessage(builder, msgStr.c_str());
    builder->newline();

    builder->emitIndent();
    builder->append("__builtin_memcpy((void *) &(");
    visit(destination);
    builder->appendFormat("), %s + BYTES(%s), BYTES(%u))",
                          program->packetStartVar.c_str(),
                          program->offsetVar.c_str(),
                          width);
    builder->endOfStatement(true);

    builder->emitIndent();
    visit(destination);
    builder->appendLine(".ebpf_valid = 1;");

    auto emitByteSwap = [this, destination, program]
            (unsigned byte1, unsigned byte2, unsigned baseOffset){
        byte1 += baseOffset / 8;
        byte2 += baseOffset / 8;

        builder->emitIndent();
        builder->appendFormat("%s = *(((u8*)&(", program->byteVar.c_str());
        visit(destination);
        builder->appendFormat(")) + %u)", byte1);
        builder->endOfStatement(true);

        builder->emitIndent();
        builder->appendFormat("*(((u8*)&(");
        visit(destination);
        builder->appendFormat(")) + %u) = *(((u8*)&(", byte1);
        visit(destination);
        builder->appendFormat(")) + %u)", byte2);
        builder->endOfStatement(true);

        builder->emitIndent();
        builder->appendFormat("*(((u8*)&(");
        visit(destination);
        builder->appendFormat(")) + %u) = %s", byte2, program->byteVar.c_str());
        builder->endOfStatement(true);
    };

    // bytes swap in a single group
    for (auto group : etype->groupedFields) {
        cstring swap, swap_type;
        unsigned swap_size = 0, shift = 0;
        if (group->groupWidth <= 8) {
            continue;
        } else if (group->groupWidth <= 16) {
            swap = "htons";
            swap_size = 16;
            swap_type = "u16";
        } else if (group->groupWidth <= 24) {
            emitByteSwap(0, 2, group->groupOffset);
            continue;
        } else if (group->groupWidth <= 32) {
            swap = "htonl";
            swap_size = 32;
            swap_type = "u32";
        } else if (group->groupWidth <= 40) {
            emitByteSwap(0, 4, group->groupOffset);
            emitByteSwap(1, 3, group->groupOffset);
            continue;
        } else if (group->groupWidth <= 48) {
            emitByteSwap(0, 5, group->groupOffset);
            emitByteSwap(1, 4, group->groupOffset);
            emitByteSwap(2, 3, group->groupOffset);
            continue;
        } else if (group->groupWidth <= 56) {
            emitByteSwap(0, 6, group->groupOffset);
            emitByteSwap(1, 5, group->groupOffset);
            emitByteSwap(2, 4, group->groupOffset);
            continue;
        } else if (group->groupWidth <= 64) {
            swap = "htonll";
            swap_size = 64;
            swap_type = "u64";
        } else {
            // ?????
        }

        shift = swap_size - group->groupWidth;
        builder->emitIndent();
        builder->appendFormat("*(%s*)((u8*)&(", swap_type.c_str());
        visit(destination);
        builder->appendFormat(") + BYTES(%u)) = %s(*(%s*)((u8*)&(",
                              group->groupOffset, swap.c_str(), swap_type.c_str());
        visit(destination);
        builder->appendFormat(") + BYTES(%u)))", group->groupOffset);
        if (shift > 0)
            builder->appendFormat(" >> %u", shift);
        builder->endOfStatement(true);
    }

    builder->newline();

    builder->emitIndent();
    builder->appendFormat("%s += %d", program->offsetVar.c_str(), width);
    builder->endOfStatement(true);

    msgStr = Util::printf_format("Parser: extracted %s", destination->toString());
    builder->target->emitTraceMessage(builder, msgStr.c_str());
}

EBPFPsaParser::EBPFPsaParser(const EBPFProgram* program, const IR::P4Parser* block,
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
    for (auto state : parserBlock->states) {
        for (auto c : state->components) {
            if (c->is<IR::MethodCallStatement>()) {
                auto mce = c->to<IR::MethodCallStatement>()->methodCall;
                auto mi = P4::MethodInstance::resolve(mce,
                                                      program->refMap,
                                                      program->typeMap);
                auto extMethod = mi->to<P4::ExternMethod>();
                if (extMethod != nullptr) {
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
    for (auto state : parserBlock->states) {
        for (auto c : state->components) {
            if (c->is<IR::MethodCallStatement>()) {
                auto mce = c->to<IR::MethodCallStatement>()->methodCall;
                auto mi = P4::MethodInstance::resolve(mce,
                                                      program->refMap,
                                                      program->typeMap);
                auto extMethod = mi->to<P4::ExternMethod>();
                if (extMethod != nullptr) {
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
