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

EBPFPsaParser::EBPFPsaParser(const EBPFProgram* program, const IR::P4Parser* block,
                             const P4::TypeMap* typeMap) : EBPFParser(program, block, typeMap) {
    visitor = new PsaStateTranslationVisitor(program->refMap, program->typeMap, this);
}

// dead code
bool EBPFPsaParser::build() {
    auto pl = parserBlock->type->applyParams;
    if (pl->size() != 6) {
        ::error(ErrorType::ERR_EXPECTED,
                "Expected parser to have exactly 6 parameters");
        return false;
    }
    auto it = pl->parameters.begin();
    packet = *it; ++it;
    headers = *it;
    for (auto state : parserBlock->states) {
        auto ps = new EBPFParserState(state, this);
        states.push_back(ps);
    }
    auto ht = typeMap->getType(headers);
    if (ht == nullptr)
        return false;
    headerType = EBPFTypeFactory::instance->create(ht);
    return true;
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
    // Create a synthetic reject state
    builder->emitIndent();
    builder->appendFormat("%s:", IR::ParserState::reject.c_str());
    builder->spc();
    builder->blockStart();

    // This state may be called from deparser, so do not explicitly tell source of this event.
    builder->target->emitTraceMessage(builder, "Packet rejected");

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

    builder->blockEnd(true);
    builder->newline();
}


void EBPFOptimizedEgressParserPSA::emitRejectState(CodeBuilder *builder) {
    // Create a synthetic reject state
    builder->emitIndent();
    builder->appendFormat("egress_%s:", IR::ParserState::reject.c_str());
    builder->spc();
    builder->blockStart();

    // This state may be called from deparser, so do not explicitly tell source of this event.
    builder->target->emitTraceMessage(builder, "Packet rejected");

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
    builder->appendFormat("goto egress_%s", IR::ParserState::accept.c_str());
    builder->endOfStatement(true);

    builder->blockEnd(true);
    builder->newline();
}

bool OptimizedEgressParserStateVisitor::preorder(const IR::ParserState *parserState) {
    if (parserState->isBuiltin()) return false;

    builder->emitIndent();
    builder->append("egress_" + parserState->name.name);
    builder->append(":");
    builder->spc();
    builder->blockStart();

    cstring msgStr = Util::printf_format("Parser: state %s", parserState->name.name);
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    visit(parserState->components, "components");
    if (parserState->selectExpression == nullptr) {
        builder->emitIndent();
        builder->append("goto ");
        builder->append("egress_" + IR::ParserState::reject);
        builder->endOfStatement(true);
    } else if (parserState->selectExpression->is<IR::SelectExpression>()) {
        visit(parserState->selectExpression);
    } else {
        // must be a PathExpression which is a state name
        if (!parserState->selectExpression->is<IR::PathExpression>())
            BUG("Expected a PathExpression, got a %1%", parserState->selectExpression);
        builder->emitIndent();
        builder->append("goto egress_");
        visit(parserState->selectExpression);
        builder->endOfStatement(true);
    }

    builder->blockEnd(true);
    return false;
}

}  // namespace EBPF
