#include "ebpfPsaParser.h"
#include "backends/ebpf/ebpfType.h"

namespace EBPF {

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
    currentSelectExpression = const_cast<IR::SelectExpression*>(expression);

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

void PsaStateTranslationVisitor::processMethod(const P4::ExternMethod* ext) {
    auto externName = ext->originalExternType->name.name;

    if (externName == "InternetChecksum" || externName == "Checksum") {
        auto instance = ext->object->getName().name;
        auto method = ext->method->getName().name;
        parser->getChecksum(instance)->processMethod(builder, method, ext->expr);
        return;
    }

    StateTranslationVisitor::processMethod(ext);
}

EBPFPsaParser::EBPFPsaParser(const EBPFProgram* program, const IR::P4Parser* block,
                             const P4::TypeMap* typeMap) : EBPFParser(program, block, typeMap) {
    visitor = new PsaStateTranslationVisitor(program->refMap, program->typeMap, this);
}

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
            auto instance = new EBPFInternetChecksumPSA(program, decl, name, this->visitor);
            checksums.emplace(name, instance);
            instance->emitVariables(builder, decl);
            return;
        }

        if (typeSpec != nullptr &&
                typeSpec->baseType->to<IR::Type_Name>()->path->name.name == "Checksum") {
            auto instance = new EBPFChecksumPSA(program, decl, name, this->visitor);
            checksums.emplace(name, instance);
            instance->emitVariables(builder, decl);
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

}  // namespace EBPF
