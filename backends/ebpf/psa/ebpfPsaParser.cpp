#include "ebpfPsaParser.h"
#include "backends/ebpf/ebpfType.h"

namespace EBPF {

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

    EBPFParser::emitDeclaration(builder, decl);
}

}  // namespace EBPF
