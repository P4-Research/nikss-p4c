#ifndef BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_
#define BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_

#include "backends/ebpf/ebpfParser.h"
#include "backends/ebpf/psa/ebpfPsaObjects.h"
#include "backends/ebpf/psa/externs/ebpfPsaChecksum.h"

namespace EBPF {

class EBPFPsaParser;

class PsaStateTranslationVisitor : public StateTranslationVisitor {
 public:
    EBPFPsaParser * parser;

    bool selectHasValueSet = false;
    bool selectFirstIfStatement = true;
    bool selectHasDefault = false;
    IR::SelectExpression* currentSelectExpression = nullptr;

    explicit PsaStateTranslationVisitor(P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
                                        EBPFPsaParser * prsr) :
        StateTranslationVisitor(refMap, typeMap), parser(prsr) {}

    bool preorder(const IR::SelectCase* selectCase) override;
    bool preorder(const IR::SelectExpression* expression) override;

    void processMethod(const P4::ExternMethod* ext) override;
};

class EBPFPsaParser : public EBPFParser {
 public:
    std::map<cstring, EBPFChecksumPSA*> checksums;
    std::map<cstring, EBPFValueSetPSA*> valueSets;

    EBPFChecksumPSA* getChecksum(cstring name) const {
        auto result = ::get(checksums, name);
        BUG_CHECK(result != nullptr, "No checksum named %1%", name);
        return result; }
    EBPFValueSetPSA* getValueSet(cstring name) const {
        auto result = ::get(valueSets, name);
        BUG_CHECK(result != nullptr, "No value_set named %1%", name);
        return result; }

    EBPFPsaParser(const EBPFProgram* program, const IR::P4Parser* block,
                  const P4::TypeMap* typeMap);

    bool build() override;

    void emitDeclaration(CodeBuilder* builder, const IR::Declaration* decl) override;

    void emitTypes(CodeBuilder* builder) override;
    void emitValueSetInstances(CodeBuilder* builder) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_ */
