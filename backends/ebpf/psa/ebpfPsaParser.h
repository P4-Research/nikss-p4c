#ifndef BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_
#define BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_

#include "backends/ebpf/ebpfParser.h"
#include "backends/ebpf/psa/externs/ebpfPsaChecksum.h"

namespace EBPF {

class EBPFPsaParser;

class PsaStateTranslationVisitor : public StateTranslationVisitor {
 public:
    EBPFPsaParser * parser;

    explicit PsaStateTranslationVisitor(P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
                                        EBPFPsaParser * prsr) :
        StateTranslationVisitor(refMap, typeMap), parser(prsr) {}

    void processMethod(const P4::ExternMethod* ext) override;
};

class EBPFPsaParser : public EBPFParser {
 public:
    std::map<cstring, EBPFChecksumPSA*> checksums;
    EBPFChecksumPSA* getChecksum(cstring name) const {
        auto result = ::get(checksums, name);
        BUG_CHECK(result != nullptr, "No checksum named %1%", name);
        return result; }

    EBPFPsaParser(const EBPFProgram* program, const IR::P4Parser* block,
                  const P4::TypeMap* typeMap);

    bool build() override;

    void emitDeclaration(CodeBuilder* builder, const IR::Declaration* decl) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_ */
