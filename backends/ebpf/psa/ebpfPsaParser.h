#ifndef BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_
#define BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_

#include "backends/ebpf/ebpfType.h"
#include "backends/ebpf/ebpfParser.h"
#include "backends/ebpf/psa/ebpfPsaObjects.h"
#include "backends/ebpf/psa/externs/ebpfPsaChecksum.h"

namespace EBPF {

class EBPFPsaParser;
class EBPFOptimizedEgressParserPSA;

class PsaStateTranslationVisitor : public StateTranslationVisitor {
 public:
    EBPFPsaParser * parser;

    bool selectHasValueSet = false;
    bool selectFirstIfStatement = true;
    bool selectHasDefault = false;
    const IR::SelectExpression* currentSelectExpression = nullptr;

    explicit PsaStateTranslationVisitor(P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
                                        EBPFPsaParser * prsr) :
        StateTranslationVisitor(refMap, typeMap), parser(prsr) {}

    bool preorder(const IR::Expression* expression) override;
    bool preorder(const IR::SelectCase* selectCase) override;
    bool preorder(const IR::SelectExpression* expression) override;

    void processFunction(const P4::ExternFunction* function) override;
    void processMethod(const P4::ExternMethod* ext) override;

    void compileVerify(const IR::MethodCallExpression * expression);
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
    void emitRejectState(CodeBuilder* builder) override;
};


class OptimizedEgressParserStateVisitor : public PsaStateTranslationVisitor {
    bool shouldMoveOffset(cstring hdr);
 public:
    EBPFOptimizedEgressParserPSA * parser;

    explicit OptimizedEgressParserStateVisitor(P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
                                               EBPFPsaParser * prsr) :
            PsaStateTranslationVisitor(refMap, typeMap, prsr),
            parser(prsr->to<EBPFOptimizedEgressParserPSA>()) { }

    bool preorder(const IR::ParserState* parserState) override;

    void compileExtract(const IR::Expression* destination) override;
};


class EBPFOptimizedEgressParserPSA : public EBPFPsaParser {
 public:
    std::set<cstring> headersToInvalidate;
    std::set<cstring> headersToSkipMovingOffset;

    EBPFOptimizedEgressParserPSA(const EBPFProgram* program, const IR::P4Parser* block,
                                 const P4::TypeMap* typeMap) : EBPFPsaParser(program, block, typeMap) {
        visitor = new OptimizedEgressParserStateVisitor(program->refMap, program->typeMap, this);
    }

    bool isHeaderExtractedByParser(cstring hdr);
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_ */
