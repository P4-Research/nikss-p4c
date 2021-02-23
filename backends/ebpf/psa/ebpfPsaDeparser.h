#ifndef BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_
#define BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_

#include "backends/ebpf/ebpfControl.h"

namespace EBPF {

class EBPFDeparserPSA;

// we need this class, because some externs (e.g. psa_resubmit()) must be handled in deparser.
class DeparserBodyTranslator : public ControlBodyTranslator {
    const EBPFDeparserPSA* deparser;

 public:
    explicit DeparserBodyTranslator(const EBPFDeparserPSA* deparser);

    void processFunction(const P4::ExternFunction* function) override;
};

class EBPFDeparserPSA : public EBPFControl {
 public:
    const IR::Parameter* packet_out;
    const IR::Parameter* istd;

    EBPFType* headerType;
    std::vector<cstring> headersExpressions;
    std::vector<const IR::Type_Header *> headersToEmit;
    cstring outerHdrOffsetVar, outerHdrLengthVar;
    cstring returnCode, hdrVoidPointerVar;

    EBPFDeparserPSA(const EBPFProgram* program, const IR::ControlBlock* control,
                    const IR::Parameter* parserHeaders, const IR::Parameter *istd) :
            EBPFControl(program, control, parserHeaders), istd(istd) {
      outerHdrOffsetVar = cstring("outHeaderOffset");
      outerHdrLengthVar = cstring("outHeaderLength");
      returnCode = cstring("returnCode");
      hdrVoidPointerVar = cstring("VoidPointerVar");
    }

    void emit(CodeBuilder* builder) override;
    // A "PreDeparser" is emitted just before set of hdr.emit() functions.
    // It is useful in case of resubmit or clone operation, as these operations
    // require to have an original packet.
    virtual void emitPreDeparser(CodeBuilder *builder) {}
    void emitHeader(CodeBuilder* builder, const IR::Type_Header* headerToEmit,
                    cstring &headerExpression) const;
    void emitField(CodeBuilder* builder, cstring headerExpression,
                   cstring field, unsigned alignment, EBPF::EBPFType* type) const;
};

class EBPFIngressDeparserPSA : public EBPFDeparserPSA {
 public:
    const IR::Parameter* resubmit_meta;
    EBPFIngressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                           const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
           EBPFDeparserPSA(program, control, parserHeaders, istd) {}

    bool build() override;
    void emitPreDeparser(CodeBuilder *builder) override;
    void emitSharedMetadataInitializer(CodeBuilder* builder);
};

class EBPFEgressDeparserPSA : public EBPFDeparserPSA {
 public:
    EBPFEgressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                          const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
            EBPFDeparserPSA(program, control, parserHeaders, istd) { }

    bool build() override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_ */
