#ifndef BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_
#define BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_

#include "backends/ebpf/ebpfControl.h"
#include "ebpfPsaControl.h"
#include "backends/ebpf/psa/externs/ebpfPsaChecksum.h"
#include "backends/ebpf/psa/ebpfPsaParser.h"

namespace EBPF {

class EBPFDeparserPSA;

// we need this class, because some externs (e.g. psa_resubmit()) must be handled in deparser.
class DeparserBodyTranslator : public ControlBodyTranslator {
    const EBPFDeparserPSA* deparser;

 public:
    explicit DeparserBodyTranslator(const EBPFDeparserPSA* deparser);

    void processFunction(const P4::ExternFunction* function) override;
    void processMethod(const P4::ExternMethod* method) override;
};

class EBPFDeparserPSA : public EBPFControlPSA {
 private:
    int maxDigestQueueSize = 100;

 public:
    const IR::Parameter* packet_out;
    const IR::Parameter* istd;
    const IR::Parameter* resubmit_meta;

    EBPFType* headerType;
    std::vector<cstring> headersExpressions;
    std::vector<const IR::Type_Header *> headersToEmit;
    cstring outerHdrOffsetVar, outerHdrLengthVar;
    cstring returnCode;
    std::map<cstring, const IR::Type *> digests;
    std::map<cstring, EBPFChecksumPSA*> checksums;

    EBPFDeparserPSA(const EBPFProgram* program, const IR::ControlBlock* control,
                    const IR::Parameter* parserHeaders, const IR::Parameter *istd) :
            EBPFControlPSA(program, control, parserHeaders), istd(istd) {
      outerHdrOffsetVar = cstring("outHeaderOffset");
      outerHdrLengthVar = cstring("outHeaderLength");
      returnCode = cstring("returnCode");
    }

    bool isHeaderEmitted(cstring hdrName) const;

    void emit(CodeBuilder* builder) override;
    // A "PreDeparser" is emitted just before a sequence of hdr.emit() functions.
    // It is useful in the case of resubmit or clone operation, as these operations
    // require to have an original packet.
    virtual void emitPreDeparser(CodeBuilder *builder) {
        (void) builder;
    }

    virtual void emitDeparserExternCalls(CodeBuilder* builder) {
        controlBlock->container->body->apply(*codeGen);
        builder->newline();
    }

    virtual void emitPreparePacketBuffer(CodeBuilder *builder);
    virtual void emitHeader(CodeBuilder* builder, const IR::Type_Header* headerToEmit,
                    cstring &headerExpression) const;
    void emitField(CodeBuilder* builder, cstring headerExpression,
                   cstring field, unsigned alignment, EBPF::EBPFType* type) const;
    void emitDigestInstances(CodeBuilder* builder) const;
    void emitDeclaration(CodeBuilder* builder, const IR::Declaration* decl) override;

    EBPFChecksumPSA* getChecksum(cstring name) const {
        auto result = ::get(checksums, name);
        BUG_CHECK(result != nullptr, "No checksum named %1%", name);
        return result; }
};

class TCIngressDeparserPSA : public EBPFDeparserPSA {
 public:
    TCIngressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                         const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
            EBPFDeparserPSA(program, control, parserHeaders, istd) {}

    bool build() override;
    void emitPreDeparser(CodeBuilder *builder) override;
};

class TCIngressDeparserForTrafficManagerPSA : public TCIngressDeparserPSA {
 public:
    TCIngressDeparserForTrafficManagerPSA(const EBPFProgram *program,
                                          const IR::ControlBlock *control,
                                          const IR::Parameter *parserHeaders,
                                          const IR::Parameter *istd) :
            TCIngressDeparserPSA(program, control, parserHeaders, istd) {}
    void emitPreDeparser(CodeBuilder *builder) override;
    void emitDeparserExternCalls(CodeBuilder* builder) override {
        (void) builder;
        // do not emit deparser extern calls for TCIngressDeparserForTrafficManagerPSA
    }
};

class TCEgressDeparserPSA : public EBPFDeparserPSA {
 public:
    TCEgressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                          const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
            EBPFDeparserPSA(program, control, parserHeaders, istd) { }

    bool build() override;
};

class XDPIngressDeparserPSA : public EBPFDeparserPSA {
 public:
    XDPIngressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                          const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
            EBPFDeparserPSA(program, control, parserHeaders, istd) { }

    bool build() override;
    void emitPreDeparser(CodeBuilder *builder) override;
};

class XDPEgressDeparserPSA : public EBPFDeparserPSA {
 public:
    XDPEgressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                          const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
            EBPFDeparserPSA(program, control, parserHeaders, istd) { }

    bool build() override;
    void emitPreDeparser(CodeBuilder *builder) override;
};

class OptimizedXDPEgressDeparserPSA : public XDPEgressDeparserPSA {
 public:
    OptimizedXDPEgressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                                  const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
            XDPEgressDeparserPSA(program, control, parserHeaders, istd) {
    }

    void emit(CodeBuilder* builder) override;
};

class OptimizedXDPIngressDeparserPSA : public XDPIngressDeparserPSA {
 public:
    std::vector<cstring> optimizedHeadersExpressions;
    std::vector<const IR::Type_Header *> optimizedHeadersToEmit;
    std::map<cstring, const IR::Type_Header *> removedHeadersToEmit;
    bool skipEgress = false;
    OptimizedXDPIngressDeparserPSA(const EBPFProgram *program, const IR::ControlBlock *control,
                                   const IR::Parameter *parserHeaders, const IR::Parameter *istd) :
            XDPIngressDeparserPSA(program, control, parserHeaders, istd) {}

    void emit(CodeBuilder* builder) override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_ */
