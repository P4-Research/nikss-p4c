#ifndef BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_
#define BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_

#include "backends/ebpf/ebpfControl.h"

namespace EBPF {

class EBPFPsaDeparser : public EBPFControl {
 public:
    const IR::P4Control *control;
    const IR::Parameter *packet_out;
    EBPFType *headerType;
    std::vector<cstring> headersExpressions;
    std::vector<const IR::Type_Header *> headersToEmit;

    EBPFPsaDeparser(const EBPFProgram *program, const IR::P4Control *control,
                    const IR::Parameter *parserHeaders) :
            EBPFControl(program, nullptr, parserHeaders), control(control) {}

    bool build() override;
    void emit(CodeBuilder* builder) override;
    void emitHeader(CodeBuilder* builder, const IR::Type_Header* headerToEmit,
                    cstring &headerExpression) const;
    void emitField(CodeBuilder* builder, cstring headerExpression,
                   cstring field, unsigned alignment, EBPF::EBPFType* type) const;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSADEPARSER_H_ */
