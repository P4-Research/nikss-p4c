#ifndef P4C_EBPFPSADEPARSER_H
#define P4C_EBPFPSADEPARSER_H

#include "backends/ebpf/ebpfControl.h"

namespace EBPF {
    class EBPFPsaDeparser : public EBPFControl {
    public:
        const IR::P4Control *control;
        const IR::Parameter *packet_out;
        std::vector<cstring> headersExpressions;
        std::vector<const IR::Type_Header *> headersToEmit;

        EBPFPsaDeparser(const EBPFProgram *program, const IR::P4Control *control, const IR::Parameter *parserHeaders) :
                EBPFControl(program, nullptr, parserHeaders), control(control) {}

        bool build() override;

        void emit(CodeBuilder *builder) override;

        void emitHeader(CodeBuilder *builder, const IR::Type_Header *headerToEmit, cstring &headerExpression) const;
        void emitField(CodeBuilder *builder, cstring headerExpression, cstring field, unsigned alignment, EBPF::EBPFType *type) const;
    };
}
#endif //P4C_EBPFPSADEPARSER_H