#ifndef P4C_EBPFPSACONTROL_H
#define P4C_EBPFPSACONTROL_H

#include "backends/ebpf/ebpfControl.h"

namespace EBPF {

class EBPFPsaControl : public EBPFControl {
 public:
    // FIXME: this should not be part of EBPFPsaControl object. It should be moved to ConvertToEBPFPsaControl.
    const IR::P4Control* control;

    EBPFPsaControl(const EBPFProgram* program, const IR::P4Control* control, const IR::Parameter* parserHeaders) :
        EBPFControl(program, nullptr, parserHeaders), control(control) {}

    bool build() override;
    void emit(CodeBuilder* builder) override;

};


}

#endif //P4C_EBPFPSACONTROL_H
