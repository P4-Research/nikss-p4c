#ifndef P4C_EBPFPSACONTROL_H
#define P4C_EBPFPSACONTROL_H

#include "backends/ebpf/ebpfControl.h"

namespace EBPF_PSA {

class EBPFPsaControl : public EBPF::EBPFControl {
 public:
    // FIXME: this should not be part of EBPFPsaControl object. It should be moved to ConvertToEBPFPsaControl.
    const IR::P4Control* control;

    EBPFPsaControl(const EBPF::EBPFProgram* program, const IR::P4Control* control, const IR::Parameter* parserHeaders) :
        EBPF::EBPFControl(program, nullptr, parserHeaders), control(control) {}

    bool build() override;
    void emit(EBPF::CodeBuilder* builder) override;

};


}

#endif //P4C_EBPFPSACONTROL_H
