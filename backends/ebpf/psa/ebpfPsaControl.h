#ifndef BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_
#define BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_

#include "backends/ebpf/ebpfControl.h"

namespace EBPF {

class EBPFPsaControl : public EBPFControl {
 public:
    // FIXME: this should not be part of EBPFPsaControl object.
    // It should be moved to ConvertToEBPFPsaControl.
    const IR::P4Control* control;

    EBPFPsaControl(const EBPFProgram* program, const IR::P4Control* control,
                   const IR::Parameter* parserHeaders) :
        EBPFControl(program, nullptr, parserHeaders), control(control) {}

    bool build() override;
    void emit(CodeBuilder* builder) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_ */
