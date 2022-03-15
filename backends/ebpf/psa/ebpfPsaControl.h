#ifndef BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_
#define BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_

#include "ebpfPsaTable.h"
#include "backends/ebpf/ebpfControl.h"

namespace EBPF {

class EBPFControlPSA;

class EBPFControlPSA : public EBPFControl {
 public:
    bool timestampIsUsed = false;
    // FIXME: this should not be part of EBPFControlPSA object.
    // It should be moved to ConvertToEBPFPsaControl.
    const IR::P4Control* p4Control;

    const IR::Parameter* user_metadata;
    const IR::Parameter* inputStandardMetadata;
    const IR::Parameter* outputStandardMetadata;

    EBPFControlPSA(const EBPFProgram* program, const IR::ControlBlock* control,
                   const IR::Parameter* parserHeaders) :
        EBPFControl(program, control, parserHeaders), p4Control(control->container) {}
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_ */
