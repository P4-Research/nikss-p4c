#ifndef P4C_BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAREGISTER_H_
#define P4C_BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAREGISTER_H_

#include "backends/ebpf/ebpfTable.h"

namespace EBPF {

class EBPFRegisterPSA : public EBPFTableBase {
 public:

    EBPFRegisterPSA(const EBPFProgram* program, cstring instanceName,
                    CodeGenInspector* codeGen) {

    }
};

}

#endif //P4C_BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAREGISTER_H_