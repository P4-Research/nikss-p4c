#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSARANDOM_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSARANDOM_H_

#include "backends/ebpf/ebpfObject.h"

namespace EBPF {

class EBPFRandomPSA : public EBPFObject {
 public:
    explicit EBPFRandomPSA(const IR::Declaration_Instance* di);

    void processMethod(CodeBuilder* builder, const P4::ExternMethod* method) const;

    void emitRead(CodeBuilder* builder) const;

 protected:
    uint32_t minValue;
    uint32_t maxValue;
    uint64_t range;
};

}  // namespace EBPF

#endif  // BACKENDS_EBPF_PSA_EXTERNS_EBPFPSARANDOM_H_
