#ifndef BACKENDS_EBPF_PSA_EBPFPSATYPES_H_
#define BACKENDS_EBPF_PSA_EBPFPSATYPES_H_

#include "backends/ebpf/ebpfType.h"

namespace EBPF {

// represents an error type for PSA
class EBPFErrorTypePSA : public EBPFType {
public:
    explicit EBPFErrorTypePSA(const IR::Type_Error * type) : EBPFType(type) {}

    void emit(CodeBuilder* builder) override;
    void declare(CodeBuilder* builder, cstring id, bool asPointer) override;
    void emitInitializer(CodeBuilder* builder) override;

    const IR::Type_Error* getType() const { return type->to<IR::Type_Error>(); }
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSATYPES_H_ */
