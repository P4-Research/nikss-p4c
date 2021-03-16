#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_

#include "backends/ebpf/ebpfObject.h"
#include "ebpfPsaHashAlgorithm.h"

namespace EBPF {

class EBPFChecksumPSA : public EBPFObject {
 protected:
    EBPFHashAlgorithmPSA * engine;

    void init(const EBPFProgram* program, const IR::Declaration* block,
              cstring name, Visitor * visitor, int type);

 public:
    EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration* block,
                    cstring name, Visitor * visitor);

    EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration* block,
                    cstring name, Visitor * visitor, int type);

    void emitVariables(CodeBuilder* builder, const IR::Declaration* decl) {
        engine->emitVariables(builder, decl);
    }

    virtual void processMethod(CodeBuilder* builder, cstring method,
                               const IR::MethodCallExpression * expr);
};

class EBPFInternetChecksumPSA : public EBPFChecksumPSA {
 public:
    EBPFInternetChecksumPSA(const EBPFProgram* program, const IR::Declaration* block,
                            cstring name, Visitor * visitor)
    : EBPFChecksumPSA(program, block, name, visitor,
                      EBPFHashAlgorithmPSA::HashAlgorithm::ONES_COMPLEMENT16) {}

    void processMethod(CodeBuilder* builder, cstring method,
                       const IR::MethodCallExpression * expr) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_ */
