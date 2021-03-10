#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H

#include "backends/ebpf/ebpfObject.h"
#include "ebpfPsaHashAlgorithm.h"

namespace EBPF {

class EBPFPsaChecksum : public EBPFObject {
 protected:
    EBPFPsaHashAlgorithm * engine;

    void init(const EBPFProgram* program, const IR::Declaration* block,
              cstring name, Visitor * visitor, int type);

 public:

    EBPFPsaChecksum(const EBPFProgram* program, const IR::Declaration* block,
                    cstring name, Visitor * visitor);

    EBPFPsaChecksum(const EBPFProgram* program, const IR::Declaration* block,
                    cstring name, Visitor * visitor, int type);

    void emitVariables(CodeBuilder* builder, const IR::Declaration* decl) {
        engine->emitVariables(builder, decl);
    }

    virtual void processMethod(CodeBuilder* builder, cstring method,
                               const IR::MethodCallExpression * expr);
};

class EBPFPsaInternetChecksum : public EBPFPsaChecksum {
 public:
    EBPFPsaInternetChecksum(const EBPFProgram* program, const IR::Declaration* block,
                            cstring name, Visitor * visitor)
    : EBPFPsaChecksum(program, block, name, visitor,
                      EBPFPsaHashAlgorithmTypeFactory::HashAlgorithm::ONES_COMPLEMENT16) {}

    void processMethod(CodeBuilder* builder, cstring method,
                       const IR::MethodCallExpression * expr) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H */
