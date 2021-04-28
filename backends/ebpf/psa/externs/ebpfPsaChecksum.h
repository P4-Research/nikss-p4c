#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_

#include "backends/ebpf/ebpfObject.h"
#include "ebpfPsaHashAlgorithm.h"

namespace EBPF {

class EBPFChecksumPSA : public EBPFObject {
 protected:
    EBPFHashAlgorithmPSA * engine;
    Visitor * visitor;
    const IR::Declaration_Instance * declaration;

    void init(const EBPFProgram* program, cstring name, int type);

 public:
    EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                    cstring name, Visitor * visitor);

    EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                    cstring name, Visitor * visitor, int type);

    void emitVariables(CodeBuilder* builder) {
        engine->emitVariables(builder, declaration);
    }

    virtual void processMethod(CodeBuilder* builder, cstring method,
                               const IR::MethodCallExpression * expr);
};

class EBPFInternetChecksumPSA : public EBPFChecksumPSA {
 public:
    EBPFInternetChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                            cstring name, Visitor * visitor)
    : EBPFChecksumPSA(program, block, name, visitor,
                      EBPFHashAlgorithmPSA::HashAlgorithm::ONES_COMPLEMENT16) {}

    void processMethod(CodeBuilder* builder, cstring method,
                       const IR::MethodCallExpression * expr) override;
};

class EBPFHashPSA : public EBPFChecksumPSA {
 public:
    EBPFHashPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                            cstring name, Visitor * visitor)
    : EBPFChecksumPSA(program, block, name, visitor) {}

    void processMethod(CodeBuilder* builder, cstring method,
                       const IR::MethodCallExpression * expr) override;

    void emitGetMethod(CodeBuilder* builder, const IR::MethodCallExpression * expr);
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_ */
