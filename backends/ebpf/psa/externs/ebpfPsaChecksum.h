#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_

#include "backends/ebpf/ebpfObject.h"
#include "ebpfPsaHashAlgorithm.h"

namespace EBPF {

class EBPFChecksumPSA : public EBPFObject {
 protected:
    EBPFHashAlgorithmPSA * engine;
    const IR::Declaration_Instance * declaration;

    void init(const EBPFProgram* program, cstring name, int type);

 public:
    EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                    cstring name);

    EBPFChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                    cstring name, int type);

    void emitVariables(CodeBuilder* builder) {
        engine->emitVariables(builder, declaration);
    }

    virtual void processMethod(CodeBuilder* builder, cstring method,
                               const IR::MethodCallExpression * expr, Visitor * visitor);
};

class EBPFInternetChecksumPSA : public EBPFChecksumPSA {
 public:
    EBPFInternetChecksumPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                            cstring name)
    : EBPFChecksumPSA(program, block, name,
                      EBPFHashAlgorithmPSA::HashAlgorithm::ONES_COMPLEMENT16) {}

    void processMethod(CodeBuilder* builder, cstring method,
                       const IR::MethodCallExpression * expr, Visitor * visitor) override;
};

class EBPFHashPSA : public EBPFChecksumPSA {
 public:
    EBPFHashPSA(const EBPFProgram* program, const IR::Declaration_Instance* block,
                cstring name) : EBPFChecksumPSA(program, block, name) {}

    void processMethod(CodeBuilder* builder, cstring method,
                       const IR::MethodCallExpression * expr, Visitor * visitor) override;

    void emitGetMethod(CodeBuilder* builder, const IR::MethodCallExpression * expr,
                       Visitor * visitor);
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EXTERNS_EBPFPSACHECKSUM_H_ */
