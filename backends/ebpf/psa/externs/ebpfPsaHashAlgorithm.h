#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H

#include "backends/ebpf/ebpfObject.h"

namespace EBPF {

class EBPFPsaHashAlgorithm : public EBPFObject {
 protected:
    cstring baseName;
    const EBPFProgram* program;
    Visitor * visitor;

 public:
    EBPFPsaHashAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor)
        : baseName(name), program(program), visitor(visitor) {}

    virtual void emitVariables(CodeBuilder* builder, const IR::Declaration* decl) = 0;

    virtual void emitClear(CodeBuilder* builder) = 0;
    virtual void emitAddData(CodeBuilder* builder, const IR::MethodCallExpression * expr) = 0;
    virtual void emitGet(CodeBuilder* builder) = 0;

    virtual void emitSubtractData(CodeBuilder* builder, const IR::MethodCallExpression * expr) = 0;

    virtual void emitGetInternalState(CodeBuilder* builder) = 0;
    virtual void emitSetInternalState(CodeBuilder* builder,
                                      const IR::MethodCallExpression * expr) = 0;
};

class InternetChecksumAlgorithm : public EBPFPsaHashAlgorithm {
 protected:
    cstring stateVar;

    void updateChecksum(CodeBuilder* builder, const IR::MethodCallExpression * expr, bool addData);

 public:
    InternetChecksumAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor)
        : EBPFPsaHashAlgorithm(program, name, visitor) {}

    static void emitGlobals(CodeBuilder* builder);

    void emitVariables(CodeBuilder* builder, const IR::Declaration* decl) override;

    void emitClear(CodeBuilder* builder) override;
    void emitAddData(CodeBuilder* builder, const IR::MethodCallExpression * expr) override;
    void emitGet(CodeBuilder* builder) override;

    void emitSubtractData(CodeBuilder* builder, const IR::MethodCallExpression * expr) override;

    void emitGetInternalState(CodeBuilder* builder) override;
    void emitSetInternalState(CodeBuilder* builder,
                              const IR::MethodCallExpression * expr) override;
};

class EBPFPsaHashAlgorithmTypeFactory {
 public:
    enum HashAlgorithm {
        IDENTITY,
        CRC32,
        CRC32_CUSTOM,
        CRC16,
        CRC16_CUSTOM,
        ONES_COMPLEMENT16 // aka InternetChecksum
    };

    static EBPFPsaHashAlgorithm * create(int type, const EBPFProgram* program, cstring name,
                                         Visitor * visitor) {
        if (type == 5 || type == 6) // Ones complement 16 or target default
            return new InternetChecksumAlgorithm(program, name, visitor);

        BUG("Algorithm %1% not yet implemented", type);
    }

    static void emitAllGlobalHelpers(CodeBuilder* builder) {
        InternetChecksumAlgorithm::emitGlobals(builder);
    }
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H */
