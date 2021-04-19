#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H_

#include "backends/ebpf/ebpfObject.h"

namespace EBPF {

class EBPFProgram;

class EBPFHashAlgorithmPSA : public EBPFObject {
 protected:
    cstring baseName;
    const EBPFProgram* program;
    Visitor * visitor;

    typedef std::vector<const IR::Expression *> argumentsList;
    argumentsList unpackArguments(const IR::MethodCallExpression * expr, int dataPos);

 public:
    // keep this enum in sync with psa.p4 file
    enum HashAlgorithm {
        IDENTITY,
        CRC32,
        CRC32_CUSTOM,
        CRC16,
        CRC16_CUSTOM,
        ONES_COMPLEMENT16,  // aka InternetChecksum
        TARGET_DEFAULT
    };

    EBPFHashAlgorithmPSA(const EBPFProgram* program, cstring name, Visitor * visitor)
        : baseName(name), program(program), visitor(visitor) {}

    virtual void emitVariables(CodeBuilder* builder, const IR::Declaration_Instance* decl) = 0;

    virtual void emitClear(CodeBuilder* builder) = 0;
    virtual void emitAddData(CodeBuilder* builder, int dataPos,
                             const IR::MethodCallExpression * expr) = 0;
    virtual void emitGet(CodeBuilder* builder) = 0;

    virtual void emitSubtractData(CodeBuilder* builder, int dataPos,
                                  const IR::MethodCallExpression * expr) = 0;

    virtual void emitGetInternalState(CodeBuilder* builder) = 0;
    virtual void emitSetInternalState(CodeBuilder* builder,
                                      const IR::MethodCallExpression * expr) = 0;
};

class InternetChecksumAlgorithm : public EBPFHashAlgorithmPSA {
 protected:
    cstring stateVar;

    void updateChecksum(CodeBuilder* builder, int dataPos,
                        const IR::MethodCallExpression * expr, bool addData);

 public:
    InternetChecksumAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor)
        : EBPFHashAlgorithmPSA(program, name, visitor) {}

    static void emitGlobals(CodeBuilder* builder);

    void emitVariables(CodeBuilder* builder, const IR::Declaration_Instance* decl) override;

    void emitClear(CodeBuilder* builder) override;
    void emitAddData(CodeBuilder* builder, int dataPos,
                     const IR::MethodCallExpression * expr) override;
    void emitGet(CodeBuilder* builder) override;

    void emitSubtractData(CodeBuilder* builder, int dataPos,
                          const IR::MethodCallExpression * expr) override;

    void emitGetInternalState(CodeBuilder* builder) override;
    void emitSetInternalState(CodeBuilder* builder,
                              const IR::MethodCallExpression * expr) override;
};

class CRC16ChecksumAlgorithm : public EBPFHashAlgorithmPSA {
 protected:
    cstring registerVar;

 public:
    CRC16ChecksumAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor)
            : EBPFHashAlgorithmPSA(program, name, visitor) {}

    static void emitGlobals(CodeBuilder* builder);

    void emitVariables(CodeBuilder* builder, const IR::Declaration_Instance* decl) override;

    void emitClear(CodeBuilder* builder) override;
    void emitAddData(CodeBuilder* builder, int dataPos,
                     const IR::MethodCallExpression * expr) override;
    void emitGet(CodeBuilder* builder) override;

    void emitSubtractData(CodeBuilder* builder, int dataPos,
                          const IR::MethodCallExpression * expr) override;

    void emitGetInternalState(CodeBuilder* builder) override;
    void emitSetInternalState(CodeBuilder* builder,
                              const IR::MethodCallExpression * expr) override;
};

class EBPFHashAlgorithmTypeFactoryPSA {
 public:
    static EBPFHashAlgorithmTypeFactoryPSA * instance() {
        static EBPFHashAlgorithmTypeFactoryPSA factory;
        return &factory;
    }

    EBPFHashAlgorithmPSA * create(int type, const EBPFProgram* program, cstring name,
                                         Visitor * visitor) {
        if (type == EBPFHashAlgorithmPSA::HashAlgorithm::CRC16)
            return new CRC16ChecksumAlgorithm(program, name, visitor);
        else if (type == EBPFHashAlgorithmPSA::HashAlgorithm::ONES_COMPLEMENT16 ||
                type == EBPFHashAlgorithmPSA::HashAlgorithm::TARGET_DEFAULT)
            return new InternetChecksumAlgorithm(program, name, visitor);

        BUG("Algorithm %1% not yet implemented", type);
    }

    void emitGlobals(CodeBuilder* builder) {
        CRC16ChecksumAlgorithm::emitGlobals(builder);
        InternetChecksumAlgorithm::emitGlobals(builder);
    }
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H_ */
